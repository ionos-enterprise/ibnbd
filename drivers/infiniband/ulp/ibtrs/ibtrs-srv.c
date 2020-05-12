#define pr_fmt(fmt) KBUILD_MODNAME " L" __stringify(__LINE__) ": " fmt

#include <linux/module.h>
#include <linux/sizes.h>
#include <linux/utsname.h>
#include <linux/cpumask.h>
#include <linux/debugfs.h>
#include <rdma/ib_verbs.h>
#include <rdma/rdma_cm.h>
#include <rdma/ibtrs.h>

#include "ibtrs-pri.h"
#include "ibtrs-srv.h"
#include "ibtrs-log.h"

MODULE_AUTHOR("ibnbd@profitbricks.com");
MODULE_DESCRIPTION("InfiniBand Transport Server");
MODULE_VERSION(__stringify(IBTRS_VER));
MODULE_LICENSE("GPL");

#define DEFAULT_MAX_IO_SIZE_KB 128
#define DEFAULT_MAX_IO_SIZE (DEFAULT_MAX_IO_SIZE_KB * 1024)
static int max_io_size = DEFAULT_MAX_IO_SIZE;
#define MAX_REQ_SIZE PAGE_SIZE
static int rcv_buf_size = DEFAULT_MAX_IO_SIZE + MAX_REQ_SIZE;

static void ibtrs_srv_rdma_done(struct ib_cq *cq, struct ib_wc *wc);

static struct ib_cqe hb_and_ack_cqe = {
	.done = ibtrs_srv_rdma_done
};

static int max_io_size_set(const char *val, const struct kernel_param *kp)
{
	int err, ival;

	err = kstrtoint(val, 0, &ival);
	if (err)
		return err;

	if (ival < 4096 || ival + MAX_REQ_SIZE > (4096 * 1024) ||
	    (ival + MAX_REQ_SIZE) % 512 != 0) {
		pr_err("Invalid max io size value %d, has to be"
		       " > %d, < %d\n", ival, 4096, 4194304);
		return -EINVAL;
	}

	max_io_size = ival;
	rcv_buf_size = max_io_size + MAX_REQ_SIZE;
	pr_info("max io size changed to %d\n", ival);

	return 0;
}

static const struct kernel_param_ops max_io_size_ops = {
	.set		= max_io_size_set,
	.get		= param_get_int,
};
module_param_cb(max_io_size, &max_io_size_ops, &max_io_size, 0444);
MODULE_PARM_DESC(max_io_size,
		 "Max size for each IO request, when change the unit is in byte"
		 " (default: " __stringify(DEFAULT_MAX_IO_SIZE_KB) "KB)");

#define DEFAULT_SESS_QUEUE_DEPTH 512
static int sess_queue_depth = DEFAULT_SESS_QUEUE_DEPTH;
module_param_named(sess_queue_depth, sess_queue_depth, int, 0444);
MODULE_PARM_DESC(sess_queue_depth,
		 "Number of buffers for pending I/O requests to allocate"
		 " per session. Maximum: " __stringify(MAX_SESS_QUEUE_DEPTH)
		 " (default: " __stringify(DEFAULT_SESS_QUEUE_DEPTH) ")");

#define DEFAULT_INIT_POOL_SIZE 10
static int init_pool_size = DEFAULT_INIT_POOL_SIZE;
module_param_named(init_pool_size, init_pool_size, int, 0444);
MODULE_PARM_DESC(init_pool_size,
		 "Maximum size of the RDMA buffers pool to pre-allocate on"
		 " module load, in number of sessions. (default: "
		 __stringify(DEFAULT_INIT_POOL_SIZE) ")");

#define DEFAULT_POOL_SIZE_HI_WM 100
static int pool_size_hi_wm = DEFAULT_POOL_SIZE_HI_WM;
module_param_named(pool_size_hi_wm, pool_size_hi_wm, int, 0444);
MODULE_PARM_DESC(pool_size_hi_wm,
		 "High watermark value for the size of RDMA buffers pool"
		 " (in number of sessions). Newly allocated buffers will be"
		 " added to the pool until pool_size_hi_wm is reached."
		 " (default: " __stringify(DEFAULT_POOL_SIZE_HI_WM) ")");

static int retry_count = 7;

static int retry_count_set(const char *val, const struct kernel_param *kp)
{
	int err, ival;

	err = kstrtoint(val, 0, &ival);
	if (err)
		return err;

	if (ival < MIN_RTR_CNT || ival > MAX_RTR_CNT) {
		pr_err("Invalid retry count value %d, has to be"
		       " > %d, < %d\n", ival, MIN_RTR_CNT, MAX_RTR_CNT);
		return -EINVAL;
	}

	retry_count = ival;
	pr_info("QP retry count changed to %d\n", ival);

	return 0;
}

static const struct kernel_param_ops retry_count_ops = {
	.set		= retry_count_set,
	.get		= param_get_int,
};
module_param_cb(retry_count, &retry_count_ops, &retry_count, 0644);

MODULE_PARM_DESC(retry_count, "Number of times to send the message if the"
		 " remote side didn't respond with Ack or Nack (default: 3,"
		 " min: " __stringify(MIN_RTR_CNT) ", max: "
		 __stringify(MAX_RTR_CNT) ")");

static int default_heartbeat_timeout_ms = DEFAULT_HEARTBEAT_TIMEOUT_MS;

static int default_heartbeat_timeout_set(const char *val,
					 const struct kernel_param *kp)
{
	int ret, ival;

	ret = kstrtouint(val, 0, &ival);
	if (ret)
		return ret;

	ret = ibtrs_heartbeat_timeout_validate(ival);
	if (ret)
		return ret;

	default_heartbeat_timeout_ms = ival;
	pr_info("Default heartbeat timeout changed to %d\n", ival);

	return 0;
}

static const struct kernel_param_ops heartbeat_timeout_ops = {
	.set		= default_heartbeat_timeout_set,
	.get		= param_get_int,
};

module_param_cb(default_heartbeat_timeout_ms, &heartbeat_timeout_ops,
		&default_heartbeat_timeout_ms, 0644);
MODULE_PARM_DESC(default_heartbeat_timeout_ms, "default heartbeat timeout,"
		 " min. " __stringify(MIN_HEARTBEAT_TIMEOUT_MS)
		 " (default:" __stringify(DEFAULT_HEARTBEAT_TIMEOUT_MS) ")");

static char cq_affinity_list[256] = "";
static cpumask_t cq_affinity_mask = { CPU_BITS_ALL };

static void init_cq_affinity(void)
{
	sprintf(cq_affinity_list, "0-%d", nr_cpu_ids - 1);
}

static int cq_affinity_list_set(const char *val, const struct kernel_param *kp)
{
	int ret = 0, len = strlen(val);
	cpumask_var_t new_value;

	if (!strlen(cq_affinity_list))
		init_cq_affinity();

	if (len >= sizeof(cq_affinity_list))
		return -EINVAL;
	if (!alloc_cpumask_var(&new_value, GFP_KERNEL))
		return -ENOMEM;

	ret = cpulist_parse(val, new_value);
	if (ret) {
		pr_err("Can't set cq_affinity_list \"%s\": %d\n", val,
		       ret);
		goto free_cpumask;
	}

	strlcpy(cq_affinity_list, val, sizeof(cq_affinity_list));
	*strchrnul(cq_affinity_list, '\n') = '\0';
	cpumask_copy(&cq_affinity_mask, new_value);

	pr_info("cq_affinity_list changed to %*pbl\n",
		cpumask_pr_args(&cq_affinity_mask));
free_cpumask:
	free_cpumask_var(new_value);
	return ret;
}

static struct kparam_string cq_affinity_list_kparam_str = {
	.maxlen	= sizeof(cq_affinity_list),
	.string	= cq_affinity_list
};

static const struct kernel_param_ops cq_affinity_list_ops = {
	.set	= cq_affinity_list_set,
	.get	= param_get_string,
};

module_param_cb(cq_affinity_list, &cq_affinity_list_ops,
		&cq_affinity_list_kparam_str, 0644);
MODULE_PARM_DESC(cq_affinity_list, "Sets the list of cpus to use as cq vectors."
		 "(default: use all possible CPUs)");

static char hostname[MAXHOSTNAMELEN] = "";

static int hostname_set(const char *val, const struct kernel_param *kp)
{
	int ret = 0, len = strlen(val);

	if (len >= sizeof(hostname))
		return -EINVAL;
	strlcpy(hostname, val, sizeof(hostname));
	*strchrnul(hostname, '\n') = '\0';

	pr_info("hostname changed to %s\n", hostname);
	return ret;
}

static struct kparam_string hostname_kparam_str = {
	.maxlen	= sizeof(hostname),
	.string	= hostname
};

static const struct kernel_param_ops hostname_ops = {
	.set	= hostname_set,
	.get	= param_get_string,
};

module_param_cb(hostname, &hostname_ops,
		&hostname_kparam_str, 0644);
MODULE_PARM_DESC(hostname, "Sets hostname of local server, will send to the"
		 " other side if set,  will display togather with addr "
		 "(default: empty)");

static struct dentry *ibtrs_srv_debugfs_dir;
static struct dentry *mempool_debugfs_dir;

static struct workqueue_struct *ibtrs_wq;

static DEFINE_MUTEX(buf_pool_mutex);
static LIST_HEAD(free_buf_pool_list);
static int nr_free_buf_pool;
static int nr_total_buf_pool;
static int nr_active_sessions;

struct ibtrs_srv_ctx {
	struct ibtrs_srv_ops ops;
	struct rdma_cm_id *cm_id_ip;
	struct rdma_cm_id *cm_id_ib;
	struct mutex sess_mutex;
	struct list_head sess_list;
	wait_queue_head_t sess_list_waitq; /* XXX DIE ASAP */
};

enum ssm_ev {
	SSM_EV_CON_DISCONNECTED,
	SSM_EV_CON_EST_ERR,
	SSM_EV_CON_CONNECTED,
	SSM_EV_SESS_CLOSE,
	SSM_EV_SYSFS_DISCONNECT
};

static inline const char *ssm_ev_str(enum ssm_ev ev)
{
	switch (ev) {
	case SSM_EV_CON_DISCONNECTED:
		return "SSM_EV_CON_DISCONNECTED";
	case SSM_EV_CON_EST_ERR:
		return "SSM_EV_CON_EST_ERR";
	case SSM_EV_CON_CONNECTED:
		return "SSM_EV_CON_CONNECTED";
	case SSM_EV_SESS_CLOSE:
		return "SSM_EV_SESS_CLOSE";
	case SSM_EV_SYSFS_DISCONNECT:
		return "SSM_EV_SYSFS_DISCONNECT";
	default:
		return "UNKNOWN";
	}
}

static const char *ssm_state_str(enum ssm_state state)
{
	switch (state) {
	case SSM_STATE_IDLE:
		return "SSM_STATE_IDLE";
	case SSM_STATE_CONNECTED:
		return "SSM_STATE_CONNECTED";
	case SSM_STATE_CLOSING:
		return "SSM_STATE_CLOSING";
	case SSM_STATE_CLOSED:
		return "SSM_STATE_CLOSED";
	default:
		return "UNKNOWN";
	}
}

enum csm_state {
	CSM_STATE_REQUESTED,
	CSM_STATE_CONNECTED,
	CSM_STATE_CLOSING,
	CSM_STATE_FLUSHING,
	CSM_STATE_CLOSED
};

static inline const char *csm_state_str(enum csm_state s)
{
	switch (s) {
	case CSM_STATE_REQUESTED:
		return "CSM_STATE_REQUESTED";
	case CSM_STATE_CONNECTED:
		return "CSM_STATE_CONNECTED";
	case CSM_STATE_CLOSING:
		return "CSM_STATE_CLOSING";
	case CSM_STATE_FLUSHING:
		return "CSM_STATE_FLUSHING";
	case CSM_STATE_CLOSED:
		return "CSM_STATE_CLOSED";
	default:
		return "UNKNOWN";
	}
}

enum csm_ev {
	CSM_EV_CON_REQUEST,
	CSM_EV_CON_ESTABLISHED,
	CSM_EV_CON_ERROR,
	CSM_EV_DEVICE_REMOVAL,
	CSM_EV_SESS_CLOSING,
	CSM_EV_CON_DISCONNECTED,
	CSM_EV_BEACON_COMPLETED
};

static inline const char *csm_ev_str(enum csm_ev ev)
{
	switch (ev) {
	case CSM_EV_CON_REQUEST:
		return "CSM_EV_CON_REQUEST";
	case CSM_EV_CON_ESTABLISHED:
		return "CSM_EV_CON_ESTABLISHED";
	case CSM_EV_CON_ERROR:
		return "CSM_EV_CON_ERROR";
	case CSM_EV_DEVICE_REMOVAL:
		return "CSM_EV_DEVICE_REMOVAL";
	case CSM_EV_SESS_CLOSING:
		return "CSM_EV_SESS_CLOSING";
	case CSM_EV_CON_DISCONNECTED:
		return "CSM_EV_CON_DISCONNECTED";
	case CSM_EV_BEACON_COMPLETED:
		return "CSM_EV_BEACON_COMPLETED";
	default:
		return "UNKNOWN";
	}
}

struct sess_put_work {
	struct ibtrs_srv_sess	*sess;
	struct work_struct	work;
};

struct ibtrs_srv_sysfs_put_work {
	struct work_struct	work;
	struct ibtrs_srv_sess	*sess;
};

struct ssm_create_con_work {
	struct ibtrs_srv_sess	*sess;
	struct rdma_cm_id	*cm_id;
	struct work_struct	work;
	bool			user;/* true if con is for user msg only */
};

struct ssm_work {
	struct ibtrs_srv_sess	*sess;
	enum ssm_ev		ev;
	struct work_struct	work;
};

struct ibtrs_srv_con {
	struct ibtrs_con	ibtrs_con;
	unsigned		cid;
	/* list for ibtrs_srv_sess->con_list */  /* XXX DIE ASAP */
	struct list_head	list; /* XXX DIE ASAP */
	enum csm_state		state; /*XXX DIE ASAP */
	/* true if con is for user msg only */  /* XXX DIE ASAP */
	bool			user; /* XXX DIE ASAP */
	atomic_t		wr_cnt;
	struct rdma_cm_id	*cm_id;  /* XXX should die, copy in ibtrs_con */
	struct ibtrs_srv_sess	*sess;
	struct workqueue_struct *rdma_resp_wq;
	bool			device_being_removed; /* XXX DIE ASAP */
};

struct csm_work {
	struct ibtrs_srv_con	*con;
	enum csm_ev		ev;
	struct work_struct	work;
};

struct msg_work {
	struct work_struct	work;
	struct ibtrs_srv_con	*con;
	void                    *msg;
};

struct ibtrs_srv_op {
	struct ibtrs_srv_con		*con;
	u32				msg_id;
	u8				dir;
	u64				data_dma_addr;
	struct ibtrs_msg_req_rdma_write *req;
	struct ib_rdma_wr		*tx_wr;
	struct ib_sge			*tx_sg;
	int				status;
	struct work_struct		work;
};

static bool __ibtrs_srv_change_state_NEW(struct ibtrs_srv_sess *sess,
				     enum ibtrs_srv_state new_state)
{
	enum ibtrs_srv_state old_state;
	bool changed = false;

	old_state = sess->state_NEW;
	switch (new_state) {
	case IBTRS_SRV_CLOSING:
		switch (old_state) {
		case IBTRS_SRV_ALIVE:
			changed = true;
			/* FALLTHRU */
		default:
			break;
		}
		break;
	case IBTRS_SRV_CLOSED:
		switch (old_state) {
		case IBTRS_SRV_CLOSING:
			changed = true;
			/* FALLTHRU */
		default:
			break;
		}
		break;
	default:
		break;
	}
	if (changed)
		sess->state_NEW = new_state;

	return changed;
}

static bool ibtrs_srv_change_state_NEW(struct ibtrs_srv_sess *sess,
				   enum ibtrs_srv_state new_state)
{
	bool changed;

	spin_lock_irq(&sess->state_lock);
	changed = __ibtrs_srv_change_state_NEW(sess, new_state);
	spin_unlock_irq(&sess->state_lock);

	return changed;
}

static void csm_set_state(struct ibtrs_srv_con *con, enum csm_state s)
{
	if (con->state != s) {
		pr_debug("changing con %p csm state from %s to %s\n", con,
			 csm_state_str(con->state), csm_state_str(s));
		con->state = s;
	}
}

static void ssm_set_state(struct ibtrs_srv_sess *sess, enum ssm_state state)
{
	if (sess->state != state) {
		pr_debug("changing sess %p ssm state from %s to %s\n", sess,
			 ssm_state_str(sess->state), ssm_state_str(state));
		sess->state = state;
	}
}

static struct ibtrs_srv_con *ibtrs_srv_get_user_con(struct ibtrs_srv_sess *sess)
{
	struct ibtrs_srv_con *con;

	if (sess->est_cnt > 0) {
		list_for_each_entry(con, &sess->con_list, list) {
			if (con->user && con->state == CSM_STATE_CONNECTED)
				return con;
		}
	}
	return NULL;
}

static void csm_init(struct ibtrs_srv_con *con);
static void csm_schedule_event(struct ibtrs_srv_con *con, enum csm_ev ev);
static int ssm_init(struct ibtrs_srv_sess *sess);
static int ssm_schedule_event(struct ibtrs_srv_sess *sess, enum ssm_ev ev);

int ibtrs_srv_current_hca_port_to_str(struct ibtrs_srv_sess *sess,
				      char *buf, size_t len)
{
	struct ibtrs_srv_con *con = ibtrs_srv_get_user_con(sess);
	char str[16] = "n/a\n";
	int sz = 4;

	if (con)
		len = scnprintf(str, sizeof(str), "%u\n", con->cm_id->port_num);
	strncpy(buf, str, len);

	return sz;
}

const char *ibtrs_srv_get_sess_hca_name(struct ibtrs_srv_sess *sess)
{
	struct ibtrs_srv_con *con = ibtrs_srv_get_user_con(sess);

	if (con)
		return sess->s.ib_dev->dev->name;

	return "n/a";
}

static void ibtrs_srv_update_rdma_stats(struct ibtrs_srv_stats *s,
					size_t size, bool read)
{
	int inflight;

	if (read) {
		atomic64_inc(&s->rdma_stats.cnt_read);
		atomic64_add(size, &s->rdma_stats.size_total_read);
	} else {
		atomic64_inc(&s->rdma_stats.cnt_write);
		atomic64_add(size, &s->rdma_stats.size_total_write);
	}

	inflight = atomic_inc_return(&s->rdma_stats.inflight);
	atomic64_add(inflight, &s->rdma_stats.inflight_total);
}

static inline void ibtrs_srv_stats_dec_inflight(struct ibtrs_srv_sess *sess)
{
	if (!atomic_dec_return(&sess->stats.rdma_stats.inflight))
		wake_up(&sess->bufs_wait);
}

int ibtrs_srv_reset_rdma_stats(struct ibtrs_srv_sess *sess, bool enable)
{
	if (enable) {
		struct ibtrs_srv_stats_rdma_stats *r = &sess->stats.rdma_stats;

		/*
		 * TODO: inflight is used for flow control
		 * we can't memset the whole structure, so reset each member
		 */
		atomic64_set(&r->cnt_read, 0);
		atomic64_set(&r->size_total_read, 0);
		atomic64_set(&r->cnt_write, 0);
		atomic64_set(&r->size_total_write, 0);
		atomic64_set(&r->inflight_total, 0);
		return 0;
	} else {
		return -EINVAL;
	}
}

ssize_t ibtrs_srv_stats_rdma_to_str(struct ibtrs_srv_sess *sess,
				    char *page, size_t len)
{
	struct ibtrs_srv_stats_rdma_stats *r = &sess->stats.rdma_stats;

	return scnprintf(page, len, "%ld %ld %ld %ld %u %ld\n",
			 atomic64_read(&r->cnt_read),
			 atomic64_read(&r->size_total_read),
			 atomic64_read(&r->cnt_write),
			 atomic64_read(&r->size_total_write),
			 atomic_read(&r->inflight),
			 (atomic64_read(&r->cnt_read) +
			  atomic64_read(&r->cnt_write)) ?
			 atomic64_read(&r->inflight_total) /
			 (atomic64_read(&r->cnt_read) +
			  atomic64_read(&r->cnt_write)) : 0);
}

int ibtrs_srv_reset_user_ib_msgs_stats(struct ibtrs_srv_sess *sess, bool enable)
{
	if (enable) {
		memset(&sess->stats.user_ib_msgs, 0,
		       sizeof(sess->stats.user_ib_msgs));
		return 0;
	} else {
		return -EINVAL;
	}
}

int ibtrs_srv_stats_user_ib_msgs_to_str(struct ibtrs_srv_sess *sess, char *buf,
					size_t len)
{
	return snprintf(buf, len, "%ld %ld %ld %ld\n",
			atomic64_read(&sess->stats.user_ib_msgs.recv_msg_cnt),
			atomic64_read(&sess->stats.user_ib_msgs.recv_size),
			atomic64_read(&sess->stats.user_ib_msgs.sent_msg_cnt),
			atomic64_read(&sess->stats.user_ib_msgs.sent_size));
}

int ibtrs_srv_reset_wc_completion_stats(struct ibtrs_srv_sess *sess, bool enable)
{
	if (enable) {
		memset(&sess->stats.wc_comp, 0, sizeof(sess->stats.wc_comp));
		return 0;
	} else {
		return -EINVAL;
	}
}

int ibtrs_srv_stats_wc_completion_to_str(struct ibtrs_srv_sess *sess, char *buf,
					 size_t len)
{
	return snprintf(buf, len, "%d %ld %ld\n",
			atomic_read(&sess->stats.wc_comp.max_wc_cnt),
			atomic64_read(&sess->stats.wc_comp.total_wc_cnt),
			atomic64_read(&sess->stats.wc_comp.calls));
}

ssize_t ibtrs_srv_reset_all_help(struct ibtrs_srv_sess *sess,
				 char *page, size_t len)
{
	return scnprintf(page, PAGE_SIZE, "echo 1 to reset all statistics\n");
}

int ibtrs_srv_reset_all_stats(struct ibtrs_srv_sess *sess, bool enable)
{
	if (enable) {
		ibtrs_srv_reset_wc_completion_stats(sess, enable);
		ibtrs_srv_reset_user_ib_msgs_stats(sess, enable);
		ibtrs_srv_reset_rdma_stats(sess, enable);
		return 0;
	} else {
		return -EINVAL;
	}
}

static inline bool srv_ops_are_valid(const struct ibtrs_srv_ops *ops)
{
	return ops && ops->sess_ev && ops->rdma_ev && ops->recv;
}

/* XXX DIE ASAP */
static int ibtrs_srv_sess_ev(struct ibtrs_srv_sess *sess,
			     enum ibtrs_srv_sess_ev ev)
{
	struct ibtrs_srv_ctx *ctx = sess->ctx;

	if (!sess->session_announced_to_user &&
	    ev != IBTRS_SRV_SESS_EV_CONNECTED)
		return 0;

	if (ev == IBTRS_SRV_SESS_EV_CONNECTED)
		sess->session_announced_to_user = true;

	return ctx->ops.sess_ev(sess, ev, sess->priv);
}

static void free_id(struct ibtrs_srv_op *id)
{
	if (!id)
		return;
	kfree(id->tx_wr);
	kfree(id->tx_sg);
	kfree(id);
}

static void free_sess_tx_bufs(struct ibtrs_srv_sess *sess)
{
	int i;

	if (sess->rdma_info_iu) {
		ibtrs_iu_free(sess->rdma_info_iu, DMA_TO_DEVICE,
			      sess->s.ib_dev->dev);
		sess->rdma_info_iu = NULL;
	}
	ibtrs_usr_msg_free_list(&sess->s, sess->s.ib_dev);

	if (sess->ops_ids) {
		for (i = 0; i < sess->queue_depth; i++)
			free_id(sess->ops_ids[i]);
		kfree(sess->ops_ids);
		sess->ops_ids = NULL;
	}
}

static int rdma_write_sg(struct ibtrs_srv_op *id)
{
	struct ibtrs_srv_sess *sess = id->con->sess;
	struct ib_rdma_wr *wr = NULL;
	struct ib_send_wr *bad_wr;
	enum ib_send_flags flags;
	int err, i, offset;

	if (unlikely(id->req->sg_cnt == 0))
		return -EINVAL;

	offset = 0;
	for (i = 0; i < id->req->sg_cnt; i++) {
		struct ib_sge *list;

		wr		= &id->tx_wr[i];
		list		= &id->tx_sg[i];
		list->addr	= id->data_dma_addr + offset;
		list->length	= id->req->desc[i].len;

		/* WR will fail with length error
		 * if this is 0
		 */
		if (unlikely(list->length == 0)) {
			ibtrs_err(sess, "Invalid RDMA-Write sg list length 0\n");
			return -EINVAL;
		}

		list->lkey = sess->s.ib_dev->pd->local_dma_lkey;
		offset += list->length;

		wr->wr.sg_list	= list;
		wr->wr.num_sge	= 1;
		wr->remote_addr	= id->req->desc[i].addr;
		wr->rkey	= id->req->desc[i].key;

		if (i < (id->req->sg_cnt - 1)) {
			wr->wr.next	= &id->tx_wr[i + 1].wr;
			wr->wr.opcode	= IB_WR_RDMA_WRITE;
			wr->wr.ex.imm_data	= 0;
			wr->wr.send_flags	= 0;
		}
	}
	/*
	 * From time to time we have to post signalled sends,
	 * or send queue will fill up and only QP reset can help.
	 */
	flags = atomic_inc_return(&id->con->wr_cnt) % sess->queue_depth ?
			0 : IB_SEND_SIGNALED;

	wr->wr.opcode = IB_WR_RDMA_WRITE_WITH_IMM;
	wr->wr.next = NULL;
	wr->wr.send_flags = flags;
	wr->wr.ex.imm_data = cpu_to_be32(id->msg_id << 16);

	err = ib_post_send(id->con->ibtrs_con.qp, &id->tx_wr[0].wr, &bad_wr);
	if (unlikely(err))
		ibtrs_err(sess,
			  "Posting RDMA-Write-Request to QP failed, err: %d\n",
			  err);

	return err;
}

static int send_io_resp_imm(struct ibtrs_srv_con *con, int msg_id, s16 errno)
{
	struct ibtrs_srv_sess *sess = con->sess;
	enum ib_send_flags flags;
	u32 imm;
	int err;

	/*
	 * From time to time we have to post signalled sends,
	 * or send queue will fill up and only QP reset can help.
	 */
	flags = atomic_inc_return(&con->wr_cnt) % sess->queue_depth ?
			0 : IB_SEND_SIGNALED;
	imm = (msg_id << 16) | (u16)errno;
	err = ibtrs_post_rdma_write_imm_empty(con->ibtrs_con.qp,
					      &hb_and_ack_cqe,
					      imm, flags);
	if (unlikely(err))
		ibtrs_err_rl(sess, "ib_post_send(), err: %d\n", err);

	return err;
}

static int send_heartbeat_raw(struct ibtrs_srv_con *con)
{
	int err;

	err = ibtrs_post_rdma_write_imm_empty(con->ibtrs_con.qp,
					      &hb_and_ack_cqe,
					      IBTRS_HB_IMM,
					      IB_SEND_SIGNALED);
	if (unlikely(err)) {
		ibtrs_err(con->sess,
			  "Sending heartbeat failed, posting msg to QP failed,"
			  " err: %d\n", err);
		return err;
	}

	ibtrs_heartbeat_set_send_ts(&con->sess->heartbeat);
	return err;
}

static int send_heartbeat(struct ibtrs_srv_sess *sess)
{
	struct ibtrs_srv_con *con;

	if (unlikely(list_empty(&sess->con_list)))
		return -ENOENT;

	con = list_first_entry(&sess->con_list, struct ibtrs_srv_con, list);
	WARN_ON(!con->user);

	if (unlikely(con->state != CSM_STATE_CONNECTED))
		return -ENOTCONN;

	return send_heartbeat_raw(con);
}

static int ibtrs_srv_queue_resp_rdma(struct ibtrs_srv_op *id)
{
	if (unlikely(id->con->state != CSM_STATE_CONNECTED)) {
		ibtrs_err_rl(id->con->sess, "Sending I/O response failed, "
			     " session is disconnected, sess state %s,"
			     " con state %s\n", ssm_state_str(id->con->sess->state),
			     csm_state_str(id->con->state));
		return -ECOMM;
	}

	if (WARN_ON(!queue_work(id->con->rdma_resp_wq, &id->work))) {
		ibtrs_err_rl(id->con->sess, "Sending I/O response failed,"
			     " couldn't queue work\n");
		return -EPERM;
	}

	return 0;
}

static void ibtrs_srv_resp_rdma_worker(struct work_struct *work)
{
	struct ibtrs_srv_sess *sess;
	struct ibtrs_srv_op *id;
	int err;

	id = container_of(work, struct ibtrs_srv_op, work);
	sess = id->con->sess;

	if (id->status || id->dir == WRITE) {
		pr_debug("err or write msg_id=%d, status=%d, sending response\n",
			 id->msg_id, id->status);

		err = send_io_resp_imm(id->con, id->msg_id, id->status);
		if (unlikely(err)) {
			ibtrs_err_rl(sess, "Sending imm msg failed, err: %d\n",
				     err);
			if (err == -ENOMEM && !ibtrs_srv_queue_resp_rdma(id))
				return;
			csm_schedule_event(id->con, CSM_EV_CON_ERROR);
		}

		ibtrs_heartbeat_set_send_ts(&sess->heartbeat);
		ibtrs_srv_stats_dec_inflight(sess);
		return;
	}

	pr_debug("read req msg_id=%d completed, sending data\n", id->msg_id);
	err = rdma_write_sg(id);
	if (unlikely(err)) {
		ibtrs_err_rl(sess, "Sending I/O read response failed, err: %d\n",
			     err);
		if (err == -ENOMEM && !ibtrs_srv_queue_resp_rdma(id))
			return;
		csm_schedule_event(id->con, CSM_EV_CON_ERROR);
	}
	ibtrs_heartbeat_set_send_ts(&sess->heartbeat);
	ibtrs_srv_stats_dec_inflight(sess);
}

/*
 * XXX DO WE REALLY NEED THAT worqueue?
 *
 * This function may be called from an interrupt context, e.g. on bio_endio
 * callback on the user module. Queue the real work on a workqueue so we don't
 * need to hold an irq spinlock.
 */
int ibtrs_srv_resp_rdma(struct ibtrs_srv_op *id, int status)
{
	int err = 0;

	if (unlikely(!id)) {
		pr_err("Sending I/O response failed, I/O ops id NULL\n");
		return -EINVAL;
	}

	id->status = status;
	/* XXX DO WE REALLY NEED THAT worqueue? */
	INIT_WORK(&id->work, ibtrs_srv_resp_rdma_worker);

	err = ibtrs_srv_queue_resp_rdma(id);
	if (err)
		ibtrs_srv_stats_dec_inflight(id->con->sess);
	return err;
}
EXPORT_SYMBOL(ibtrs_srv_resp_rdma);

int ibtrs_srv_send(struct ibtrs_srv_sess *sess, const struct kvec *vec,
		   size_t nr)
{
	struct ibtrs_iu *iu = NULL;
	struct ibtrs_srv_con *con;
	struct ibtrs_msg_user *msg;
	size_t len;
	int err;

	if (WARN_ONCE(list_empty(&sess->con_list),
		      "Sending message failed, no connection available\n"))
		return -ECOMM;
	con = ibtrs_srv_get_user_con(sess);

	if (unlikely(!con)) {
		ibtrs_wrn(sess,
			  "Sending message failed, no user connection exists\n");
		return -ECOMM;
	}

	len = kvec_length(vec, nr);

	if (unlikely(len + IBTRS_HDR_LEN > MAX_REQ_SIZE)) {
		ibtrs_wrn_rl(sess, "Sending message failed, passed data too big,"
			     " %zu > %lu\n", len, MAX_REQ_SIZE - IBTRS_HDR_LEN);
		return -EMSGSIZE;
	}
	iu = ibtrs_usr_msg_get(&sess->s);
	if (unlikely(!iu)) {
		/* We are in disconnecting state, just return */
		ibtrs_err_rl(sess, "Sending user message failed, disconnecting");
		return -ECOMM;
	}

	msg		= iu->buf;
	msg->hdr.type	= IBTRS_MSG_USER;
	msg->hdr.tsize	= len + IBTRS_HDR_LEN;
	copy_from_kvec(msg->payl, vec, len);

	err = ibtrs_post_send(con->ibtrs_con.qp,
			      con->sess->s.ib_dev->mr,
			      iu, msg->hdr.tsize);
	if (unlikely(err)) {
		ibtrs_err_rl(sess, "Sending message failed, posting message to QP"
			     " failed, err: %d\n", err);
		goto err_post_send;
	}
	ibtrs_heartbeat_set_send_ts(&sess->heartbeat);

	atomic64_inc(&sess->stats.user_ib_msgs.sent_msg_cnt);
	atomic64_add(len, &sess->stats.user_ib_msgs.sent_size);

	return 0;

err_post_send:
	ibtrs_usr_msg_return_iu(&sess->s, iu);
	ibtrs_usr_msg_put(&sess->s);

	return err;
}
EXPORT_SYMBOL(ibtrs_srv_send);

inline void ibtrs_srv_set_sess_priv(struct ibtrs_srv_sess *sess, void *priv)
{
	sess->priv = priv;
}
EXPORT_SYMBOL(ibtrs_srv_set_sess_priv);

static int ibtrs_post_recv(struct ibtrs_srv_con *con, struct ibtrs_iu *iu)
{
	struct ib_recv_wr wr, *bad_wr;
	struct ib_sge list;
	int err;

	list.addr   = iu->dma_addr;
	list.length = iu->size;
	list.lkey   = con->sess->s.ib_dev->pd->local_dma_lkey;

	if (unlikely(list.length == 0)) {
		ibtrs_err_rl(con->sess, "Posting recv buffer failed, invalid sg list"
			     " length 0\n");
		return -EINVAL;
	}

	iu->cqe.done = ibtrs_srv_rdma_done;

	wr.next     = NULL;
	wr.wr_cqe   = &iu->cqe;
	wr.sg_list  = &list;
	wr.num_sge  = 1;

	err = ib_post_recv(con->ibtrs_con.qp, &wr, &bad_wr);
	if (unlikely(err))
		ibtrs_err_rl(con->sess, "Posting recv buffer failed, err: %d\n",
			     err);

	return err;
}

static struct ibtrs_rcv_buf_pool *alloc_rcv_buf_pool(void)
{
	struct ibtrs_rcv_buf_pool *pool;
	struct page *cont_pages = NULL;
	struct ibtrs_mem_chunk *mem_chunk;
	int alloced_bufs = 0;
	int rcv_buf_order = get_order(rcv_buf_size);
	int max_order, alloc_order;
	unsigned int alloced_size;

	pool = kzalloc(sizeof(*pool), GFP_KERNEL);
	if (!pool) {
		pr_err("Failed to allocate memory for buffer pool struct\n");
		return NULL;
	}

	pool->rcv_bufs = kcalloc(sess_queue_depth, sizeof(*pool->rcv_bufs),
				 GFP_KERNEL);
	if (!pool->rcv_bufs) {
		pr_err("Failed to allocate array for receive buffers\n");
		kfree(pool);
		return NULL;
	}
	INIT_LIST_HEAD(&pool->chunk_list);

	while (alloced_bufs < sess_queue_depth) {
		mem_chunk = kzalloc(sizeof(*mem_chunk), GFP_KERNEL);
		if (!mem_chunk) {
			pr_err("Failed to allocate memory for memory chunk"
			       " struct\n");
			goto alloc_fail;
		}

		max_order = min(MAX_ORDER - 1,
				get_order((sess_queue_depth - alloced_bufs) *
					  rcv_buf_size));
		for (alloc_order = max_order; alloc_order > rcv_buf_order;
		     alloc_order--) {
			cont_pages = alloc_pages(__GFP_NORETRY | __GFP_NOWARN |
						 __GFP_ZERO, alloc_order);
			if (cont_pages) {
				pr_debug("Allocated order %d pages\n", alloc_order);
				break;
			}
			pr_debug("Failed to allocate order %d pages\n", alloc_order);
		}

		if (cont_pages) {
			void *recv_buf_start;

			mem_chunk->order = alloc_order;
			mem_chunk->addr = page_address(cont_pages);
			list_add_tail(&mem_chunk->list, &pool->chunk_list);
			alloced_size = (1 << alloc_order) * PAGE_SIZE;

			pr_debug("Memory chunk size: %d, address: %p\n",
				 alloced_size, mem_chunk->addr);

			recv_buf_start = mem_chunk->addr;
			while (alloced_size > rcv_buf_size &&
			       alloced_bufs < sess_queue_depth) {
				pool->rcv_bufs[alloced_bufs].buf =
					recv_buf_start;
				alloced_bufs++;
				recv_buf_start += rcv_buf_size;
				alloced_size -= rcv_buf_size;
			}
		} else {
			/* if allocation of pages to fit multiple rcv_buf's
			 * failed we fall back to alloc'ing exact number of
			 * pages
			 */
			gfp_t gfp_mask = (GFP_KERNEL | __GFP_REPEAT |
					  __GFP_ZERO);
			void *addr = alloc_pages_exact(rcv_buf_size, gfp_mask);

			if (!addr) {
				pr_err("Failed to allocate memory for "
				       " receive buffer (size %dB)\n",
				       rcv_buf_size);
				goto alloc_fail;
			}

			pr_debug("Alloced pages exact at %p for rcv_bufs[%d]\n",
				 addr, alloced_bufs);

			mem_chunk->addr = addr;
			mem_chunk->order = IBTRS_MEM_CHUNK_NOORDER;
			list_add_tail(&mem_chunk->list, &pool->chunk_list);

			pool->rcv_bufs[alloced_bufs].buf = addr;
			alloced_bufs++;
		}
	}

	return pool;

alloc_fail:
	if (!list_empty(&pool->chunk_list)) {
		struct ibtrs_mem_chunk *tmp;

		list_for_each_entry_safe(mem_chunk, tmp, &pool->chunk_list,
					 list) {
			if (mem_chunk->order != IBTRS_MEM_CHUNK_NOORDER)
				free_pages((unsigned long)mem_chunk->addr,
					   mem_chunk->order);
			else
				free_pages_exact(mem_chunk->addr, rcv_buf_size);
			list_del(&mem_chunk->list);
			kfree(mem_chunk);
		}
	}
	kfree(pool->rcv_bufs);
	kfree(pool);
	return NULL;
}

static struct ibtrs_rcv_buf_pool *__get_pool_from_list(void)
{
	struct ibtrs_rcv_buf_pool *pool = NULL;

	if (!list_empty(&free_buf_pool_list)) {
		pr_debug("Getting buf pool from pre-allocated list\n");
		pool = list_first_entry(&free_buf_pool_list,
					struct ibtrs_rcv_buf_pool, list);
		list_del(&pool->list);
		nr_free_buf_pool--;
	}

	return pool;
}

static void __put_pool_on_list(struct ibtrs_rcv_buf_pool *pool)
{
	list_add(&pool->list, &free_buf_pool_list);
	nr_free_buf_pool++;
	pr_debug("Put buf pool back to the free list (nr_free_buf_pool: %d)\n",
		 nr_free_buf_pool);
}

static struct ibtrs_rcv_buf_pool *get_alloc_rcv_buf_pool(void)
{
	struct ibtrs_rcv_buf_pool *pool = NULL;

	mutex_lock(&buf_pool_mutex);
	if (nr_active_sessions >= pool_size_hi_wm) {
		WARN_ON(nr_free_buf_pool || !list_empty(&free_buf_pool_list));
		pr_debug("current nr_active_sessions (%d), pool_size_hi_wm (%d),"
			 ", allocating.\n", nr_active_sessions, pool_size_hi_wm);
		pool = alloc_rcv_buf_pool();
	} else if (nr_total_buf_pool < pool_size_hi_wm) {
		/* try to allocate new pool while used+free is less then
		 * watermark
		 */
		pr_debug("nr_total_buf_pool (%d) smaller than pool_size_hi_wm (%d)"
			 ", trying to allocate.\n", nr_total_buf_pool,
			 pool_size_hi_wm);
		pool = alloc_rcv_buf_pool();
		if (pool)
			nr_total_buf_pool++;
		else
			pool = __get_pool_from_list();
	} else if (nr_total_buf_pool == pool_size_hi_wm) {
		/* pool size has already reached watermark, check if there are
		 * free pools on the list
		 */
		if (nr_free_buf_pool) {
			pool = __get_pool_from_list();
			WARN_ON(!pool);
			pr_debug("Got pool from free list (nr_free_buf_pool: %d)\n",
				 nr_free_buf_pool);
		} else {
			/* all pools are already being used */
			pr_debug("No free pool on the list\n");
			WARN_ON((nr_active_sessions != nr_total_buf_pool) ||
				nr_free_buf_pool);
			pool = alloc_rcv_buf_pool();
		}
	} else {
		/* all possibilities should be covered */
		WARN_ON(1);
	}

	if (pool)
		nr_active_sessions++;

	mutex_unlock(&buf_pool_mutex);

	return pool;
}

static void free_recv_buf_pool(struct ibtrs_rcv_buf_pool *pool)
{
	struct ibtrs_mem_chunk *mem_chunk, *tmp;

	pr_debug("Freeing memory chunks for %d receive buffers\n", sess_queue_depth);

	list_for_each_entry_safe(mem_chunk, tmp, &pool->chunk_list, list) {
		if (mem_chunk->order != IBTRS_MEM_CHUNK_NOORDER)
			free_pages((unsigned long)mem_chunk->addr,
				   mem_chunk->order);
		else
			free_pages_exact(mem_chunk->addr, rcv_buf_size);
		list_del(&mem_chunk->list);
		kfree(mem_chunk);
	}

	kfree(pool->rcv_bufs);
	kfree(pool);
}

static void put_rcv_buf_pool(struct ibtrs_rcv_buf_pool *pool)
{
	mutex_lock(&buf_pool_mutex);
	nr_active_sessions--;
	if (nr_active_sessions >= pool_size_hi_wm) {
		mutex_unlock(&buf_pool_mutex);
		pr_debug("Freeing buf pool"
			 " (nr_active_sessions: %d, pool_size_hi_wm: %d)\n",
			 nr_active_sessions, pool_size_hi_wm);
		free_recv_buf_pool(pool);
	} else {
		__put_pool_on_list(pool);
		mutex_unlock(&buf_pool_mutex);
	}
}

static void unreg_cont_bufs(struct ibtrs_srv_sess *sess)
{
	struct ibtrs_rcv_buf *buf;
	int i;

	pr_debug("Unregistering %d RDMA buffers\n", sess_queue_depth);
	for (i = 0; i < sess_queue_depth; i++) {
		buf = &sess->rcv_buf_pool->rcv_bufs[i];

		ib_dma_unmap_single(sess->s.ib_dev->dev, buf->rdma_addr,
				    rcv_buf_size, DMA_BIDIRECTIONAL);
	}
}

static void release_cont_bufs(struct ibtrs_srv_sess *sess)
{
	unreg_cont_bufs(sess);
	put_rcv_buf_pool(sess->rcv_buf_pool);
	sess->rcv_buf_pool = NULL;
}

static int setup_cont_bufs(struct ibtrs_srv_sess *sess)
{
	struct ibtrs_rcv_buf *buf;
	int i, err;

	sess->rcv_buf_pool = get_alloc_rcv_buf_pool();
	if (!sess->rcv_buf_pool) {
		ibtrs_err(sess, "Failed to allocate receive buffers for session\n");
		return -ENOMEM;
	}

	pr_debug("Mapping %d buffers for RDMA\n", sess->queue_depth);
	for (i = 0; i < sess->queue_depth; i++) {
		buf = &sess->rcv_buf_pool->rcv_bufs[i];

		buf->rdma_addr = ib_dma_map_single(sess->s.ib_dev->dev,
						   buf->buf, rcv_buf_size,
						   DMA_BIDIRECTIONAL);
		if (unlikely(ib_dma_mapping_error(sess->s.ib_dev->dev,
						  buf->rdma_addr))) {
			pr_err("Registering RDMA buf failed,"
			       " DMA mapping failed\n");
			err = -EIO;
			goto err_map;
		}
	}

	sess->off_len = 31 - ilog2(sess->queue_depth - 1);
	sess->off_mask = (1 << sess->off_len) - 1;

	ibtrs_info(sess, "Allocated %d %dKB RDMA receive buffers, %dKB in total\n",
		   sess->queue_depth, rcv_buf_size >> 10,
		   sess->queue_depth * rcv_buf_size >> 10);

	return 0;

err_map:
	for (i = 0; i < sess->queue_depth; i++) {
		buf = &sess->rcv_buf_pool->rcv_bufs[i];

		if (buf->rdma_addr &&
		    !ib_dma_mapping_error(sess->s.ib_dev->dev, buf->rdma_addr))
			ib_dma_unmap_single(sess->s.ib_dev->dev, buf->rdma_addr,
					    rcv_buf_size, DMA_BIDIRECTIONAL);
	}
	return err;
}

static void fill_ibtrs_msg_sess_open_resp(struct ibtrs_msg_sess_open_resp *msg,
					  struct ibtrs_srv_con *con)
{
	int i;

	msg->hdr.type   = IBTRS_MSG_SESS_OPEN_RESP;
	msg->hdr.tsize  = IBTRS_MSG_SESS_OPEN_RESP_LEN(con->sess->queue_depth);

	msg->ver = IBTRS_VERSION;
	strlcpy(msg->hostname, hostname, sizeof(msg->hostname));
	msg->cnt = con->sess->queue_depth;
	msg->rkey = con->sess->s.ib_dev->pd->unsafe_global_rkey;
	msg->max_inflight_msg = con->sess->queue_depth;
	msg->max_io_size = max_io_size;
	msg->max_req_size = MAX_REQ_SIZE;
	for (i = 0; i < con->sess->queue_depth; i++)
		msg->addr[i] = con->sess->rcv_buf_pool->rcv_bufs[i].rdma_addr;
}

static int alloc_sess_tx_bufs(struct ibtrs_srv_sess *sess)
{
	struct ibtrs_srv_op *id;
	int i, err;

	sess->rdma_info_iu =
		ibtrs_iu_alloc(0, IBTRS_MSG_SESS_OPEN_RESP_LEN(
				       sess->queue_depth), GFP_KERNEL,
			       sess->s.ib_dev->dev, DMA_TO_DEVICE);
	if (unlikely(!sess->rdma_info_iu)) {
		ibtrs_err(sess, "Allocation failed\n");
		return -ENOMEM;
	}
	sess->ops_ids = kcalloc(sess->queue_depth, sizeof(*sess->ops_ids),
				GFP_KERNEL);
	if (unlikely(!sess->ops_ids)) {
		ibtrs_err(sess, "Allocation failed\n");
		goto err;
	}
	for (i = 0; i < sess->queue_depth; ++i) {
		id = kzalloc(sizeof(*id), GFP_KERNEL);
		if (unlikely(!id)) {
			ibtrs_err(sess, "Allocation failed\n");
			goto err;
		}
		sess->ops_ids[i] = id;
	}
	err = ibtrs_usr_msg_alloc_list(&sess->s, sess->s.ib_dev,
				       MAX_REQ_SIZE);
	if (unlikely(err)) {
		ibtrs_err(sess, "Allocation failed\n");
		goto err;
	}

	return 0;

err:
	free_sess_tx_bufs(sess);
	return -ENOMEM;
}

static int alloc_sess_bufs(struct ibtrs_srv_sess *sess)
{
	int err;

	err = ibtrs_iu_alloc_sess_rx_bufs(&sess->s, MAX_REQ_SIZE);
	if (unlikely(err))
		return err;

	err = alloc_sess_tx_bufs(sess);
	if (unlikely(err))
		ibtrs_iu_free_sess_rx_bufs(&sess->s);

	return err;
}

static int post_recv_io(struct ibtrs_srv_con *con)
{
	struct ibtrs_srv_sess *sess = con->sess;
	struct ibtrs_iu *iu = sess->s.dummy_rx_iu;
	int i, err;

	for (i = 0; i < sess->queue_depth; i++) {
		err = ibtrs_post_recv(con, iu);
		if (unlikely(err))
			return err;
	}

	return 0;
}

static int post_recv_usr(struct ibtrs_srv_con *con)
{
	struct ibtrs_srv_sess *sess = con->sess;
	struct ibtrs_iu *iu;
	int i, err;

	for (i = 0; i < USR_CON_BUF_SIZE; i++) {
		iu = sess->s.usr_rx_ring[i];
		err = ibtrs_post_recv(con, iu);
		if (unlikely(err))
			return err;
	}

	return 0;
}

static int post_recv(struct ibtrs_srv_con *con)
{
	if (con->cid == 0)
		return post_recv_usr(con);
	return post_recv_io(con);
}

static void free_sess_bufs(struct ibtrs_srv_sess *sess)
{
	ibtrs_iu_free_sess_rx_bufs(&sess->s);
	free_sess_tx_bufs(sess);
}

static int init_transfer_bufs(struct ibtrs_srv_con *con)
{
	struct ibtrs_srv_sess *sess = con->sess;
	int err;

	if (con->user) {
		err = alloc_sess_bufs(sess);
		if (err) {
			ibtrs_err(sess, "Alloc sess bufs failed, err: %d\n",
				  err);
			return err;
		}
	}

	return post_recv(con);
}

static void process_rdma_write_req(struct ibtrs_srv_con *con,
				   struct ibtrs_msg_req_rdma_write *req,
				   u32 buf_id, u32 off)
{
	struct ibtrs_srv_sess *sess = con->sess;
	struct ibtrs_srv_ctx *ctx = sess->ctx;
	struct ibtrs_srv_op *id;
	int ret;

	if (unlikely(sess->state != SSM_STATE_CONNECTED ||
		     con->state != CSM_STATE_CONNECTED)) {
		ibtrs_err_rl(sess, "Processing RDMA-Write-Req request failed, "
			     " session is disconnected, sess state %s,"
			     " con state %s\n", ssm_state_str(sess->state),
			     csm_state_str(con->state));
		return;
	}
	ibtrs_srv_update_rdma_stats(&sess->stats, off, true);
	id = sess->ops_ids[buf_id];
	kfree(id->tx_wr);
	kfree(id->tx_sg);
	id->con		= con;
	id->dir		= READ;
	id->msg_id	= buf_id;
	id->req		= req;
	id->tx_wr	= kcalloc(req->sg_cnt, sizeof(*id->tx_wr), GFP_KERNEL);
	id->tx_sg	= kcalloc(req->sg_cnt, sizeof(*id->tx_sg), GFP_KERNEL);
	if (!id->tx_wr || !id->tx_sg) {
		ibtrs_err_rl(sess, "Processing RDMA-Write-Req failed, work request "
			     "or scatter gather allocation failed for msg_id %d\n",
			     buf_id);
		ret = -ENOMEM;
		goto send_err_msg;
	}

	id->data_dma_addr = sess->rcv_buf_pool->rcv_bufs[buf_id].rdma_addr;
	ret = ctx->ops.rdma_ev(con->sess, sess->priv, id,
			       IBTRS_SRV_RDMA_EV_WRITE_REQ,
			       sess->rcv_buf_pool->rcv_bufs[buf_id].buf, off);

	if (unlikely(ret)) {
		ibtrs_err_rl(sess, "Processing RDMA-Write-Req failed, user "
			     "module cb reported for msg_id %d, err: %d\n",
			     buf_id, ret);
		goto send_err_msg;
	}

	return;

send_err_msg:
	ret = send_io_resp_imm(con, buf_id, ret);
	if (ret < 0) {
		ibtrs_err_rl(sess, "Sending err msg for failed RDMA-Write-Req"
			     " failed, msg_id %d, err: %d\n", buf_id, ret);
		csm_schedule_event(con, CSM_EV_CON_ERROR);
	}
	ibtrs_srv_stats_dec_inflight(sess);
}

static void process_rdma_write(struct ibtrs_srv_con *con,
			       struct ibtrs_msg_rdma_write *req,
			       u32 buf_id, u32 off)
{
	struct ibtrs_srv_sess *sess = con->sess;
	struct ibtrs_srv_ctx *ctx = sess->ctx;
	struct ibtrs_srv_op *id;
	int ret;

	if (unlikely(sess->state != SSM_STATE_CONNECTED ||
		     con->state != CSM_STATE_CONNECTED)) {
		ibtrs_err_rl(sess, "Processing RDMA-Write request failed, "
			     " session is disconnected, sess state %s,"
			     " con state %s\n", ssm_state_str(sess->state),
			     csm_state_str(con->state));
		return;
	}
	ibtrs_srv_update_rdma_stats(&sess->stats, off, false);
	id = con->sess->ops_ids[buf_id];
	id->con    = con;
	id->dir    = WRITE;
	id->msg_id = buf_id;

	ret = ctx->ops.rdma_ev(sess, sess->priv, id, IBTRS_SRV_RDMA_EV_RECV,
			       sess->rcv_buf_pool->rcv_bufs[buf_id].buf, off);
	if (unlikely(ret)) {
		ibtrs_err_rl(sess, "Processing RDMA-Write failed, user module"
			     " callback reports err: %d\n", ret);
		goto send_err_msg;
	}

	return;

send_err_msg:
	ret = send_io_resp_imm(con, buf_id, ret);
	if (ret < 0) {
		ibtrs_err_rl(sess, "Processing RDMA-Write failed, sending I/O"
			     " response failed, msg_id %d, err: %d\n",
			     buf_id, ret);
		csm_schedule_event(con, CSM_EV_CON_ERROR);
	}
	ibtrs_srv_stats_dec_inflight(sess);
}

static int ibtrs_send_usr_msg_ack(struct ibtrs_srv_con *con)
{
	struct ibtrs_srv_sess *sess;
	int err;

	sess = con->sess;

	if (unlikely(con->state != CSM_STATE_CONNECTED)) {
		ibtrs_err_rl(sess, "Sending user msg ack failed, disconnected"
			     " Connection state is %s\n", csm_state_str(con->state));
		return -ECOMM;
	}
	pr_debug("Sending user message ack\n");
	err = ibtrs_post_rdma_write_imm_empty(con->ibtrs_con.qp,
					      &hb_and_ack_cqe,
					      IBTRS_ACK_IMM,
					      IB_SEND_SIGNALED);
	if (unlikely(err)) {
		ibtrs_err_rl(sess, "Sending user Ack msg failed, err: %d\n",
			     err);
		return err;
	}

	ibtrs_heartbeat_set_send_ts(&sess->heartbeat);
	return 0;
}

static void process_msg_user(struct ibtrs_srv_con *con,
			     struct ibtrs_msg_user *msg)
{
	struct ibtrs_srv_sess *sess = con->sess;
	struct ibtrs_srv_ctx *ctx = sess->ctx;
	int len;

	len = msg->hdr.tsize - IBTRS_HDR_LEN;
	if (unlikely(sess->state < SSM_STATE_CONNECTED || !sess->priv)) {
		ibtrs_err_rl(sess, "Sending user msg failed, session isn't ready."
			     " Session state is %s\n", ssm_state_str(sess->state));
		return;
	}

	ctx->ops.recv(sess, sess->priv, msg->payl, len);

	atomic64_inc(&sess->stats.user_ib_msgs.recv_msg_cnt);
	atomic64_add(len, &sess->stats.user_ib_msgs.recv_size);
}

static void process_msg_user_ack(struct ibtrs_srv_con *con)
{
	struct ibtrs_srv_sess *sess = con->sess;

	ibtrs_usr_msg_put(&sess->s);
}

static void ibtrs_handle_write(struct ibtrs_srv_con *con, struct ibtrs_iu *iu,
			       struct ibtrs_msg_hdr *hdr, u32 id, u32 off)
{
	struct ibtrs_srv_sess *sess = con->sess;
	int ret;

	if (unlikely(ibtrs_validate_message(hdr))) {
		ibtrs_err(sess,
			  "Processing I/O failed, message validation failed\n");
		ret = ibtrs_post_recv(con, iu);
		if (unlikely(ret != 0))
			ibtrs_err(sess,
				  "Failed to post receive buffer to HCA, err: %d\n",
				  ret);
		goto err;
	}

	pr_debug("recv completion, type 0x%02x, tag %u, id %u, off %u\n",
		 hdr->type, iu->tag, id, off);
	print_hex_dump_debug("", DUMP_PREFIX_OFFSET, 8, 1,
			     hdr, IBTRS_HDR_LEN + 32, true);
	ret = ibtrs_post_recv(con, iu);
	if (unlikely(ret != 0)) {
		ibtrs_err(sess, "Posting receive buffer to HCA failed, err: %d\n",
			  ret);
		goto err;
	}

	switch (hdr->type) {
	case IBTRS_MSG_RDMA_WRITE:
		process_rdma_write(con, (struct ibtrs_msg_rdma_write *)hdr,
				   id, off);
		break;
	case IBTRS_MSG_REQ_RDMA_WRITE:
		process_rdma_write_req(con,
				       (struct ibtrs_msg_req_rdma_write *)hdr,
				       id, off);
		break;
	default:
		ibtrs_err(sess, "Processing I/O request failed, "
			  "unknown message type received: 0x%02x\n", hdr->type);
		goto err;
	}

	return;

err:
	csm_schedule_event(con, CSM_EV_CON_ERROR);
}

static void msg_worker(struct work_struct *work)
{
	struct msg_work *w;
	struct ibtrs_srv_con *con;
	struct ibtrs_msg_user *msg;

	w = container_of(work, struct msg_work, work);
	con = w->con;
	msg = w->msg;
	kfree(w);
	process_msg_user(con, msg);
	kfree(msg);
}

static int ibtrs_schedule_msg(struct ibtrs_srv_con *con,
			      struct ibtrs_msg_user *msg)
{
	struct msg_work *w;

	w = kmalloc(sizeof(*w), GFP_KERNEL | __GFP_REPEAT);
	if (!w)
		return -ENOMEM;

	w->con = con;
	w->msg = kmalloc(msg->hdr.tsize, GFP_KERNEL | __GFP_REPEAT);
	if (!w->msg) {
		kfree(w);
		return -ENOMEM;
	}
	memcpy(w->msg, msg, msg->hdr.tsize);
	INIT_WORK(&w->work, msg_worker);
	queue_work(ibtrs_wq, &w->work);
	return 0;
}

/* XXX DIE ASAP */
__attribute__((unused))
static void ibtrs_handle_recv(struct ibtrs_srv_con *con, struct ibtrs_iu *iu)
{
	struct ibtrs_msg_hdr *hdr;
	struct ibtrs_msg_sess_info *req;
	struct ibtrs_srv_sess *sess = con->sess;
	int ret;
	u8 type;

	hdr = (struct ibtrs_msg_hdr *)iu->buf;
	if (unlikely(ibtrs_validate_message(hdr)))
		goto err1;

	type = hdr->type;

	pr_debug("recv completion, type 0x%02x, tag %u\n",
		 type, iu->tag);
	print_hex_dump_debug("", DUMP_PREFIX_OFFSET, 8, 1,
			     iu->buf, IBTRS_HDR_LEN, true);

	switch (type) {
	case IBTRS_MSG_USER:
		ret = ibtrs_schedule_msg(con, iu->buf);
		if (unlikely(ret)) {
			ibtrs_err_rl(sess, "Scheduling worker of user message "
				     "to user module failed, err: %d\n",
				     ret);
			goto err1;
		}
		ret = ibtrs_post_recv(con, iu);
		if (unlikely(ret)) {
			ibtrs_err_rl(sess, "Posting receive buffer of user message "
				     "to HCA failed, err: %d\n", ret);
			goto err2;
		}
		ret = ibtrs_send_usr_msg_ack(con);
		if (unlikely(ret)) {
			ibtrs_err_rl(sess, "Sending ACK for user message failed, "
				     "err: %d\n", ret);
			goto err2;
		}
		return;
	case IBTRS_MSG_SESS_INFO:
		ret = ibtrs_post_recv(con, iu);
		if (unlikely(ret)) {
			ibtrs_err_rl(sess, "Posting receive buffer of sess info "
				     "to HCA failed, err: %d\n", ret);
			goto err2;
		}
		req = (struct ibtrs_msg_sess_info *)hdr;
		memcpy(sess->s.addr.hostname, req->hostname,
		       sizeof(req->hostname));
		return;
	default:
		ibtrs_err(sess, "Processing received message failed, "
			  "unknown type: 0x%02x\n", type);
		goto err1;
	}

err1:
	ibtrs_post_recv(con, iu);
err2:
	ibtrs_err(sess, "Failed to process IBTRS message\n");
	csm_schedule_event(con, CSM_EV_CON_ERROR);
}

static void ibtrs_srv_info_req_done(struct ib_cq *cq, struct ib_wc *wc)
{
	struct ibtrs_srv_con *con = cq->cq_context;
	struct ibtrs_srv_sess *sess = con->sess;
	struct ibtrs_iu *iu;

	iu = container_of(wc->wr_cqe, struct ibtrs_iu, cqe);
	ibtrs_iu_free(iu, DMA_TO_DEVICE, sess->s.ib_dev->dev);
}

static int ibtrs_handle_info_req_NEW(struct ibtrs_srv_con *con,
				     struct ibtrs_msg_info_req *msg)
{
	struct ibtrs_srv_sess *sess = con->sess;
	struct ibtrs_srv_ctx *ctx = sess->ctx;
	struct ibtrs_msg_info_rsp *rsp;
	struct ibtrs_iu *tx_iu;
	size_t tx_sz;
	int i, err;
	u64 addr;

	memcpy(sess->s.addr.hostname, msg->hostname, sizeof(msg->hostname));

	tx_sz  = sizeof(struct ibtrs_msg_info_rsp);
	tx_sz += sizeof(u64) * sess->queue_depth;
	tx_iu = ibtrs_iu_alloc(0, tx_sz, GFP_KERNEL, sess->s.ib_dev->dev,
			       DMA_TO_DEVICE);
	if (unlikely(!tx_iu)) {
		ibtrs_err(sess, "ibtrs_iu_alloc(), err: %d\n", -ENOMEM);
		return -ENOMEM;
	}

	rsp = tx_iu->buf;
	rsp->type = cpu_to_le16(IBTRS_MSG_INFO_RSP);
	rsp->addr_num = cpu_to_le16(sess->queue_depth);
	strlcpy(rsp->hostname, hostname, sizeof(rsp->hostname));
	for (i = 0; i < sess->queue_depth; i++) {
		addr = sess->rcv_buf_pool->rcv_bufs[i].rdma_addr;
		rsp->addr[i] = cpu_to_le64(addr);
	}
	/* Send info response */
	tx_iu->cqe.done = ibtrs_srv_info_req_done;
	err = ibtrs_post_send(con->ibtrs_con.qp, sess->s.ib_dev->mr,
			      tx_iu, tx_sz);
	if (unlikely(err)) {
		ibtrs_err(sess, "ibtrs_post_send(), err: %d\n", err);
		ibtrs_iu_free(tx_iu, DMA_TO_DEVICE, sess->s.ib_dev->dev);
	}
	/*
	 * We do not account number of established connections at the current
	 * moment, we rely on the client, which should send info request when
	 * all connections are successfully established.  Thus, simply notify
	 * listener with proper event when info request is received.
	 */
	ctx->ops.sess_ev(sess, IBTRS_SRV_SESS_EV_CONNECTED, sess->priv);

	return err;
}

static void close_sess_NEW(struct ibtrs_srv_sess *sess);

static void ibtrs_handle_recv_NEW(struct ibtrs_srv_con *con, struct ibtrs_iu *iu)
{
	struct ibtrs_srv_sess *sess = con->sess;
	int err, type;

	type = le16_to_cpu(*(__le16 *)iu->buf);
	pr_debug("recv completion, type 0x%02x, tag %u\n", type, iu->tag);
	print_hex_dump_debug("", DUMP_PREFIX_OFFSET, 8, 1,
			     iu->buf, IBTRS_HDR_LEN, true);

	switch (type) {
	case IBTRS_MSG_USER:
		err = ibtrs_schedule_msg(con, iu->buf);
		if (unlikely(err)) {
			ibtrs_err(sess, "ibtrs_schedule_msg(), err: %d\n",
				  err);
			goto err;
		}
		err = ibtrs_post_recv(con, iu);
		if (unlikely(err)) {
			ibtrs_err(sess, "ibtrs_post_recv(), err: %d\n", err);
			goto err;
		}
		err = ibtrs_send_usr_msg_ack(con);
		if (unlikely(err)) {
			ibtrs_err(sess, "ibtrs_send_usr_msg_ack(), err: %d\n",
				  err);
			goto err;
		}
		break;
	case IBTRS_MSG_INFO_REQ:
		err = ibtrs_handle_info_req_NEW(con, iu->buf);
		if (unlikely(err)) {
			ibtrs_err(sess, "ibtrs_handle_info_req(), err: %d\n",
				  err);
			goto err;
		}
		err = ibtrs_post_recv(con, iu);
		if (unlikely(err)) {
			ibtrs_err(sess, "ibtrs_post_recv(), err: %d\n", err);
			goto err;
		}
		break;
	default:
		ibtrs_err(sess, "Processing received message failed, "
			  "unknown type: 0x%02x\n", type);
		goto err;
	}

	return;

err:
	close_sess_NEW(sess);
}

static void add_con_to_list(struct ibtrs_srv_sess *sess,
			    struct ibtrs_srv_con *con)
{
	mutex_lock(&sess->lock);
	list_add_tail(&con->list, &sess->con_list);
	mutex_unlock(&sess->lock);
}

static void remove_con_from_list(struct ibtrs_srv_con *con)
{
	if (WARN_ON(!con->sess))
		return;
	mutex_lock(&con->sess->lock);
	list_del(&con->list);
	mutex_unlock(&con->sess->lock);
}

static void close_con(struct ibtrs_srv_con *con)
{
	struct ibtrs_srv_sess *sess = con->sess;

	pr_debug("Closing connection %p\n", con);

	if (con->user)
		cancel_delayed_work(&sess->send_heartbeat_dwork);

	destroy_workqueue(con->rdma_resp_wq);

	ibtrs_cq_qp_destroy(&con->ibtrs_con);
	if (!con->device_being_removed)
		rdma_destroy_id(con->cm_id);

	con->sess->active_cnt--;
}

static void destroy_con(struct ibtrs_srv_con *con)
{
	remove_con_from_list(con);
	kfree(con);
}

static void destroy_sess(struct kref *kref)
{
	struct ibtrs_srv_con *con, *con_next;
	struct ibtrs_srv_sess *sess;
	struct ibtrs_srv_ctx *ctx;

	sess = container_of(kref, struct ibtrs_srv_sess, kref);
	ctx = sess->ctx;

	destroy_workqueue(sess->sm_wq);

	list_for_each_entry_safe(con, con_next, &sess->con_list, list)
		destroy_con(con);

	mutex_lock(&ctx->sess_mutex);
	list_del(&sess->ctx_list);
	mutex_unlock(&ctx->sess_mutex);
	wake_up(&ctx->sess_list_waitq);

	ibtrs_info(sess, "Session is closed\n");
	kfree(sess);
}

int ibtrs_srv_sess_get(struct ibtrs_srv_sess *sess)
{
	return kref_get_unless_zero(&sess->kref);
}

void ibtrs_srv_sess_put(struct ibtrs_srv_sess *sess)
{
	kref_put(&sess->kref, destroy_sess);
}

static void sess_put_worker(struct work_struct *work)
{
	struct sess_put_work *w = container_of(work, struct sess_put_work,
					       work);

	ibtrs_srv_sess_put(w->sess);
	kfree(w);
}

static void schedule_sess_put(struct ibtrs_srv_sess *sess)
{
	struct sess_put_work *w;

	while (true) {
		w = kmalloc(sizeof(*w), GFP_KERNEL | __GFP_REPEAT);
		if (w)
			break;
		cond_resched();
	}

	/* Since we can be closing this session from a session workqueue,
	 * we need to schedule another work on the global workqueue to put the
	 * session, which can destroy the session workqueue and free the
	 * session.
	 */
	w->sess = sess;
	INIT_WORK(&w->work, sess_put_worker);
	queue_work(ibtrs_wq, &w->work);
}

static void ibtrs_srv_sysfs_put_worker(struct work_struct *work)
{
	struct ibtrs_srv_sysfs_put_work *w;

	w = container_of(work, struct ibtrs_srv_sysfs_put_work, work);
	kobject_put(&w->sess->kobj_stats);
	kobject_put(&w->sess->kobj);

	kfree(w);
}

static void ibtrs_srv_schedule_sysfs_put(struct ibtrs_srv_sess *sess)
{
	struct ibtrs_srv_sysfs_put_work *w;

	w = kmalloc(sizeof(*w), GFP_KERNEL | __GFP_REPEAT);

	if (WARN_ON(!w))
		return;

	w->sess	= sess;

	INIT_WORK(&w->work, ibtrs_srv_sysfs_put_worker);
	queue_work(ibtrs_wq, &w->work);
}

static void ibtrs_srv_sess_destroy(struct ibtrs_srv_sess *sess)
{
	release_cont_bufs(sess);
	free_sess_bufs(sess);
	ibtrs_ib_dev_put(sess->s.ib_dev);
}

static void process_err_wc(struct ibtrs_srv_con *con, struct ib_wc *wc)
{
	struct ibtrs_srv_sess *sess = con->sess;
	struct ibtrs_iu *iu;

	if (wc->wr_cqe == &con->ibtrs_con.beacon_cqe) {
		pr_debug("beacon received for con %p\n", con);
		csm_schedule_event(con, CSM_EV_BEACON_COMPLETED);
		return;
	}
	if (wc->wr_cqe == &hb_and_ack_cqe) {
		ibtrs_err_rl(sess, "ib_post_send() of hb or ack failed, "
			     "status: %s\n", ib_wc_status_msg(wc->status));
		csm_schedule_event(con, CSM_EV_CON_ERROR);
		return;
	}
	/*
	 * Only wc->wr_cqe is ensured to be correct in erroneous WCs,
	 * we can't rely on wc->opcode, use iu->direction to determine
	 * if it's an tx or rx IU.
	 */
	iu = container_of(wc->wr_cqe, struct ibtrs_iu, cqe);
	if (iu && iu->direction == DMA_TO_DEVICE && iu != sess->rdma_info_iu)
		ibtrs_usr_msg_return_iu(&sess->s, iu);

	if (wc->status != IB_WC_WR_FLUSH_ERR ||
	    (con->state != CSM_STATE_CLOSING &&
	     con->state != CSM_STATE_FLUSHING)) {
		/* suppress flush errors when the connection has
		 * just called rdma_disconnect() and is in
		 * DISCONNECTING state waiting for the second
		 * CM_DISCONNECTED event
		 */
		ibtrs_err_rl(sess, "%s (wr_cqe: %p,"
			     " type: %s, vendor_err: 0x%x, len: %u)\n",
			     ib_wc_status_msg(wc->status), wc->wr_cqe,
			     ib_wc_opcode_str(wc->opcode),
			     wc->vendor_err, wc->byte_len);
	}
	csm_schedule_event(con, CSM_EV_CON_ERROR);
}

static void ibtrs_srv_update_wc_stats(struct ibtrs_srv_con *con)
{
	//XXX remove ASAP
	//XXX int old_max = atomic_read(&con->sess->stats.wc_comp.max_wc_cnt);

	atomic64_inc(&con->sess->stats.wc_comp.calls);
	atomic64_inc(&con->sess->stats.wc_comp.total_wc_cnt);
}

static void ibtrs_srv_rdma_done(struct ib_cq *cq, struct ib_wc *wc)
{
	struct ibtrs_srv_con *con = cq->cq_context;
	struct ibtrs_srv_sess *sess = con->sess;
	struct ibtrs_msg_hdr *hdr;
	struct ibtrs_iu *iu;
	u32 imm, msg_id, off;
	int ret;

	ibtrs_srv_update_wc_stats(con);
	if (unlikely(wc->status != IB_WC_SUCCESS)) {
		process_err_wc(con, wc);
		return;
	}

	switch (wc->opcode) {
	case IB_WC_SEND:
		/*
		 * post_send() completions: beacon, sess info resp, user msgs
		 */
		iu = container_of(wc->wr_cqe, struct ibtrs_iu, cqe);
		if (iu == sess->rdma_info_iu)
			break;
		if (con->user)
			//XXX WTF? should be WARN_ON if !con->user
			ibtrs_usr_msg_return_iu(&sess->s, iu);
		break;
	case IB_WC_RECV:
		/*
		 * post_recv() completions: sess info, user msgs
		 */
		ibtrs_heartbeat_set_recv_ts(&sess->heartbeat);
		iu = container_of(wc->wr_cqe, struct ibtrs_iu, cqe);
		ibtrs_handle_recv_NEW(con, iu);
		break;
	case IB_WC_RDMA_WRITE:
		/*
		 * post_send() RDMA write completions of IO reqs (read/write),
		 *             user msgs acks, heartbeats
		 */
		break;
	case IB_WC_RECV_RDMA_WITH_IMM:
		/*
		 * post_recv() RDMA write completions of IO reqs (read/write),
		 *             user msgs acks, heartbeats
		 */
		ibtrs_heartbeat_set_recv_ts(&sess->heartbeat);
		iu = container_of(wc->wr_cqe, struct ibtrs_iu, cqe);
		imm = be32_to_cpu(wc->ex.imm_data);
		if (imm == IBTRS_HB_IMM) {
			ret = ibtrs_post_recv(con, iu);
			if (unlikely(ret != 0)) {
				ibtrs_err(sess, "post receive buffer failed,"
					  " err: %d\n", ret);
				csm_schedule_event(con, CSM_EV_CON_ERROR);
				return;
			}
			break;
		} else if (imm == IBTRS_ACK_IMM) {
			ret = ibtrs_post_recv(con, iu);
			if (unlikely(ret))
				ibtrs_err_rl(sess, "Posting receive buffer of"
					     " user Ack msg to HCA failed,"
					     " err: %d\n", ret);
			process_msg_user_ack(con);
			break;
		}
		msg_id = imm >> sess->off_len;
		off = imm & sess->off_mask;

		if (msg_id > sess->queue_depth || off > rcv_buf_size) {
			ibtrs_err(sess, "Processing I/O failed, contiguous "
				  "buf addr is out of reserved area\n");
			ret = ibtrs_post_recv(con, iu);
			if (unlikely(ret != 0))
				ibtrs_err(sess, "Processing I/O failed, "
					  "post receive buffer failed, "
					  "err: %d\n", ret);
			csm_schedule_event(con, CSM_EV_CON_ERROR);
			return;
		}

		hdr = (struct ibtrs_msg_hdr *)
			(sess->rcv_buf_pool->rcv_bufs[msg_id].buf + off);

		ibtrs_handle_write(con, iu, hdr, msg_id, off);
		break;
	default:
		ibtrs_wrn(sess, "Unexpected WC type: %s\n",
			  ib_wc_opcode_str(wc->opcode));
		return;
	}
}

static int accept(struct ibtrs_srv_con *con)
{
	struct ibtrs_srv_sess *sess = con->sess;
	struct rdma_conn_param conn_param;
	int ret;

	memset(&conn_param, 0, sizeof(conn_param));
	conn_param.retry_count = retry_count;

	if (con->user)
		conn_param.rnr_retry_count = 7;

	ret = rdma_accept(con->cm_id, &conn_param);
	if (ret) {
		ibtrs_err(sess, "Accepting RDMA connection request failed,"
			  " err: %d\n", ret);
		return ret;
	}

	return 0;
}

static struct ibtrs_srv_sess *
__create_sess(struct ibtrs_srv_ctx *ctx, struct rdma_cm_id *cm_id,
	      const struct ibtrs_msg_sess_open *req)
{
	struct ibtrs_srv_sess *sess;
	int err;

	sess = kzalloc(sizeof(*sess), GFP_KERNEL);
	if (unlikely(!sess)) {
		err = -ENOMEM;
		goto out;
	}
	sess->ctx = ctx;
	sess->s.addr.sockaddr = cm_id->route.addr.dst_addr;
	sess->est_cnt = 0;
	sess->state_in_sysfs = false;
	sess->cur_cq_vector = -1;
	INIT_LIST_HEAD(&sess->con_list);
	mutex_init(&sess->lock);

	sess->wq_size		= cm_id->device->attrs.max_qp_wr - 1;
	sess->queue_depth	= sess_queue_depth;
	sess->con_cnt		= req->con_cnt;

	ibtrs_heartbeat_init(&sess->heartbeat,
			     default_heartbeat_timeout_ms <
			     MIN_HEARTBEAT_TIMEOUT_MS ?
			     MIN_HEARTBEAT_TIMEOUT_MS :
			     default_heartbeat_timeout_ms);

	sess->s.ib_dev = ibtrs_ib_dev_find_get(cm_id);
	if (unlikely(!sess->s.ib_dev)) {
		err = -ENOMEM;
		ibtrs_wrn(sess, "Failed to alloc ibtrs_ib_dev\n");
		goto err1;
	}
	err = setup_cont_bufs(sess);
	if (unlikely(err))
		goto err2;

	memcpy(sess->s.uuid.b, req->uuid, sizeof(sess->s.uuid));
	err = ssm_init(sess);
	if (unlikely(err)) {
		ibtrs_wrn(sess, "Failed to initialize the session state machine\n");
		goto err3;
	}

	kref_init(&sess->kref);
	init_waitqueue_head(&sess->bufs_wait);

	list_add(&sess->ctx_list, &ctx->sess_list);
	ibtrs_info(sess, "IBTRS Session created (queue depth: %d)\n",
		   sess->queue_depth);

	return sess;

err3:
	release_cont_bufs(sess);
err2:
	ibtrs_ib_dev_put(sess->s.ib_dev);
err1:
	kfree(sess);
out:
	return ERR_PTR(err);
}

const char *ibtrs_srv_get_sess_hostname(struct ibtrs_srv_sess *sess)
{
	return sess->s.addr.hostname;
}
EXPORT_SYMBOL(ibtrs_srv_get_sess_hostname);

const struct sockaddr_storage *
ibtrs_srv_get_sess_sockaddr(struct ibtrs_srv_sess *sess)
{
	return &sess->s.addr.sockaddr;
}
EXPORT_SYMBOL(ibtrs_srv_get_sess_sockaddr);

int ibtrs_srv_get_sess_qdepth(struct ibtrs_srv_sess *sess)
{
	return sess->queue_depth;
}
EXPORT_SYMBOL(ibtrs_srv_get_sess_qdepth);

static struct ibtrs_srv_sess *
__find_sess(struct ibtrs_srv_ctx *ctx, const char *uuid)
{
	struct ibtrs_srv_sess *sess;

	list_for_each_entry(sess, &ctx->sess_list, ctx_list) {
		if (!memcmp(sess->s.uuid.b, uuid, sizeof(sess->s.uuid.b)) &&
		    sess->state != SSM_STATE_CLOSING &&
		    sess->state != SSM_STATE_CLOSED)
			return sess;
	}

	return NULL;
}

static int rdma_con_reject(struct rdma_cm_id *cm_id, s16 errno)
{
	struct ibtrs_msg_error msg;
	int ret;

	memset(&msg, 0, sizeof(msg));
	msg.hdr.type	= IBTRS_MSG_ERROR;
	msg.hdr.tsize	= sizeof(msg);
	msg.errno	= errno;

	ret = rdma_reject(cm_id, &msg, sizeof(msg));
	if (ret)
		pr_err("Rejecting RDMA connection request failed, err: %d\n",
		       ret);

	return ret;
}

static int find_next_bit_ring(int cur)
{
	int v = cpumask_next(cur, &cq_affinity_mask);

	if (v >= nr_cpu_ids)
		v = cpumask_first(&cq_affinity_mask);
	return v;
}

static int ibtrs_srv_get_next_cq_vector(struct ibtrs_srv_sess *sess)
{
	sess->cur_cq_vector = find_next_bit_ring(sess->cur_cq_vector);

	return sess->cur_cq_vector;
}

static void ssm_create_con_worker(struct work_struct *work)
{
	struct ssm_create_con_work *ssm_w;
	struct ibtrs_srv_sess *sess;
	u16 cq_size, wr_queue_size;
	struct ibtrs_srv_con *con;
	struct rdma_cm_id *cm_id;
	int cq_vector, ret;
	bool user;

	ssm_w = container_of(work, struct ssm_create_con_work, work);
	sess = ssm_w->sess;
	cm_id = ssm_w->cm_id;
	user = ssm_w->user;
	kfree(ssm_w);

	if (sess->state == SSM_STATE_CLOSING ||
	    sess->state == SSM_STATE_CLOSED) {
		ibtrs_wrn(sess, "Creating connection failed, "
			  "session is being closed\n");
		ret = -ECOMM;
		goto err_reject;
	}

	con = kzalloc(sizeof(*con), GFP_KERNEL);
	if (!con) {
		ibtrs_err(sess, "Creating connection failed, "
			  "can't allocate memory for connection\n");
		ret = -ENOMEM;
		goto err_reject;
	}

	con->cm_id			= cm_id;
	con->sess			= sess;
	con->user			= user;
	con->device_being_removed	= false;

	atomic_set(&con->wr_cnt, 0);
	if (con->user) {
		cq_size		= USR_CON_BUF_SIZE + 1;
		wr_queue_size	= USR_CON_BUF_SIZE + 1;
	} else {
		cq_size		= con->sess->queue_depth;
		wr_queue_size	= sess->wq_size;
	}

	cq_vector = ibtrs_srv_get_next_cq_vector(sess);

	/* TODO: SOFTIRQ can be faster, but be careful with softirq context */
	ret = ibtrs_cq_qp_create(&sess->s, &con->ibtrs_con, con->cm_id,
				 1, cq_vector, cq_size, wr_queue_size,
				 con->sess->s.ib_dev, IB_POLL_WORKQUEUE);
	if (ret) {
		ibtrs_err(sess, "Failed to initialize IB connection, err: %d\n",
			  ret);
		goto err_init;
	}
	/* XXX soon beacon will die */
	con->ibtrs_con.beacon_cqe.done = ibtrs_srv_rdma_done;

	con->rdma_resp_wq = alloc_workqueue("%s", 0, WQ_HIGHPRI,
					    "ibtrs_rdma_resp");

	if (!con->rdma_resp_wq) {
		ibtrs_err(sess, "Creating connection failed, can't allocate"
			  " work queue for send response, err: %d\n", ret);
		goto err_wq;
	}

	ret = init_transfer_bufs(con);
	if (ret) {
		ibtrs_err(sess, "Creating connection failed, can't init"
			  " transfer buffers, err: %d\n", ret);
		goto err_buf;
	}

	csm_init(con);
	add_con_to_list(sess, con);

	cm_id->context = con;
	ret = accept(con);
	if (ret)
		goto err_accept;

	con->sess->active_cnt++;

	return;

err_accept:
	cm_id->context = NULL;
	remove_con_from_list(con);
err_buf:
	destroy_workqueue(con->rdma_resp_wq);
err_wq:
	ibtrs_cq_qp_destroy(&con->ibtrs_con);
err_init:
	kfree(con);
err_reject:
	rdma_destroy_id(cm_id);

	ssm_schedule_event(sess, SSM_EV_CON_EST_ERR);
}

static int ssm_schedule_create_con(struct ibtrs_srv_sess *sess,
				   struct rdma_cm_id *cm_id,
				   bool user)
{
	struct ssm_create_con_work *w;

	w = kmalloc(sizeof(*w), GFP_KERNEL | __GFP_REPEAT);
	if (!w)
		return -ENOMEM;

	w->sess		= sess;
	w->cm_id	= cm_id;
	w->user		= user;
	INIT_WORK(&w->work, ssm_create_con_worker);
	queue_work(sess->sm_wq, &w->work);

	return 0;
}

static int rdma_con_establish(struct rdma_cm_id *cm_id,
			      const struct ibtrs_msg_hdr *hdr,
			      size_t size)
{
	struct ibtrs_srv_ctx *ctx = cm_id->context;
	struct ibtrs_srv_sess *sess;
	const char *uuid = NULL;
	bool user = false;
	int ret;

	if (unlikely((size < sizeof(struct ibtrs_msg_con_open)) ||
		     (size < sizeof(struct ibtrs_msg_sess_open)) ||
		     ibtrs_validate_message(hdr))) {
		pr_err("Establishing connection failed, "
		       "connection request payload size unexpected "
		       "%zu != %lu or %lu\n", size,
		       sizeof(struct ibtrs_msg_con_open),
		       sizeof(struct ibtrs_msg_sess_open));
		ret = -EINVAL;
		goto err_reject;
	}

	if (hdr->type == IBTRS_MSG_SESS_OPEN)
		uuid = ((struct ibtrs_msg_sess_open *)hdr)->uuid;
	else if (hdr->type == IBTRS_MSG_CON_OPEN)
		uuid = ((struct ibtrs_msg_con_open *)hdr)->uuid;

	mutex_lock(&ctx->sess_mutex);
	sess = __find_sess(ctx, uuid);
	if (sess) {
		if (unlikely(hdr->type == IBTRS_MSG_SESS_OPEN)) {
			ibtrs_info(sess, "Connection request rejected, "
				   "session already exists\n");
			mutex_unlock(&ctx->sess_mutex);
			ret = -EEXIST;
			goto err_reject;
		}
		if (!ibtrs_srv_sess_get(sess)) {
			ibtrs_info(sess, "Connection request rejected,"
				   " session is being closed\n");
			mutex_unlock(&ctx->sess_mutex);
			ret = -EINVAL;
			goto err_reject;
		}
	} else {
		if (unlikely(hdr->type == IBTRS_MSG_CON_OPEN)) {
			mutex_unlock(&ctx->sess_mutex);
			pr_info("Connection request rejected,"
				" received con_open msg but no active session"
				" exists.\n");
			ret = -EINVAL;
			goto err_reject;
		}

		sess = __create_sess(ctx, cm_id,
				     (const struct ibtrs_msg_sess_open *)hdr);
		if (IS_ERR(sess)) {
			mutex_unlock(&ctx->sess_mutex);
			ret = PTR_ERR(sess);
			pr_err("Establishing connection failed, "
			       "creating local session resource failed, err:"
			       " %d\n", ret);
			goto err_reject;
		}
		ibtrs_srv_sess_get(sess);
		user = true;
	}

	mutex_unlock(&ctx->sess_mutex);

	ret = ssm_schedule_create_con(sess, cm_id, user);
	if (ret) {
		ibtrs_err(sess, "Unable to schedule creation of connection,"
			  " session will be closed.\n");
		goto err_close;
	}

	ibtrs_srv_sess_put(sess);
	return 0;

err_close:
	ssm_schedule_event(sess, SSM_EV_CON_EST_ERR);
	ibtrs_srv_sess_put(sess);
err_reject:
	rdma_con_reject(cm_id, ret);
	return ret;
}

/*XXX: REMOVE ASAP */
 __maybe_unused
static int ibtrs_srv_rdma_cm_ev_handler(struct rdma_cm_id *cm_id,
					struct rdma_cm_event *event)
{
	struct ibtrs_srv_con *con = NULL;
	int ret = 0;

	pr_debug("cma_event type %d cma_id %p(%s) on con: %p\n", event->event,
		 cm_id, rdma_event_msg(event->event), con);

	if (cm_id->qp) {
		struct ibtrs_con *ibtrs_con = cm_id->qp->qp_context;

		con = container_of(ibtrs_con, struct ibtrs_srv_con, ibtrs_con);
	}
	if (!con && event->event != RDMA_CM_EVENT_CONNECT_REQUEST) {
		pr_info("Ignore cma_event type %d cma_id %p(%s)\n",
			event->event, cm_id, rdma_event_msg(event->event));
		/* XXX: FIXME: WTF? */
		return 0;
	}

	switch (event->event) {
	case RDMA_CM_EVENT_CONNECT_REQUEST:
		ret = rdma_con_establish(cm_id, event->param.conn.private_data,
					 event->param.conn.private_data_len);
		break;
	case RDMA_CM_EVENT_ESTABLISHED:
		csm_schedule_event(con, CSM_EV_CON_ESTABLISHED);
		break;
	case RDMA_CM_EVENT_DISCONNECTED:
	case RDMA_CM_EVENT_TIMEWAIT_EXIT:
		csm_schedule_event(con, CSM_EV_CON_DISCONNECTED);
		break;

	case RDMA_CM_EVENT_DEVICE_REMOVAL: {
		struct completion dc;

		ibtrs_err_rl(con->sess,
			     "IB Device was removed, disconnecting session.\n");

		con->device_being_removed = true;
		init_completion(&dc);
		con->sess->s.ib_dev->ib_dev_destroy_completion = &dc;

		csm_schedule_event(con, CSM_EV_DEVICE_REMOVAL);
		wait_for_completion(&dc);

		/* If it's user connection, the cm_id will be destroyed by
		 * destroy_sess(), so return 0 to signal that we will destroy
		 * it later. Otherwise, return 1 so CMA will destroy it.
		 */
		if (con->user)
			return 0;
		else
			return 1;
	}
	case RDMA_CM_EVENT_CONNECT_ERROR:
	case RDMA_CM_EVENT_ROUTE_ERROR:
	case RDMA_CM_EVENT_UNREACHABLE:
	case RDMA_CM_EVENT_ADDR_CHANGE:
		ibtrs_err_rl(con->sess, "CM error (CM event: %s, err: %d)\n",
			     rdma_event_msg(event->event), event->status);

		csm_schedule_event(con, CSM_EV_CON_ERROR);
		break;
	case RDMA_CM_EVENT_REJECTED:
		/* reject status is defined in enum, not errno */
		ibtrs_err_rl(con->sess,
			     "Connection rejected (CM event: %s, err: %s)\n",
			     rdma_event_msg(event->event),
			     rdma_reject_msg(cm_id, event->status));
		csm_schedule_event(con, CSM_EV_CON_ERROR);
		break;
	default:
		ibtrs_wrn(con->sess, "Ignoring unexpected CM event %s, err %d\n",
			  rdma_event_msg(event->event), event->status);
		break;
	}
	return ret;
}

static void ibtrs_srv_close_work(struct work_struct *work)
{
	struct ibtrs_srv_sess *sess;
	struct ibtrs_srv_ctx *ctx;
	struct ibtrs_srv_con *con;
	int i;

	sess = container_of(work, typeof(*sess), close_work);
	ctx = sess->ctx;

	ctx->ops.sess_ev(sess, IBTRS_SRV_SESS_EV_DISCONNECTED, sess->priv);

	ibtrs_srv_change_state_NEW(sess, IBTRS_SRV_CLOSED);
	ibtrs_srv_destroy_sess_files(sess);

	mutex_lock(&ctx->sess_mutex);
	list_del(&sess->ctx_list);
	mutex_unlock(&ctx->sess_mutex);

	/* XXX cancel_delayed_work(&sess->send_heartbeat_dwork);
	   cancel_delayed_work(&sess->check_heartbeat_dwork); */

	for (i = 0; i < sess->con_cnt; i++) {
		con = sess->con[i];
		if (!con)
			continue;

		rdma_disconnect(con->ibtrs_con.cm_id);
		ib_drain_qp(con->ibtrs_con.qp);
		destroy_workqueue(con->rdma_resp_wq);
		ibtrs_cq_qp_destroy(&con->ibtrs_con);
		rdma_destroy_id(con->ibtrs_con.cm_id);
		kfree(con);
	}
	destroy_workqueue(sess->sm_wq);
	release_cont_bufs(sess);
	free_sess_bufs(sess);
	ibtrs_ib_dev_put(sess->s.ib_dev);
	kfree(sess->con);
	kfree(sess);
}

static int ibtrs_rdma_do_accept(struct ibtrs_srv_sess *sess,
				struct rdma_cm_id *cm_id)
{
	struct ibtrs_msg_conn_rsp msg;
	struct rdma_conn_param param;
	int err;

	memset(&param, 0, sizeof(param));
	param.retry_count = retry_count;
	param.rnr_retry_count = 7;
	param.private_data = &msg;
	param.private_data_len = sizeof(msg);

	memset(&msg, 0, sizeof(msg));
	msg.magic = cpu_to_le16(IBTRS_MAGIC);
	msg.version = cpu_to_le16(IBTRS_CURRENT_VER);
	msg.errno = 0;
	msg.queue_depth = cpu_to_le16(sess->queue_depth);
	msg.rkey = cpu_to_le32(sess->s.ib_dev->pd->unsafe_global_rkey);
	msg.max_io_size = cpu_to_le32(max_io_size);
	msg.max_req_size = cpu_to_le32(MAX_REQ_SIZE);
	memcpy(&msg.uuid, sess->s.uuid.b, sizeof(msg.uuid));

	err = rdma_accept(cm_id, &param);
	if (err)
		pr_err("rdma_accept(), err: %d\n", err);

	return err;
}

static int ibtrs_rdma_do_reject(struct rdma_cm_id *cm_id, int errno)
{
	struct ibtrs_msg_conn_rsp msg;
	int err;

	memset(&msg, 0, sizeof(msg));
	msg.magic = cpu_to_le16(IBTRS_MAGIC);
	msg.version = cpu_to_le16(IBTRS_CURRENT_VER);
	msg.errno = cpu_to_le16(errno);

	err = rdma_reject(cm_id, &msg, sizeof(msg));
	if (err)
		pr_err("rdma_reject(), err: %d\n", err);

	return err;
}

static struct ibtrs_srv_sess *
__find_sess_NEW(struct ibtrs_srv_ctx *ctx, const char *uuid)
{
	struct ibtrs_srv_sess *sess;

	list_for_each_entry(sess, &ctx->sess_list, ctx_list) {
		if (!memcmp(&sess->s.uuid, uuid, sizeof(sess->s.uuid)))
			return sess;
	}

	return NULL;
}

static int create_con_NEW(struct ibtrs_srv_sess *sess,
		      struct rdma_cm_id *cm_id,
		      unsigned cid)
{
	u16 cq_size, wr_queue_size;
	struct ibtrs_srv_con *con;
	int cq_vector, err;

	con = kzalloc(sizeof(*con), GFP_KERNEL);
	if (unlikely(!con)) {
		ibtrs_err(sess, "kzalloc() failed\n");
		err = -ENOMEM;
		goto err;
	}

	con->cm_id = cm_id;
	con->sess = sess;
	con->cid = cid;
	atomic_set(&con->wr_cnt, 0);

	if (con->cid == 0) {
		cq_size       = USR_CON_BUF_SIZE + 1;
		wr_queue_size = USR_CON_BUF_SIZE + 1;
	} else {
		cq_size       = con->sess->queue_depth;
		wr_queue_size = sess->wq_size;
	}

	cq_vector = ibtrs_srv_get_next_cq_vector(sess);

	/* TODO: SOFTIRQ can be faster, but be careful with softirq context */
	err = ibtrs_cq_qp_create(&sess->s, &con->ibtrs_con, con->cm_id,
				 1, cq_vector, cq_size, wr_queue_size,
				 con->sess->s.ib_dev, IB_POLL_WORKQUEUE);
	if (unlikely(err)) {
		ibtrs_err(sess, "ibtrs_cq_qp_create(), err: %d\n", err);
		goto free_con;
	}
	con->rdma_resp_wq = alloc_workqueue("ibtrs_rdma_resp", 0, WQ_HIGHPRI);
	if (unlikely(!con->rdma_resp_wq)) {
		ibtrs_err(sess, "alloc_workqueue() failed\n");
		goto free_cqqp;
	}
	err = post_recv(con);
	if (unlikely(err)) {
		ibtrs_err(sess, "post_recv(), err: %d\n", err);
		goto free_wq;
	}
	WARN_ON(sess->con[cid]);
	sess->con[cid] = con;

	return 0;

free_wq:
	destroy_workqueue(con->rdma_resp_wq);
free_cqqp:
	ibtrs_cq_qp_destroy(&con->ibtrs_con);
free_con:
	kfree(con);

err:
	return err;
}

static struct ibtrs_srv_sess *__alloc_sess_NEW(struct ibtrs_srv_ctx *ctx,
					   struct rdma_cm_id *cm_id,
					   unsigned con_cnt, const char *uuid)
{
	struct ibtrs_srv_sess *sess;
	int err = -ENOMEM;

	sess = kzalloc(sizeof(*sess), GFP_KERNEL);
	if (unlikely(!sess))
		goto err;

	sess->con = kcalloc(con_cnt, sizeof(*sess->con), GFP_KERNEL);
	if (unlikely(!sess->con))
		goto err_free_sess;

	sess->state_NEW = IBTRS_SRV_ALIVE;
	sess->ctx = ctx;
	sess->con_cnt = con_cnt;
	sess->cur_cq_vector = -1;
	sess->queue_depth = sess_queue_depth;
	sess->wq_size = cm_id->device->attrs.max_qp_wr - 1;
	sess->s.addr.sockaddr = cm_id->route.addr.dst_addr;

	memcpy(&sess->s.uuid, uuid, sizeof(sess->s.uuid));
	init_waitqueue_head(&sess->bufs_wait);
	spin_lock_init(&sess->state_lock);

	/*XXX
	ibtrs_heartbeat_init(&sess->heartbeat,
			     default_heartbeat_timeout_ms <
			     MIN_HEARTBEAT_TIMEOUT_MS ?
			     MIN_HEARTBEAT_TIMEOUT_MS :
			     default_heartbeat_timeout_ms);

	INIT_DELAYED_WORK(&sess->check_heartbeat_dwork, check_heartbeat_work);
	INIT_DELAYED_WORK(&sess->send_heartbeat_dwork, send_heartbeat_work);
	*/
	INIT_WORK(&sess->close_work, ibtrs_srv_close_work);

	sess->s.ib_dev = ibtrs_ib_dev_find_get(cm_id);
	if (unlikely(!sess->s.ib_dev)) {
		err = -ENOMEM;
		ibtrs_wrn(sess, "Failed to alloc ibtrs_device\n");
		goto err_free_con;
	}
	err = setup_cont_bufs(sess);
	if (unlikely(err))
		goto err_put_dev;

	err = alloc_sess_bufs(sess);
	if (unlikely(err))
		goto err_release_bufs;

	list_add(&sess->ctx_list, &ctx->sess_list);

	return sess;

err_release_bufs:
	release_cont_bufs(sess);
err_put_dev:
	ibtrs_ib_dev_put(sess->s.ib_dev);
err_free_con:
	kfree(sess->con);
err_free_sess:
	kfree(sess);

err:
	return ERR_PTR(err);
}

static int ibtrs_rdma_connect_NEW(struct rdma_cm_id *cm_id,
			      const struct ibtrs_msg_conn_req *msg,
			      size_t len)
{
	struct ibtrs_srv_ctx *ctx = cm_id->context;
	struct ibtrs_srv_sess *sess;
	u16 version, con_cnt, cid;
	int err;

	if (unlikely(len < sizeof(*msg))) {
		pr_err("Invalid IBTRS connection request");
		goto reject_w_econnreset;
	}
	if (unlikely(le16_to_cpu(msg->magic) != IBTRS_MAGIC)) {
		pr_err("Invalid IBTRS magic");
		goto reject_w_econnreset;
	}
	version = le16_to_cpu(msg->version);
	if (unlikely(version >> 8 != IBTRS_CURRENT_VER >> 8)) {
		pr_err("Unsupported major IBTRS version: %d", version);
		goto reject_w_econnreset;
	}
	con_cnt = le16_to_cpu(msg->cid_num);
	if (unlikely(con_cnt > 4096)) {
		/* Sanity check */
		pr_err("Too many connections requested: %d\n", con_cnt);
		goto reject_w_econnreset;
	}
	cid = le16_to_cpu(msg->cid_num);
	if (unlikely(cid >= con_cnt)) {
		/* Sanity check */
		pr_err("Incorrect cid: %d >= %d\n", cid, con_cnt);
		goto reject_w_econnreset;
	}
	mutex_lock(&ctx->sess_mutex);
	sess = __find_sess_NEW(ctx, msg->uuid);
	if (sess) {
		if (unlikely(sess->state_NEW != IBTRS_SRV_ALIVE)) {
			ibtrs_err(sess, "Session in wrong state: %s\n",
				  ibtrs_srv_state_str(sess->state_NEW));
			mutex_unlock(&ctx->sess_mutex);
			goto reject_w_econnreset;
		}
		/*
		 * Sanity checks
		 */
		if (unlikely(con_cnt != sess->con_cnt ||
			     cid >= sess->con_cnt)) {
			ibtrs_err(sess, "Incorrect request: %d, %d\n",
				  cid, con_cnt);
			mutex_unlock(&ctx->sess_mutex);
			goto reject_w_econnreset;
		}
		if (unlikely(sess->con[cid])) {
			ibtrs_err(sess, "Connection already exists: %d\n",
				  cid);
			mutex_unlock(&ctx->sess_mutex);
			goto reject_w_econnreset;
		}
	} else {
		sess = __alloc_sess_NEW(ctx, cm_id, con_cnt, msg->uuid);
		if (unlikely(IS_ERR(sess))) {
			mutex_unlock(&ctx->sess_mutex);
			err = PTR_ERR(sess);
			goto reject_w_err;
		}
	}
	err = create_con_NEW(sess, cm_id, cid);
	if (unlikely(err))
		goto close_and_reject_w_err;
	err = ibtrs_rdma_do_accept(sess, cm_id);
	if (unlikely(err))
		goto close_and_reject_w_err;
	mutex_unlock(&ctx->sess_mutex);

	return 0;

reject_w_err:
	return ibtrs_rdma_do_reject(cm_id, err);

reject_w_econnreset:
	return ibtrs_rdma_do_reject(cm_id, -ECONNRESET);

close_and_reject_w_err:
	close_sess_NEW(sess);
	mutex_unlock(&ctx->sess_mutex);
	goto reject_w_err;
}

static void ibtrs_rdma_disconnect_NEW(struct ibtrs_srv_con *con)
{
	struct ibtrs_srv_sess *sess = con->sess;

	close_sess_NEW(sess);
}

static void ibtrs_rdma_conn_error_NEW(struct ibtrs_srv_con *con)
{
	struct ibtrs_srv_sess *sess = con->sess;

	close_sess_NEW(sess);
}

static void ibtrs_rdma_device_removal_NEW(struct ibtrs_srv_con *con)
{
	struct ibtrs_srv_sess *sess = con->sess;

	close_sess_NEW(sess);
}

static int ibtrs_srv_rdma_cm_handler_NEW(struct rdma_cm_id *cm_id,
				     struct rdma_cm_event *event)
{
	struct ibtrs_srv_con *con = NULL;
	int err = 0;

	if (cm_id->qp) {
		struct ibtrs_con *ibtrs_con = cm_id->qp->qp_context;

		con = container_of(ibtrs_con, struct ibtrs_srv_con, ibtrs_con);
	}

	switch (event->event) {
	case RDMA_CM_EVENT_CONNECT_REQUEST:
		err = ibtrs_rdma_connect_NEW(cm_id, event->param.conn.private_data,
					 event->param.conn.private_data_len);
		break;
	case RDMA_CM_EVENT_ESTABLISHED:
		/* Nothing here */
		break;
	case RDMA_CM_EVENT_REJECTED:
	case RDMA_CM_EVENT_CONNECT_ERROR:
	case RDMA_CM_EVENT_UNREACHABLE:
		ibtrs_err(con->sess, "CM error (CM event: %s, err: %d)\n",
			  rdma_event_msg(event->event), event->status);
		ibtrs_rdma_conn_error_NEW(con);
		break;
	case RDMA_CM_EVENT_DISCONNECTED:
	case RDMA_CM_EVENT_ADDR_CHANGE:
	case RDMA_CM_EVENT_TIMEWAIT_EXIT:
		ibtrs_rdma_disconnect_NEW(con);
		break;
	case RDMA_CM_EVENT_DEVICE_REMOVAL:
		ibtrs_rdma_device_removal_NEW(con);
		break;
	default:
		ibtrs_wrn(con->sess, "Ignoring unexpected CM event %s, err %d\n",
			  rdma_event_msg(event->event), event->status);
		break;
	}

	return err;
}

static struct rdma_cm_id *ibtrs_srv_cm_init(struct ibtrs_srv_ctx *ctx,
					    struct sockaddr *addr,
					    enum rdma_port_space ps)
{
	struct rdma_cm_id *cm_id;
	int ret;

	cm_id = rdma_create_id(&init_net, ibtrs_srv_rdma_cm_handler_NEW,
			       ctx, ps, IB_QPT_RC);
	if (IS_ERR(cm_id)) {
		ret = PTR_ERR(cm_id);
		pr_err("Creating id for RDMA connection failed, err: %d\n",
		       ret);
		goto err_out;
	}
	ret = rdma_bind_addr(cm_id, addr);
	if (ret) {
		pr_err("Binding RDMA address failed, err: %d\n", ret);
		goto err_cm;
	}
	ret = rdma_listen(cm_id, 64);
	if (ret) {
		pr_err("Listening on RDMA connection failed, err: %d\n",
		       ret);
		goto err_cm;
	}

	switch (addr->sa_family) {
	case AF_INET:
		pr_debug("listening on port %u\n",
			 ntohs(((struct sockaddr_in *)addr)->sin_port));
		break;
	case AF_INET6:
		pr_debug("listening on port %u\n",
			 ntohs(((struct sockaddr_in6 *)addr)->sin6_port));
		break;
	case AF_IB:
		pr_debug("listening on service id 0x%016llx\n",
			 be64_to_cpu(rdma_get_service_id(cm_id, addr)));
		break;
	default:
		pr_debug("listening on address family %u\n", addr->sa_family);
	}

	return cm_id;

err_cm:
	rdma_destroy_id(cm_id);
err_out:

	return ERR_PTR(ret);
}

static int ibtrs_srv_rdma_init(struct ibtrs_srv_ctx *ctx, unsigned port)
{
	struct sockaddr_in6 sin = {
		.sin6_family	= AF_INET6,
		.sin6_addr	= IN6ADDR_ANY_INIT,
		.sin6_port	= htons(port),
	};
	struct sockaddr_ib sib = {
		.sib_family			= AF_IB,
		.sib_addr.sib_subnet_prefix	= 0ULL,
		.sib_addr.sib_interface_id	= 0ULL,
		.sib_sid	= cpu_to_be64(RDMA_IB_IP_PS_IB | port),
		.sib_sid_mask	= cpu_to_be64(0xffffffffffffffffULL),
		.sib_pkey	= cpu_to_be16(0xffff),
	};
	struct rdma_cm_id *cm_ip, *cm_ib;
	int ret = 0;

	/*
	 * We accept both IPoIB and IB connections, so we need to keep
	 * two cm id's, one for each socket type and port space.
	 * If the cm initialization of one of the id's fails, we abort
	 * everything.
	 */

	cm_ip = ibtrs_srv_cm_init(ctx, (struct sockaddr *)&sin, RDMA_PS_TCP);
	if (unlikely((IS_ERR(cm_ip))))
	    return PTR_ERR(cm_ip);

	cm_ib = ibtrs_srv_cm_init(ctx, (struct sockaddr *)&sib, RDMA_PS_IB);
	if (unlikely((IS_ERR(cm_ib))))
		goto free_cm_ip;

	ctx->cm_id_ip = cm_ip;
	ctx->cm_id_ib = cm_ib;

	return ret;

free_cm_ip:
	rdma_destroy_id(cm_ip);

	return ret;
}

static struct ibtrs_srv_ctx *alloc_srv_ctx(const struct ibtrs_srv_ops *ops)
{
	struct ibtrs_srv_ctx *ctx;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return NULL;

	ctx->ops = *ops;
	mutex_init(&ctx->sess_mutex);
	INIT_LIST_HEAD(&ctx->sess_list);
	init_waitqueue_head(&ctx->sess_list_waitq);

	return ctx;
}

static void free_srv_ctx(struct ibtrs_srv_ctx *ctx)
{
	WARN_ON(!list_empty(&ctx->sess_list));
	kfree(ctx);
}

struct ibtrs_srv_ctx *ibtrs_srv_open(const struct ibtrs_srv_ops *ops,
				     unsigned int port)
{
	struct ibtrs_srv_ctx *ctx;
	int err;

	if (unlikely(!srv_ops_are_valid(ops))) {
		pr_err("Registration failed, user module supploed invalid ops"
		       " parameter\n");
		return ERR_PTR(-EINVAL);
	}
	ctx = alloc_srv_ctx(ops);
	if (unlikely(!ctx))
		return ERR_PTR(-ENOMEM);

	err = ibtrs_srv_rdma_init(ctx, port);
	if (err) {
		free_srv_ctx(ctx);
		pr_err("Can't init RDMA resource, err: %d\n", err);
		return ERR_PTR(err);
	}

	return ctx;
}
EXPORT_SYMBOL(ibtrs_srv_open);

void ibtrs_srv_queue_close(struct ibtrs_srv_sess *sess)
{
	close_sess_NEW(sess);
}

static void close_sessions(struct ibtrs_srv_ctx *ctx)
{
	struct ibtrs_srv_sess *sess;

	mutex_lock(&ctx->sess_mutex);
	list_for_each_entry(sess, &ctx->sess_list, ctx_list) {
		if (!ibtrs_srv_sess_get(sess))
			continue;
		ssm_schedule_event(sess, SSM_EV_SESS_CLOSE);
		ibtrs_srv_sess_put(sess);
	}
	mutex_unlock(&ctx->sess_mutex);

	wait_event(ctx->sess_list_waitq, list_empty(&ctx->sess_list));
}

void ibtrs_srv_close(struct ibtrs_srv_ctx *ctx)
{
	rdma_destroy_id(ctx->cm_id_ip);
	rdma_destroy_id(ctx->cm_id_ib);
	close_sessions(ctx);
	flush_workqueue(ibtrs_wq);
	free_srv_ctx(ctx);
}
EXPORT_SYMBOL(ibtrs_srv_close);

static void close_sess_NEW(struct ibtrs_srv_sess *sess)
{
	if (ibtrs_srv_change_state_NEW(sess, IBTRS_SRV_CLOSING))
		queue_work(ibtrs_wq, &sess->close_work);
	WARN_ON(sess->state_NEW != IBTRS_SRV_CLOSING);
}

static void close_sessions_NEW(struct ibtrs_srv_ctx *ctx)
{
	struct ibtrs_srv_sess *sess;

	mutex_lock(&ctx->sess_mutex);
	list_for_each_entry(sess, &ctx->sess_list, ctx_list)
		close_sess_NEW(sess);
	mutex_unlock(&ctx->sess_mutex);
	flush_workqueue(ibtrs_wq);
}

void ibtrs_srv_close_NEW(struct ibtrs_srv_ctx *ctx)
{
	rdma_destroy_id(ctx->cm_id_ip);
	rdma_destroy_id(ctx->cm_id_ib);
	close_sessions_NEW(ctx);
	free_srv_ctx(ctx);
}
EXPORT_SYMBOL(ibtrs_srv_close_NEW);

static int check_module_params(void)
{
	if (sess_queue_depth < 1 || sess_queue_depth > MAX_SESS_QUEUE_DEPTH) {
		pr_err("Invalid sess_queue_depth parameter value\n");
		return -EINVAL;
	}

	/* check if IB immediate data size is enough to hold the mem_id and the
	 * offset inside the memory chunk
	 */
	if (ilog2(sess_queue_depth - 1) + ilog2(rcv_buf_size - 1) >
	    IB_IMM_SIZE_BITS) {
		pr_err("RDMA immediate size (%db) not enough to encode "
		       "%d buffers of size %dB. Reduce 'sess_queue_depth' "
		       "or 'max_io_size' parameters.\n", IB_IMM_SIZE_BITS,
		       sess_queue_depth, rcv_buf_size);
		return -EINVAL;
	}

	if (init_pool_size < 0) {
		pr_err("Invalid 'init_pool_size' parameter value."
		       " Value must be positive.\n");
		return -EINVAL;
	}

	if (pool_size_hi_wm < init_pool_size) {
		pr_err("Invalid 'pool_size_hi_wm' parameter value. Value must"
		       " be iqual or higher than 'init_pool_size'.\n");
		return -EINVAL;
	}

	return 0;
}

static void csm_init(struct ibtrs_srv_con *con)
{
	pr_debug("initializing csm to %s\n", csm_state_str(CSM_STATE_REQUESTED));
	csm_set_state(con, CSM_STATE_REQUESTED);
}

static int send_msg_sess_open_resp(struct ibtrs_srv_con *con)
{
	struct ibtrs_msg_sess_open_resp *msg;
	int err;
	struct ibtrs_srv_sess *sess = con->sess;

	msg = sess->rdma_info_iu->buf;

	fill_ibtrs_msg_sess_open_resp(msg, con);

	err = ibtrs_post_send(con->ibtrs_con.qp, con->sess->s.ib_dev->mr,
			      sess->rdma_info_iu, msg->hdr.tsize);
	if (unlikely(err))
		ibtrs_err(sess, "Sending sess open resp failed, "
			  "posting msg to QP failed, err: %d\n", err);

	return err;
}

static void queue_heartbeat_dwork(struct ibtrs_srv_sess *sess)
{
	ibtrs_heartbeat_set_recv_ts(&sess->heartbeat);
	WARN_ON(!queue_delayed_work(sess->sm_wq,
				    &sess->send_heartbeat_dwork,
				    HEARTBEAT_INTV_JIFFIES));
	WARN_ON(!queue_delayed_work(sess->sm_wq,
				    &sess->check_heartbeat_dwork,
				    HEARTBEAT_INTV_JIFFIES));
}

static void csm_requested(struct ibtrs_srv_con *con, enum csm_ev ev)
{
	struct ibtrs_srv_sess *sess = con->sess;
	enum csm_state state = con->state;

	pr_debug("con %p, event %s\n", con, csm_ev_str(ev));
	switch (ev) {
	case CSM_EV_CON_ESTABLISHED: {
		csm_set_state(con, CSM_STATE_CONNECTED);
		if (con->user) {
			/* send back rdma info */
			if (send_msg_sess_open_resp(con))
				goto destroy;
			queue_heartbeat_dwork(con->sess);
		}
		ssm_schedule_event(sess, SSM_EV_CON_CONNECTED);
		break;
	}
	case CSM_EV_DEVICE_REMOVAL:
	case CSM_EV_CON_ERROR:
	case CSM_EV_SESS_CLOSING:
	case CSM_EV_CON_DISCONNECTED:
destroy:
		csm_set_state(con, CSM_STATE_CLOSED);
		close_con(con);
		ssm_schedule_event(sess, SSM_EV_CON_EST_ERR);
		break;
	default:
		ibtrs_err(sess, "Connection received unexpected event %s "
			  "in %s state.\n", csm_ev_str(ev), csm_state_str(state));
	}
}

static void csm_connected(struct ibtrs_srv_con *con, enum csm_ev ev)
{
	struct ibtrs_srv_sess *sess = con->sess;
	enum csm_state state = con->state;

	pr_debug("con %p, event %s\n", con, csm_ev_str(ev));
	switch (ev) {
	case CSM_EV_CON_ERROR:
	case CSM_EV_SESS_CLOSING: {
		int err;

		csm_set_state(con, CSM_STATE_CLOSING);
		err = rdma_disconnect(con->cm_id);
		if (err)
			ibtrs_err(sess, "Connection received event %s "
				  "in %s state, new state is %s, but failed to "
				  "disconnect connection.\n", csm_ev_str(ev),
				  csm_state_str(state), csm_state_str(con->state));
		break;
	}
	case CSM_EV_DEVICE_REMOVAL:
		/* Send a SSM_EV_SESS_CLOSE event to the session to speed up the
		 * closing of the other connections. If we just wait for the
		 * client to close all connections this can take a while.
		 */
		ssm_schedule_event(sess, SSM_EV_SESS_CLOSE);
		/* fall-through */
	case CSM_EV_CON_DISCONNECTED: {
		int err;

		csm_set_state(con, CSM_STATE_FLUSHING);
		err = rdma_disconnect(con->cm_id);
		if (err)
			ibtrs_err(sess, "Connection received event %s "
				  "in %s state, new state is %s, but failed to "
				  "disconnect connection.\n", csm_ev_str(ev),
				  csm_state_str(state), csm_state_str(con->state));

		wait_event(sess->bufs_wait,
			   !atomic_read(&sess->stats.rdma_stats.inflight));
		pr_debug("posting beacon on con %p\n", con);
		err = ibtrs_post_beacon(&con->ibtrs_con);
		if (err) {
			ibtrs_err(sess, "Connection received event %s "
				  "in %s state, new state is %s but failed to post"
				  " beacon, closing connection.\n", csm_ev_str(ev),
				  csm_state_str(state), csm_state_str(con->state));
			goto destroy;
		}

		/* XXX: should die ASAP */
		err = ibtrs_request_cq_notifications(&con->ibtrs_con);
		if (unlikely(err < 0)) {
			ibtrs_wrn(con->sess, "Requesting CQ Notification for"
				  " ibtrs_con failed. Connection will be destroyed\n");
			goto destroy;
		}
		break;

destroy:
		csm_set_state(con, CSM_STATE_CLOSED);
		close_con(con);
		ssm_schedule_event(sess, SSM_EV_CON_DISCONNECTED);

		break;
	}
	default:
		ibtrs_err(sess, "Connection received unexpected event %s "
			  "in %s state\n", csm_ev_str(ev), csm_state_str(state));
	}
}

static void csm_closing(struct ibtrs_srv_con *con, enum csm_ev ev)
{
	struct ibtrs_srv_sess *sess = con->sess;
	enum csm_state state = con->state;

	pr_debug("con %p, event %s\n", con, csm_ev_str(ev));
	switch (ev) {
	case CSM_EV_DEVICE_REMOVAL:
	case CSM_EV_CON_DISCONNECTED: {
		int err;

		csm_set_state(con, CSM_STATE_FLUSHING);

		wait_event(sess->bufs_wait,
			   !atomic_read(&sess->stats.rdma_stats.inflight));

		pr_debug("posting beacon on con %p\n", con);
		if (ibtrs_post_beacon(&con->ibtrs_con)) {
			ibtrs_err(sess, "Connection received event %s "
				  "in %s state, new state is %s but failed to post"
				  " beacon, closing connection.\n", csm_ev_str(ev),
				  csm_state_str(state), csm_state_str(con->state));
			goto destroy;
		}

		/* XXX: should die ASAP */
		err = ibtrs_request_cq_notifications(&con->ibtrs_con);
		if (unlikely(err < 0)) {
			ibtrs_wrn(con->sess, "Requesting CQ Notification for"
				  " ibtrs_con failed. Connection will be destroyed\n");
			goto destroy;
		}
		break;

destroy:
		csm_set_state(con, CSM_STATE_CLOSED);
		close_con(con);
		ssm_schedule_event(sess, SSM_EV_CON_DISCONNECTED);
		break;
	}
	case CSM_EV_CON_ERROR:
		/* ignore connection errors, just wait for CM_DISCONNECTED */
	case CSM_EV_SESS_CLOSING:
		break;
	default:
		ibtrs_err(sess, "Connection received unexpected event %s "
			  "in %s state\n", csm_ev_str(ev), csm_state_str(state));
	}
}

static void csm_flushing(struct ibtrs_srv_con *con, enum csm_ev ev)
{
	struct ibtrs_srv_sess *sess = con->sess;
	enum csm_state state = con->state;

	pr_debug("con %p, event %s\n", con, csm_ev_str(ev));

	switch (ev) {
	case CSM_EV_BEACON_COMPLETED:
		csm_set_state(con, CSM_STATE_CLOSED);
		close_con(con);
		ssm_schedule_event(sess, SSM_EV_CON_DISCONNECTED);
		break;
	case CSM_EV_SESS_CLOSING:
	case CSM_EV_DEVICE_REMOVAL:
		/* Ignore CSM_EV_DEVICE_REMOVAL and CSM_EV_SESS_CLOSING in
		 * this state. The beacon was already posted, so the
		 * CSM_EV_BEACON_COMPLETED event should arrive anytime soon.
		 */
		break;
	case CSM_EV_CON_ERROR:
		break;
	case CSM_EV_CON_DISCONNECTED:
		/* Ignore CSM_EV_CON_DISCONNECTED. At this point we could have
		 * already received a CSM_EV_CON_DISCONNECTED for the same
		 * connection, but an additional RDMA_CM_EVENT_DISCONNECTED or
		 * RDMA_CM_EVENT_TIMEWAIT_EXIT could be generated.
		 */
		break;
	default:
		ibtrs_err(sess, "Connection received unexpected event %s "
			  "in %s state\n", csm_ev_str(ev), csm_state_str(state));
	}
}

static void csm_closed(struct ibtrs_srv_con *con, enum csm_ev ev)
{
	/* in this state, we ignore every event scheduled for this connection
	 * and just wait for the session workqueue to be flushed and the
	 * connection freed
	 */
	pr_debug("con %p, event %s\n", con, csm_ev_str(ev));
}

typedef void (ibtrs_srv_csm_ev_handler_fn)(struct ibtrs_srv_con *, enum csm_ev);

static ibtrs_srv_csm_ev_handler_fn *ibtrs_srv_csm_ev_handlers[] = {
	[CSM_STATE_REQUESTED]		= csm_requested,
	[CSM_STATE_CONNECTED]		= csm_connected,
	[CSM_STATE_CLOSING]		= csm_closing,
	[CSM_STATE_FLUSHING]		= csm_flushing,
	[CSM_STATE_CLOSED]		= csm_closed,
};

static inline void ibtrs_srv_csm_ev_handle(struct ibtrs_srv_con *con,
					   enum csm_ev ev)
{
	return (*ibtrs_srv_csm_ev_handlers[con->state])(con, ev);
}

static void csm_worker(struct work_struct *work)
{
	struct csm_work *csm_w = container_of(work, struct csm_work, work);

	ibtrs_srv_csm_ev_handle(csm_w->con, csm_w->ev);
	kfree(csm_w);
}

static void csm_schedule_event(struct ibtrs_srv_con *con, enum csm_ev ev)
{
	struct csm_work *w;

	if (!ibtrs_srv_sess_get(con->sess))
		return;

	while (true) {
		if (con->state == CSM_STATE_CLOSED)
			goto out;
		w = kmalloc(sizeof(*w), GFP_KERNEL | __GFP_REPEAT);
		if (w)
			break;
		cond_resched();
	}

	w->con = con;
	w->ev = ev;
	INIT_WORK(&w->work, csm_worker);
	queue_work(con->sess->sm_wq, &w->work);

out:
	ibtrs_srv_sess_put(con->sess);
}

static void sess_schedule_csm_event(struct ibtrs_srv_sess *sess, enum csm_ev ev)
{
	struct ibtrs_srv_con *con;

	list_for_each_entry(con, &sess->con_list, list)
		csm_schedule_event(con, ev);
}

static void remove_sess_from_sysfs(struct ibtrs_srv_sess *sess)
{
	if (!sess->state_in_sysfs)
		return;

	kobject_del(&sess->kobj_stats);
	kobject_del(&sess->kobj);
	sess->state_in_sysfs = false;

	ibtrs_srv_schedule_sysfs_put(sess);
}

static void ssm_idle(struct ibtrs_srv_sess *sess, enum ssm_ev ev)
{
	enum ssm_state state = sess->state;

	pr_debug("sess %p, event %s, est_cnt=%d\n", sess, ssm_ev_str(ev),
		 sess->est_cnt);
	switch (ev) {
	case SSM_EV_CON_DISCONNECTED:
		sess->est_cnt--;
		/* fall through */
	case SSM_EV_CON_EST_ERR:
		if (!sess->active_cnt) {
			ibtrs_srv_sess_destroy(sess);
			ssm_set_state(sess, SSM_STATE_CLOSED);
			cancel_delayed_work(&sess->check_heartbeat_dwork);
			schedule_sess_put(sess);
		} else {
			ssm_set_state(sess, SSM_STATE_CLOSING);
		}
		break;
	case SSM_EV_CON_CONNECTED: {
		int err;

		sess->est_cnt++;
		if (sess->est_cnt != sess->con_cnt)
			break;

		err = ibtrs_srv_create_sess_files(sess);
		if (err) {
			if (err == -EEXIST)
				ibtrs_err(sess,
					  "Session sysfs files already exist,"
					  " possibly a user-space process is"
					  " holding them\n");
			else
				ibtrs_err(sess,
					  "Create session sysfs files failed,"
					  " err: %d\n", err);
			goto destroy;
		}

		sess->state_in_sysfs = true;

		err = ibtrs_srv_sess_ev(sess, IBTRS_SRV_SESS_EV_CONNECTED);
		if (err) {
			ibtrs_err(sess, "Notifying user session event"
				  " failed, err: %d\n. Session is closed",
				  err);
			goto destroy;
		}

		ssm_set_state(sess, SSM_STATE_CONNECTED);

		break;
		destroy:
		remove_sess_from_sysfs(sess);
		ssm_set_state(sess, SSM_STATE_CLOSING);
		sess_schedule_csm_event(sess, CSM_EV_SESS_CLOSING);
		break;
	}
	case SSM_EV_SESS_CLOSE:
		ssm_set_state(sess, SSM_STATE_CLOSING);
		sess_schedule_csm_event(sess, CSM_EV_SESS_CLOSING);
		break;
	default:
		ibtrs_err(sess, "Session received unexpected event %s "
			  "in %s state.\n", ssm_ev_str(ev), ssm_state_str(state));
	}
}

static void ssm_connected(struct ibtrs_srv_sess *sess, enum ssm_ev ev)
{
	enum ssm_state state = sess->state;

	pr_debug("sess %p, event %s, est_cnt=%d\n", sess, ssm_ev_str(ev),
		 sess->est_cnt);
	switch (ev) {
	case SSM_EV_CON_DISCONNECTED:
		remove_sess_from_sysfs(sess);
		sess->est_cnt--;

		ssm_set_state(sess, SSM_STATE_CLOSING);
		ibtrs_srv_sess_ev(sess, IBTRS_SRV_SESS_EV_DISCONNECTED);
		break;
	case SSM_EV_SESS_CLOSE:
	case SSM_EV_SYSFS_DISCONNECT:
		remove_sess_from_sysfs(sess);
		ssm_set_state(sess, SSM_STATE_CLOSING);
		ibtrs_srv_sess_ev(sess, IBTRS_SRV_SESS_EV_DISCONNECTED);

		sess_schedule_csm_event(sess, CSM_EV_SESS_CLOSING);
		break;
	default:
		ibtrs_err(sess, "Session received unexpected event %s "
			  "in %s state.\n", ssm_ev_str(ev), ssm_state_str(state));
	}
}

static void ssm_closing(struct ibtrs_srv_sess *sess, enum ssm_ev ev)
{
	enum ssm_state state = sess->state;

	pr_debug("sess %p, event %s, est_cnt=%d\n", sess, ssm_ev_str(ev),
		 sess->est_cnt);
	switch (ev) {
	case SSM_EV_CON_CONNECTED:
		sess->est_cnt++;
		break;
	case SSM_EV_CON_DISCONNECTED:
		sess->est_cnt--;
		/* fall through */
	case SSM_EV_CON_EST_ERR:
		if (sess->active_cnt == 0) {
			ibtrs_srv_sess_destroy(sess);
			ssm_set_state(sess, SSM_STATE_CLOSED);
			cancel_delayed_work(&sess->check_heartbeat_dwork);
			schedule_sess_put(sess);
		}
		break;
	case SSM_EV_SESS_CLOSE:
		sess_schedule_csm_event(sess, CSM_EV_SESS_CLOSING);
		break;
	case SSM_EV_SYSFS_DISCONNECT:
		/* just ignore it, the connection should have a
		 * CSM_EV_SESS_CLOSING event on the queue to be
		 * processed later
		 */
		break;
	default:
		ibtrs_err(sess, "Session received unexpected event %s "
			  "in %s state.\n", ssm_ev_str(ev), ssm_state_str(state));
	}
}

static void ssm_closed(struct ibtrs_srv_sess *sess, enum ssm_ev ev)
{
	/* in this state, we ignore every event and wait for the session
	 * to be destroyed
	 */
	pr_debug("sess %p, event %s, est_cnt=%d\n", sess, ssm_ev_str(ev),
		 sess->est_cnt);
}

typedef void (ssm_ev_handler_fn)(struct ibtrs_srv_sess *, enum ssm_ev);

static ssm_ev_handler_fn *ibtrs_srv_ev_handlers[] = {
	[SSM_STATE_IDLE]		= ssm_idle,
	[SSM_STATE_CONNECTED]		= ssm_connected,
	[SSM_STATE_CLOSING]		= ssm_closing,
	[SSM_STATE_CLOSED]		= ssm_closed,
};

static void check_heartbeat_work(struct work_struct *work)
{
	struct ibtrs_srv_sess *sess;
	s64 diff;

	sess = container_of(to_delayed_work(work), struct ibtrs_srv_sess,
			    check_heartbeat_dwork);

	if (!sess->heartbeat.timeout_ms)
		return;
	diff = ibtrs_heartbeat_recv_ts_diff_ms(&sess->heartbeat);
	if (unlikely(diff >= sess->heartbeat.timeout_ms)) {
		ssm_schedule_event(sess, SSM_EV_SESS_CLOSE);
		return;
	}
	if (WARN_ON(!queue_delayed_work(sess->sm_wq,
					&sess->check_heartbeat_dwork,
					HEARTBEAT_INTV_JIFFIES)))
		ibtrs_wrn_rl(sess, "Schedule check heartbeat work failed, "
			     "check_heartbeat worker already queued?\n");
}

static void send_heartbeat_work(struct work_struct *work)
{
	struct ibtrs_srv_sess *sess;
	int err;

	sess = container_of(to_delayed_work(work), struct ibtrs_srv_sess,
			    send_heartbeat_dwork);

	if (ibtrs_heartbeat_send_ts_diff_ms(&sess->heartbeat) >=
	    HEARTBEAT_INTV_MS) {
		err = send_heartbeat(sess);
		if (unlikely(err)) {
			ibtrs_wrn_rl(sess,
				     "Sending heartbeat failed, err: %d,"
				     " no further heartbeat will be sent\n",
				     err);
			return;
		}
	}

	if (WARN_ON(!queue_delayed_work(sess->sm_wq,
					&sess->send_heartbeat_dwork,
					HEARTBEAT_INTV_JIFFIES)))
		ibtrs_wrn_rl(sess, "schedule send heartbeat work failed, "
			     "send_heartbeat worker already queued?\n");
}

static inline void ssm_ev_handle(struct ibtrs_srv_sess *sess, enum ssm_ev ev)
{
	return (*ibtrs_srv_ev_handlers[sess->state])(sess, ev);
}

static void ssm_worker(struct work_struct *work)
{
	struct ssm_work *ssm_w = container_of(work, struct ssm_work, work);

	ssm_ev_handle(ssm_w->sess, ssm_w->ev);
	kfree(ssm_w);
}

static int ssm_schedule_event(struct ibtrs_srv_sess *sess, enum ssm_ev ev)
{
	struct ssm_work *w;
	int ret = 0;

	if (!ibtrs_srv_sess_get(sess))
		return -EPERM;

	while (true) {
		if (sess->state == SSM_STATE_CLOSED) {
			ret = -EPERM;
			goto out;
		}
		w = kmalloc(sizeof(*w), GFP_KERNEL | __GFP_REPEAT);
		if (w)
			break;
		cond_resched();
	}

	w->sess = sess;
	w->ev = ev;
	INIT_WORK(&w->work, ssm_worker);
	queue_work(sess->sm_wq, &w->work);

out:
	ibtrs_srv_sess_put(sess);
	return ret;
}

static int ssm_init(struct ibtrs_srv_sess *sess)
{
	sess->sm_wq = create_singlethread_workqueue("ibtrs_ssm_wq");
	if (!sess->sm_wq)
		return -ENOMEM;

	INIT_DELAYED_WORK(&sess->check_heartbeat_dwork, check_heartbeat_work);
	INIT_DELAYED_WORK(&sess->send_heartbeat_dwork, send_heartbeat_work);

	ssm_set_state(sess, SSM_STATE_IDLE);

	return 0;
}

static int ibtrs_srv_create_debugfs_files(void)
{
	int ret = 0;
	struct dentry *file;

	ibtrs_srv_debugfs_dir = debugfs_create_dir("ibtrs_server", NULL);
	if (IS_ERR_OR_NULL(ibtrs_srv_debugfs_dir)) {
		ibtrs_srv_debugfs_dir = NULL;
		ret = PTR_ERR(ibtrs_srv_debugfs_dir);
		if (ret == -ENODEV)
			pr_warn("Debugfs not enabled in kernel\n");
		else
			pr_warn("Failed to create top-level debugfs directory,"
				" err: %d\n", ret);
		goto out;
	}

	mempool_debugfs_dir = debugfs_create_dir("mempool",
						 ibtrs_srv_debugfs_dir);
	if (IS_ERR_OR_NULL(mempool_debugfs_dir)) {
		ret = PTR_ERR(mempool_debugfs_dir);
		pr_warn("Failed to create mempool debugfs directory,"
			" err: %d\n", ret);
		goto out_remove;
	}

	file = debugfs_create_u32("nr_free_buf_pool", 0444,
				  mempool_debugfs_dir, &nr_free_buf_pool);
	if (IS_ERR_OR_NULL(file)) {
		pr_warn("Failed to create mempool \"nr_free_buf_pool\""
			" debugfs file\n");
		ret = -EINVAL;
		goto out_remove;
	}

	file = debugfs_create_u32("nr_total_buf_pool", 0444,
				  mempool_debugfs_dir, &nr_total_buf_pool);
	if (IS_ERR_OR_NULL(file)) {
		pr_warn("Failed to create mempool \"nr_total_buf_pool\""
			" debugfs file\n");
		ret = -EINVAL;
		goto out_remove;
	}

	file = debugfs_create_u32("nr_active_sessions", 0444,
				  mempool_debugfs_dir, &nr_active_sessions);
	if (IS_ERR_OR_NULL(file)) {
		pr_warn("Failed to create mempool \"nr_active_sessions\""
			" debugfs file\n");
		ret = -EINVAL;
		goto out_remove;
	}

	goto out;

out_remove:
	debugfs_remove_recursive(ibtrs_srv_debugfs_dir);
	ibtrs_srv_debugfs_dir = NULL;
	mempool_debugfs_dir = NULL;
out:
	return ret;
}

static void ibtrs_srv_destroy_debugfs_files(void)
{
	debugfs_remove_recursive(ibtrs_srv_debugfs_dir);
}

static void ibtrs_srv_free_buf_pool(void)
{
	struct ibtrs_rcv_buf_pool *pool, *pool_next;

	list_for_each_entry_safe(pool, pool_next, &free_buf_pool_list, list) {
		list_del(&pool->list);
		nr_free_buf_pool--;
		free_recv_buf_pool(pool);
	}
}

static void ibtrs_srv_alloc_buf_pool(void)
{
	struct ibtrs_rcv_buf_pool *pool;
	int i;

	for (i = 0; i < init_pool_size; i++) {
		pool = alloc_rcv_buf_pool();
		if (!pool) {
			pr_warn("Failed to allocate initial RDMA buffer pool"
				" #%d\n", i + 1);
			break;
		}
		list_add(&pool->list, &free_buf_pool_list);
		nr_free_buf_pool++;
		nr_total_buf_pool++;
	}
}

static int __init ibtrs_server_init(void)
{
	int err;

	if (!strlen(cq_affinity_list))
		init_cq_affinity();

	scnprintf(hostname, sizeof(hostname), "%s", utsname()->nodename);
	pr_info("Loading module ibtrs_server, version: %s ("
		" retry_count: %d, "
		" default_heartbeat_timeout_ms: %d,"
		" cq_affinity_list: %s, max_io_size: %d,"
		" sess_queue_depth: %d, init_pool_size: %d,"
		" pool_size_hi_wm: %d, hostname: %s)\n",
		__stringify(IBTRS_VER),
		retry_count, default_heartbeat_timeout_ms,
		cq_affinity_list, max_io_size, sess_queue_depth,
		init_pool_size, pool_size_hi_wm, hostname);

	err = check_module_params();
	if (err) {
		pr_err("Failed to load module, invalid module parameters,"
		       " err: %d\n", err);
		return err;
	}
	ibtrs_wq = create_workqueue("ibtrs_server_wq");
	if (!ibtrs_wq) {
		pr_err("Failed to load module, alloc ibtrs_server_wq failed\n");
		return -ENOMEM;
	}
	err = ibtrs_srv_create_sysfs_files();
	if (err) {
		pr_err("Failed to load module, can't create sysfs files,"
		       " err: %d\n", err);
		goto out_ibtrs_wq;
	}
	err = ibtrs_srv_create_debugfs_files();
	if (err)
		pr_warn("Unable to create debugfs files, err: %d."
			" Continuing without debugfs\n", err);

	ibtrs_srv_alloc_buf_pool();

	return 0;

out_ibtrs_wq:
	destroy_workqueue(ibtrs_wq);
	return err;
}

static void __exit ibtrs_server_exit(void)
{
	ibtrs_srv_destroy_debugfs_files();
	ibtrs_srv_destroy_sysfs_files();
	destroy_workqueue(ibtrs_wq);
	ibtrs_srv_free_buf_pool();
}

module_init(ibtrs_server_init);
module_exit(ibtrs_server_exit);
