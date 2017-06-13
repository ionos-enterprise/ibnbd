#define pr_fmt(fmt) KBUILD_MODNAME " L" __stringify(__LINE__) ": " fmt

#include <linux/module.h>
#include <linux/sizes.h>
#include <linux/utsname.h>
#include <linux/cpumask.h>
#include <linux/debugfs.h>
#include <rdma/ib_verbs.h>
#include <rdma/rdma_cm.h>
#include <rdma/ib.h>

#include <rdma/ibtrs_srv.h>
#include "ibtrs_srv_sysfs.h"
#include "ibtrs_srv_internal.h"
#include <rdma/ibtrs.h>
#include <rdma/ibtrs_log.h>

MODULE_AUTHOR("ibnbd@profitbricks.com");
MODULE_DESCRIPTION("InfiniBand Transport Server");
MODULE_VERSION(__stringify(IBTRS_VER));
MODULE_LICENSE("GPL");

#define DEFAULT_MAX_IO_SIZE_KB 128
#define DEFAULT_MAX_IO_SIZE (DEFAULT_MAX_IO_SIZE_KB * 1024)
static int max_io_size = DEFAULT_MAX_IO_SIZE;
#define MAX_REQ_SIZE PAGE_SIZE
static int rcv_buf_size = DEFAULT_MAX_IO_SIZE + MAX_REQ_SIZE;

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
		pr_err("Can't set cq_affinity_list \"%s\": %s\n", val,
		       strerror(ret));
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

static struct rdma_cm_id	*cm_id_ip;
static struct rdma_cm_id	*cm_id_ib;
static DEFINE_MUTEX(sess_mutex);
static LIST_HEAD(sess_list);
static DECLARE_WAIT_QUEUE_HEAD(sess_list_waitq);
static struct workqueue_struct *destroy_wq;

static LIST_HEAD(device_list);
static DEFINE_MUTEX(device_list_mutex);

static DEFINE_MUTEX(buf_pool_mutex);
static LIST_HEAD(free_buf_pool_list);
static int nr_free_buf_pool;
static int nr_total_buf_pool;
static int nr_active_sessions;

static const struct ibtrs_srv_ops *srv_ops;
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
	struct ibtrs_session	*sess;
	struct work_struct	work;
};

struct ibtrs_srv_sysfs_put_work {
	struct work_struct	work;
	struct ibtrs_session	*sess;
};

struct ssm_create_con_work {
	struct ibtrs_session	*sess;
	struct rdma_cm_id	*cm_id;
	struct work_struct	work;
	bool			user;/* true if con is for user msg only */
};

struct ssm_work {
	struct ibtrs_session	*sess;
	enum ssm_ev		ev;
	struct work_struct	work;
};

struct ibtrs_con {
	/* list for ibtrs_session->con_list */
	struct list_head	list;
	enum csm_state		state;
	/* true if con is for user msg only */
	bool			user;
	bool			failover_enabled;
	struct ib_con		ib_con;
	atomic_t		wr_cnt;
	struct rdma_cm_id	*cm_id;
	int			cq_vector;
	struct ibtrs_session	*sess;
	struct work_struct	cq_work;
	struct workqueue_struct *cq_wq;
	struct workqueue_struct *rdma_resp_wq;
	struct ib_wc		wcs[WC_ARRAY_SIZE];
	bool			device_being_removed;
};

struct csm_work {
	struct ibtrs_con	*con;
	enum csm_ev		ev;
	struct work_struct	work;
};

struct msg_work {
	struct work_struct	work;
	struct ibtrs_con	*con;
	void                    *msg;
};

struct ibtrs_device {
	struct list_head	entry;
	struct ib_device	*device;
	struct ib_session	ib_sess;
	struct completion	*ib_sess_destroy_completion;
	struct kref		ref;
};

struct ibtrs_ops_id {
	struct ibtrs_con		*con;
	u32				msg_id;
	u8				dir;
	u64				data_dma_addr;
	struct ibtrs_msg_req_rdma_write *req;
	struct ib_rdma_wr		*tx_wr;
	struct ib_sge			*tx_sg;
	int				status;
	struct work_struct		work;
} ____cacheline_aligned;

static void csm_set_state(struct ibtrs_con *con, enum csm_state s)
{
	if (con->state != s) {
		pr_debug("changing con %p csm state from %s to %s\n", con,
		    csm_state_str(con->state), csm_state_str(s));
		con->state = s;
	}
}

static void ssm_set_state(struct ibtrs_session *sess, enum ssm_state state)
{
	if (sess->state != state) {
		pr_debug("changing sess %p ssm state from %s to %s\n", sess,
		    ssm_state_str(sess->state), ssm_state_str(state));
		sess->state = state;
	}
}

static struct ibtrs_con *ibtrs_srv_get_user_con(struct ibtrs_session *sess)
{
	struct ibtrs_con *con;

	if (sess->est_cnt > 0) {
		list_for_each_entry(con, &sess->con_list, list) {
			if (con->user && con->state == CSM_STATE_CONNECTED)
				return con;
		}
	}
	return NULL;
}

static void csm_init(struct ibtrs_con *con);
static void csm_schedule_event(struct ibtrs_con *con, enum csm_ev ev);
static int ssm_init(struct ibtrs_session *sess);
static int ssm_schedule_event(struct ibtrs_session *sess, enum ssm_ev ev);

static int ibtrs_srv_get_sess_current_port_num(struct ibtrs_session *sess)
{
	struct ibtrs_con *con, *next;
	struct ibtrs_con *ucon = ibtrs_srv_get_user_con(sess);

	if (sess->state != SSM_STATE_CONNECTED || !ucon)
		return -ECOMM;

	mutex_lock(&sess->lock);
	if (WARN_ON(!sess->cm_id)) {
		mutex_unlock(&sess->lock);
		return -ENODEV;
	}
	list_for_each_entry_safe(con, next, &sess->con_list, list) {
		if (unlikely(con->state != CSM_STATE_CONNECTED)) {
			mutex_unlock(&sess->lock);
			return -ECOMM;
		}
		if (con->cm_id->port_num != sess->cm_id->port_num) {
			mutex_unlock(&sess->lock);
			return 0;
		}
	}
	mutex_unlock(&sess->lock);
	return sess->cm_id->port_num;
}

int ibtrs_srv_current_hca_port_to_str(struct ibtrs_session *sess,
				      char *buf, size_t len)
{
	if (!ibtrs_srv_get_sess_current_port_num(sess))
		return scnprintf(buf, len, "migrating\n");

	if (ibtrs_srv_get_sess_current_port_num(sess) < 0)
		return ibtrs_srv_get_sess_current_port_num(sess);

	return scnprintf(buf, len, "%u\n",
			 ibtrs_srv_get_sess_current_port_num(sess));
}

inline const char *ibtrs_srv_get_sess_hca_name(struct ibtrs_session *sess)
{
	struct ibtrs_con *con = ibtrs_srv_get_user_con(sess);

	if (con)
		return sess->dev->device->name;
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

static inline void ibtrs_srv_stats_dec_inflight(struct ibtrs_session *sess)
{
	if (!atomic_dec_return(&sess->stats.rdma_stats.inflight))
		wake_up(&sess->bufs_wait);
}

int ibtrs_srv_reset_rdma_stats(struct ibtrs_session *sess, bool enable)
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

ssize_t ibtrs_srv_stats_rdma_to_str(struct ibtrs_session *sess,
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

int ibtrs_srv_reset_user_ib_msgs_stats(struct ibtrs_session *sess, bool enable)
{
	if (enable) {
		memset(&sess->stats.user_ib_msgs, 0,
		       sizeof(sess->stats.user_ib_msgs));
		return 0;
	} else {
		return -EINVAL;
	}
}

int ibtrs_srv_stats_user_ib_msgs_to_str(struct ibtrs_session *sess, char *buf,
					size_t len)
{
	return snprintf(buf, len, "%ld %ld %ld %ld\n",
			atomic64_read(&sess->stats.user_ib_msgs.recv_msg_cnt),
			atomic64_read(&sess->stats.user_ib_msgs.recv_size),
			atomic64_read(&sess->stats.user_ib_msgs.sent_msg_cnt),
			atomic64_read(&sess->stats.user_ib_msgs.sent_size));
}

int ibtrs_srv_reset_wc_completion_stats(struct ibtrs_session *sess, bool enable)
{
	if (enable) {
		memset(&sess->stats.wc_comp, 0, sizeof(sess->stats.wc_comp));
		return 0;
	} else {
		return -EINVAL;
	}
}

int ibtrs_srv_stats_wc_completion_to_str(struct ibtrs_session *sess, char *buf,
					 size_t len)
{
	return snprintf(buf, len, "%d %ld %ld\n",
			atomic_read(&sess->stats.wc_comp.max_wc_cnt),
			atomic64_read(&sess->stats.wc_comp.total_wc_cnt),
			atomic64_read(&sess->stats.wc_comp.calls));
}

ssize_t ibtrs_srv_reset_all_help(struct ibtrs_session *sess,
				 char *page, size_t len)
{
	return scnprintf(page, PAGE_SIZE, "echo 1 to reset all statistics\n");
}

int ibtrs_srv_reset_all_stats(struct ibtrs_session *sess, bool enable)
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

static int ibtrs_srv_sess_ev(struct ibtrs_session *sess,
			     enum ibtrs_srv_sess_ev ev)
{
	if (!sess->session_announced_to_user &&
	    ev != IBTRS_SRV_SESS_EV_CONNECTED)
		return 0;

	if (ev == IBTRS_SRV_SESS_EV_CONNECTED)
		sess->session_announced_to_user = true;

	return srv_ops->sess_ev(sess, ev, sess->priv);
}

static void free_id(struct ibtrs_ops_id *id)
{
	if (!id)
		return;
	kfree(id->tx_wr);
	kfree(id->tx_sg);
	kfree(id);
}

static void free_sess_tx_bufs(struct ibtrs_session *sess)
{
	struct ibtrs_iu *e, *next;
	int i;

	if (sess->rdma_info_iu) {
		ibtrs_iu_free(sess->rdma_info_iu, DMA_TO_DEVICE,
			      sess->dev->device);
		sess->rdma_info_iu = NULL;
	}

	WARN_ON(sess->tx_bufs_used);
	list_for_each_entry_safe(e, next, &sess->tx_bufs, list) {
		list_del(&e->list);
		ibtrs_iu_free(e, DMA_TO_DEVICE, sess->dev->device);
	}

	if (sess->ops_ids) {
		for (i = 0; i < sess->queue_depth; i++)
			free_id(sess->ops_ids[i]);
		kfree(sess->ops_ids);
		sess->ops_ids = NULL;
	}
}

static void put_tx_iu(struct ibtrs_session *sess, struct ibtrs_iu *iu)
{
	spin_lock(&sess->tx_bufs_lock);
	ibtrs_iu_put(&sess->tx_bufs, iu);
	sess->tx_bufs_used--;
	spin_unlock(&sess->tx_bufs_lock);
}

static struct ibtrs_iu *get_tx_iu(struct ibtrs_session *sess)
{
	struct ibtrs_iu *iu;

	spin_lock(&sess->tx_bufs_lock);
	iu = ibtrs_iu_get(&sess->tx_bufs);
	if (iu)
		sess->tx_bufs_used++;
	spin_unlock(&sess->tx_bufs_lock);

	return iu;
}

static int rdma_write_sg(struct ibtrs_ops_id *id)
{
	int err, i, offset;
	struct ib_send_wr *bad_wr;
	struct ib_rdma_wr *wr = NULL;
	struct ibtrs_session *sess = id->con->sess;

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
			ERR(sess, "Invalid RDMA-Write sg list length 0\n");
			return -EINVAL;
		}

		list->lkey = sess->dev->ib_sess.pd->local_dma_lkey;
		offset += list->length;

		wr->wr.wr_id		= (uintptr_t)id;
		wr->wr.sg_list		= list;
		wr->wr.num_sge		= 1;
		wr->remote_addr	= id->req->desc[i].addr;
		wr->rkey	= id->req->desc[i].key;

		if (i < (id->req->sg_cnt - 1)) {
			wr->wr.next	= &id->tx_wr[i + 1].wr;
			wr->wr.opcode	= IB_WR_RDMA_WRITE;
			wr->wr.ex.imm_data	= 0;
			wr->wr.send_flags	= 0;
		}
	}

	wr->wr.opcode	= IB_WR_RDMA_WRITE_WITH_IMM;
	wr->wr.next	= NULL;
	wr->wr.send_flags	= atomic_inc_return(&id->con->wr_cnt) %
				sess->queue_depth ? 0 : IB_SEND_SIGNALED;
	wr->wr.ex.imm_data	= cpu_to_be32(id->msg_id << 16);

	err = ib_post_send(id->con->ib_con.qp, &id->tx_wr[0].wr, &bad_wr);
	if (unlikely(err))
		ERR(sess,
		    "Posting RDMA-Write-Request to QP failed, err: %s\n",
		    strerror(err));

	return err;
}

static int send_io_resp_imm(struct ibtrs_con *con, int msg_id, s16 errno)
{
	int err;

	err = ibtrs_write_empty_imm(con->ib_con.qp, (msg_id << 16) | (u16)errno,
				    atomic_inc_return(&con->wr_cnt) %
				    con->sess->queue_depth ? 0 :
				    IB_SEND_SIGNALED);
	if (unlikely(err))
		ERR_RL(con->sess, "Posting RDMA-Write-Request to QP failed,"
		       " err: %s\n", strerror(err));

	return err;
}

static int send_heartbeat_raw(struct ibtrs_con *con)
{
	int err;

	err = ibtrs_write_empty_imm(con->ib_con.qp, UINT_MAX, IB_SEND_SIGNALED);
	if (unlikely(err)) {
		ERR(con->sess,
		    "Sending heartbeat failed, posting msg to QP failed,"
		    " err: %s\n", strerror(err));
		return err;
	}

	ibtrs_heartbeat_set_send_ts(&con->sess->heartbeat);
	return err;
}

static int send_heartbeat(struct ibtrs_session *sess)
{
	struct ibtrs_con *con;

	if (unlikely(list_empty(&sess->con_list)))
		return -ENOENT;

	con = list_first_entry(&sess->con_list, struct ibtrs_con, list);
	WARN_ON(!con->user);

	if (unlikely(con->state != CSM_STATE_CONNECTED))
		return -ENOTCONN;

	return send_heartbeat_raw(con);
}

static int ibtrs_srv_queue_resp_rdma(struct ibtrs_ops_id *id)
{
	if (unlikely(id->con->state != CSM_STATE_CONNECTED)) {
		ERR_RL(id->con->sess, "Sending I/O response failed, "
		       " session is disconnected, sess state %s,"
		       " con state %s\n", ssm_state_str(id->con->sess->state),
		       csm_state_str(id->con->state));
		return -ECOMM;
	}

	if (WARN_ON(!queue_work(id->con->rdma_resp_wq, &id->work))) {
		ERR_RL(id->con->sess, "Sending I/O response failed,"
		       " couldn't queue work\n");
		return -EPERM;
	}

	return 0;
}

static void ibtrs_srv_resp_rdma_worker(struct work_struct *work)
{
	struct ibtrs_ops_id *id;
	int err;
	struct ibtrs_session *sess;

	id = container_of(work, struct ibtrs_ops_id, work);
	sess = id->con->sess;

	if (id->status || id->dir == WRITE) {
		pr_debug("err or write msg_id=%d, status=%d, sending response\n",
		    id->msg_id, id->status);

		err = send_io_resp_imm(id->con, id->msg_id, id->status);
		if (unlikely(err)) {
			ERR_RL(sess, "Sending imm msg failed, err: %s\n",
			       strerror(err));
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
		ERR_RL(sess, "Sending I/O read response failed, err: %s\n",
		       strerror(err));
		if (err == -ENOMEM && !ibtrs_srv_queue_resp_rdma(id))
			return;
		csm_schedule_event(id->con, CSM_EV_CON_ERROR);
	}
	ibtrs_heartbeat_set_send_ts(&sess->heartbeat);
	ibtrs_srv_stats_dec_inflight(sess);
}

/*
 * This function may be called from an interrupt context, e.g. on bio_endio
 * callback on the user module. Queue the real work on a workqueue so we don't
 * need to hold an irq spinlock.
 */
int ibtrs_srv_resp_rdma(struct ibtrs_ops_id *id, int status)
{
	int err = 0;

	if (unlikely(!id)) {
		pr_err("Sending I/O response failed, I/O ops id NULL\n");
		return -EINVAL;
	}

	id->status = status;
	INIT_WORK(&id->work, ibtrs_srv_resp_rdma_worker);

	err = ibtrs_srv_queue_resp_rdma(id);
	if (err)
		ibtrs_srv_stats_dec_inflight(id->con->sess);
	return err;
}
EXPORT_SYMBOL(ibtrs_srv_resp_rdma);

static bool ibtrs_srv_get_usr_msg_buf(struct ibtrs_session *sess)
{
	return atomic_dec_if_positive(&sess->peer_usr_msg_bufs) >= 0;
}

int ibtrs_srv_send(struct ibtrs_session *sess, const struct kvec *vec,
		   size_t nr)
{
	struct ibtrs_iu *iu = NULL;
	struct ibtrs_con *con;
	struct ibtrs_msg_user *msg;
	size_t len;
	bool closed_st = false;
	int err;

	if (WARN_ONCE(list_empty(&sess->con_list),
		      "Sending message failed, no connection available\n"))
		return -ECOMM;
	con = ibtrs_srv_get_user_con(sess);

	if (unlikely(!con)) {
		WRN(sess,
		    "Sending message failed, no user connection exists\n");
		return -ECOMM;
	}

	len = kvec_length(vec, nr);

	if (unlikely(len + IBTRS_HDR_LEN > MAX_REQ_SIZE)) {
		WRN_RL(sess, "Sending message failed, passed data too big,"
		       " %zu > %lu\n", len, MAX_REQ_SIZE - IBTRS_HDR_LEN);
		return -EMSGSIZE;
	}

	wait_event(sess->mu_buf_wait_q,
		   (closed_st = (con->state != CSM_STATE_CONNECTED)) ||
		   ibtrs_srv_get_usr_msg_buf(sess));

	if (unlikely(closed_st)) {
		ERR_RL(sess, "Sending message failed, not connected (state"
		       " %s)\n", csm_state_str(con->state));
		return -ECOMM;
	}

	wait_event(sess->mu_iu_wait_q,
		   (closed_st = (con->state != CSM_STATE_CONNECTED)) ||
		   (iu = get_tx_iu(sess)) != NULL);

	if (unlikely(closed_st)) {
		ERR_RL(sess, "Sending message failed, not connected (state"
		       " %s)\n", csm_state_str(con->state));
		err = -ECOMM;
		goto err_iu;
	}

	msg		= iu->buf;
	msg->hdr.type	= IBTRS_MSG_USER;
	msg->hdr.tsize	= len + IBTRS_HDR_LEN;
	copy_from_kvec(msg->payl, vec, len);

	ibtrs_deb_msg_hdr("Sending: ", &msg->hdr);
	err = ibtrs_post_send(con->ib_con.qp,
			      con->sess->dev->ib_sess.pd->__internal_mr, iu,
			      msg->hdr.tsize);
	if (unlikely(err)) {
		ERR_RL(sess, "Sending message failed, posting message to QP"
		       " failed, err: %s\n", strerror(err));
		goto err_post_send;
	}
	ibtrs_heartbeat_set_send_ts(&sess->heartbeat);

	atomic64_inc(&sess->stats.user_ib_msgs.sent_msg_cnt);
	atomic64_add(len, &sess->stats.user_ib_msgs.sent_size);

	return 0;

err_post_send:
	put_tx_iu(sess, iu);
	wake_up(&con->sess->mu_iu_wait_q);
err_iu:
	atomic_inc(&sess->peer_usr_msg_bufs);
	wake_up(&con->sess->mu_buf_wait_q);
	return err;
}
EXPORT_SYMBOL(ibtrs_srv_send);

inline void ibtrs_srv_set_sess_priv(struct ibtrs_session *sess, void *priv)
{
	sess->priv = priv;
}
EXPORT_SYMBOL(ibtrs_srv_set_sess_priv);

static int ibtrs_post_recv(struct ibtrs_con *con, struct ibtrs_iu *iu)
{
	struct ib_recv_wr wr, *bad_wr;
	struct ib_sge list;
	int err;

	list.addr   = iu->dma_addr;
	list.length = iu->size;
	list.lkey   = con->sess->dev->ib_sess.pd->local_dma_lkey;

	if (unlikely(list.length == 0)) {
		ERR_RL(con->sess, "Posting recv buffer failed, invalid sg list"
		       " length 0\n");
		return -EINVAL;
	}

	wr.next     = NULL;
	wr.wr_id    = (uintptr_t)iu;
	wr.sg_list  = &list;
	wr.num_sge  = 1;

	err = ib_post_recv(con->ib_con.qp, &wr, &bad_wr);
	if (unlikely(err))
		ERR_RL(con->sess, "Posting recv buffer failed, err: %s\n",
		       strerror(err));

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

static void unreg_cont_bufs(struct ibtrs_session *sess)
{
	struct ibtrs_rcv_buf *buf;
	int i;

	pr_debug("Unregistering %d RDMA buffers\n", sess_queue_depth);
	for (i = 0; i < sess_queue_depth; i++) {
		buf = &sess->rcv_buf_pool->rcv_bufs[i];

		ib_dma_unmap_single(sess->dev->device, buf->rdma_addr,
				    rcv_buf_size, DMA_BIDIRECTIONAL);
	}
}

static void release_cont_bufs(struct ibtrs_session *sess)
{
	unreg_cont_bufs(sess);
	put_rcv_buf_pool(sess->rcv_buf_pool);
	sess->rcv_buf_pool = NULL;
}

static int setup_cont_bufs(struct ibtrs_session *sess)
{
	struct ibtrs_rcv_buf *buf;
	int i, err;

	sess->rcv_buf_pool = get_alloc_rcv_buf_pool();
	if (!sess->rcv_buf_pool) {
		ERR(sess, "Failed to allocate receive buffers for session\n");
		return -ENOMEM;
	}

	pr_debug("Mapping %d buffers for RDMA\n", sess->queue_depth);
	for (i = 0; i < sess->queue_depth; i++) {
		buf = &sess->rcv_buf_pool->rcv_bufs[i];

		buf->rdma_addr = ib_dma_map_single(sess->dev->device, buf->buf,
						   rcv_buf_size,
						   DMA_BIDIRECTIONAL);
		if (unlikely(ib_dma_mapping_error(sess->dev->device,
						  buf->rdma_addr))) {
			pr_err("Registering RDMA buf failed,"
			       " DMA mapping failed\n");
			err = -EIO;
			goto err_map;
		}
	}

	sess->off_len = 31 - ilog2(sess->queue_depth - 1);
	sess->off_mask = (1 << sess->off_len) - 1;

	INFO(sess, "Allocated %d %dKB RDMA receive buffers, %dKB in total\n",
	     sess->queue_depth, rcv_buf_size >> 10,
	     sess->queue_depth * rcv_buf_size >> 10);

	return 0;

err_map:
	for (i = 0; i < sess->queue_depth; i++) {
		buf = &sess->rcv_buf_pool->rcv_bufs[i];

		if (buf->rdma_addr &&
		    !ib_dma_mapping_error(sess->dev->device, buf->rdma_addr))
			ib_dma_unmap_single(sess->dev->device, buf->rdma_addr,
					    rcv_buf_size, DMA_BIDIRECTIONAL);
	}
	return err;
}

static void fill_ibtrs_msg_sess_open_resp(struct ibtrs_msg_sess_open_resp *msg,
					  struct ibtrs_con *con)
{
	int i;

	msg->hdr.type   = IBTRS_MSG_SESS_OPEN_RESP;
	msg->hdr.tsize  = IBTRS_MSG_SESS_OPEN_RESP_LEN(con->sess->queue_depth);

	msg->ver = con->sess->ver;
	strlcpy(msg->hostname, hostname, sizeof(msg->hostname));
	msg->cnt = con->sess->queue_depth;
	msg->rkey = con->sess->dev->ib_sess.pd->unsafe_global_rkey;
	msg->max_inflight_msg = con->sess->queue_depth;
	msg->max_io_size = max_io_size;
	msg->max_req_size = MAX_REQ_SIZE;
	for (i = 0; i < con->sess->queue_depth; i++)
		msg->addr[i] = con->sess->rcv_buf_pool->rcv_bufs[i].rdma_addr;
}

static void free_sess_rx_bufs(struct ibtrs_session *sess)
{
	int i;

	if (sess->dummy_rx_iu) {
		ibtrs_iu_free(sess->dummy_rx_iu, DMA_FROM_DEVICE,
			      sess->dev->device);
		sess->dummy_rx_iu = NULL;
	}

	if (sess->usr_rx_ring) {
		for (i = 0; i < USR_CON_BUF_SIZE; ++i)
			if (sess->usr_rx_ring[i])
				ibtrs_iu_free(sess->usr_rx_ring[i],
					      DMA_FROM_DEVICE,
					      sess->dev->device);
		kfree(sess->usr_rx_ring);
		sess->usr_rx_ring = NULL;
	}
}

static int alloc_sess_tx_bufs(struct ibtrs_session *sess)
{
	struct ibtrs_iu *iu;
	struct ibtrs_ops_id *id;
	struct ib_device *ib_dev = sess->dev->device;
	int i;

	sess->rdma_info_iu =
		ibtrs_iu_alloc(0, IBTRS_MSG_SESS_OPEN_RESP_LEN(
			       sess->queue_depth), GFP_KERNEL, ib_dev,
			       DMA_TO_DEVICE, true);
	if (unlikely(!sess->rdma_info_iu)) {
		ERR_RL(sess, "Can't allocate transfer buffer for "
			     "sess open resp\n");
		return -ENOMEM;
	}

	sess->ops_ids = kcalloc(sess->queue_depth, sizeof(*sess->ops_ids),
				GFP_KERNEL);
	if (unlikely(!sess->ops_ids)) {
		ERR_RL(sess, "Can't alloc ops_ids for the session\n");
		goto err;
	}

	for (i = 0; i < sess->queue_depth; ++i) {
		id = kzalloc(sizeof(*id), GFP_KERNEL);
		if (unlikely(!id)) {
			ERR_RL(sess, "Can't alloc ops id for session\n");
			goto err;
		}
		sess->ops_ids[i] = id;
	}

	for (i = 0; i < USR_MSG_CNT; ++i) {
		iu = ibtrs_iu_alloc(i, MAX_REQ_SIZE, GFP_KERNEL,
				    ib_dev, DMA_TO_DEVICE, true);
		if (!iu) {
			ERR_RL(sess, "Can't alloc tx bufs for user msgs\n");
			goto err;
		}
		list_add(&iu->list, &sess->tx_bufs);
	}

	return 0;

err:
	free_sess_tx_bufs(sess);
	return -ENOMEM;
}

static int alloc_sess_rx_bufs(struct ibtrs_session *sess)
{
	int i;

	sess->dummy_rx_iu =
		ibtrs_iu_alloc(0, IBTRS_HDR_LEN, GFP_KERNEL, sess->dev->device,
			       DMA_FROM_DEVICE, true);
	if (!sess->dummy_rx_iu) {
		ERR(sess, "Failed to allocate dummy IU to receive "
			  "immediate messages on io connections\n");
		goto err;
	}

	sess->usr_rx_ring = kcalloc(USR_CON_BUF_SIZE,
				    sizeof(*sess->usr_rx_ring), GFP_KERNEL);
	if (!sess->usr_rx_ring) {
		ERR(sess, "Alloc usr_rx_ring for session failed\n");
		goto err;
	}

	for (i = 0; i < USR_CON_BUF_SIZE; ++i) {
		sess->usr_rx_ring[i] =
			ibtrs_iu_alloc(i, MAX_REQ_SIZE, GFP_KERNEL,
				       sess->dev->device, DMA_FROM_DEVICE,
				       true);
		if (!sess->usr_rx_ring[i]) {
			ERR(sess, "Failed to allocate iu for usr_rx_ring\n");
			goto err;
		}
	}

	return 0;

err:
	free_sess_rx_bufs(sess);
	return -ENOMEM;
}

static int alloc_sess_bufs(struct ibtrs_session *sess)
{
	int err;

	err = alloc_sess_rx_bufs(sess);
	if (err)
		return err;
	else
		return alloc_sess_tx_bufs(sess);
}

static int post_io_con_recv(struct ibtrs_con *con)
{
	int i, ret;

	for (i = 0; i < con->sess->queue_depth; i++) {
		ret = ibtrs_post_recv(con, con->sess->dummy_rx_iu);
		if (unlikely(ret))
			return ret;
	}

	return 0;
}

static int post_user_con_recv(struct ibtrs_con *con)
{
	int i, ret;

	for (i = 0; i < USR_CON_BUF_SIZE; i++) {
		struct ibtrs_iu *iu = con->sess->usr_rx_ring[i];

		ret = ibtrs_post_recv(con, iu);
		if (unlikely(ret))
			return ret;
	}

	return 0;
}

static int post_recv(struct ibtrs_con *con)
{
	if (con->user)
		return post_user_con_recv(con);
	else
		return post_io_con_recv(con);

	return 0;
}

static void free_sess_bufs(struct ibtrs_session *sess)
{
	free_sess_rx_bufs(sess);
	free_sess_tx_bufs(sess);
}

static int init_transfer_bufs(struct ibtrs_con *con)
{
	int err;
	struct ibtrs_session *sess = con->sess;

	if (con->user) {
		err = alloc_sess_bufs(sess);
		if (err) {
			ERR(sess, "Alloc sess bufs failed, err: %s\n",
			    strerror(err));
			return err;
		}
	}

	return post_recv(con);
}

static void process_rdma_write_req(struct ibtrs_con *con,
				   struct ibtrs_msg_req_rdma_write *req,
				   u32 buf_id, u32 off)
{
	int ret;
	struct ibtrs_ops_id *id;
	struct ibtrs_session *sess = con->sess;

	if (unlikely(sess->state != SSM_STATE_CONNECTED ||
		     con->state != CSM_STATE_CONNECTED)) {
		ERR_RL(sess, "Processing RDMA-Write-Req request failed, "
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
		ERR_RL(sess, "Processing RDMA-Write-Req failed, work request "
		       "or scatter gather allocation failed for msg_id %d\n",
		       buf_id);
		ret = -ENOMEM;
		goto send_err_msg;
	}

	id->data_dma_addr = sess->rcv_buf_pool->rcv_bufs[buf_id].rdma_addr;
	ret = srv_ops->rdma_ev(con->sess, sess->priv, id,
			       IBTRS_SRV_RDMA_EV_WRITE_REQ,
			       sess->rcv_buf_pool->rcv_bufs[buf_id].buf, off);

	if (unlikely(ret)) {
		ERR_RL(sess, "Processing RDMA-Write-Req failed, user "
		       "module cb reported for msg_id %d, err: %s\n",
		       buf_id, strerror(ret));
		goto send_err_msg;
	}

	return;

send_err_msg:
	ret = send_io_resp_imm(con, buf_id, ret);
	if (ret < 0) {
		ERR_RL(sess, "Sending err msg for failed RDMA-Write-Req"
		       " failed, msg_id %d, err: %s\n", buf_id, strerror(ret));
		csm_schedule_event(con, CSM_EV_CON_ERROR);
	}
	ibtrs_srv_stats_dec_inflight(sess);
}

static void process_rdma_write(struct ibtrs_con *con,
			       struct ibtrs_msg_rdma_write *req,
			       u32 buf_id, u32 off)
{
	int ret;
	struct ibtrs_ops_id *id;
	struct ibtrs_session *sess = con->sess;

	if (unlikely(sess->state != SSM_STATE_CONNECTED ||
		     con->state != CSM_STATE_CONNECTED)) {
		ERR_RL(sess, "Processing RDMA-Write request failed, "
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

	ret = srv_ops->rdma_ev(sess, sess->priv, id, IBTRS_SRV_RDMA_EV_RECV,
			       sess->rcv_buf_pool->rcv_bufs[buf_id].buf, off);
	if (unlikely(ret)) {
		ERR_RL(sess, "Processing RDMA-Write failed, user module"
		       " callback reports err: %s\n", strerror(ret));
		goto send_err_msg;
	}

	return;

send_err_msg:
	ret = send_io_resp_imm(con, buf_id, ret);
	if (ret < 0) {
		ERR_RL(sess, "Processing RDMA-Write failed, sending I/O"
		       " response failed, msg_id %d, err: %s\n",
		       buf_id, strerror(ret));
		csm_schedule_event(con, CSM_EV_CON_ERROR);
	}
	ibtrs_srv_stats_dec_inflight(sess);
}

static int ibtrs_send_usr_msg_ack(struct ibtrs_con *con)
{
	struct ibtrs_session *sess;
	int err;

	sess = con->sess;

	if (unlikely(con->state != CSM_STATE_CONNECTED)) {
		ERR_RL(sess, "Sending user msg ack failed, disconnected"
			" Connection state is %s\n", csm_state_str(con->state));
		return -ECOMM;
	}
	pr_debug("Sending user message ack\n");
	err = ibtrs_write_empty_imm(con->ib_con.qp, UINT_MAX - 1,
				    IB_SEND_SIGNALED);
	if (unlikely(err)) {
		ERR_RL(sess, "Sending user Ack msg failed, err: %s\n",
		       strerror(err));
		return err;
	}

	ibtrs_heartbeat_set_send_ts(&sess->heartbeat);
	return 0;
}

static void process_msg_user(struct ibtrs_con *con,
			     struct ibtrs_msg_user *msg)
{
	int len;
	struct ibtrs_session *sess = con->sess;

	len = msg->hdr.tsize - IBTRS_HDR_LEN;
	if (unlikely(sess->state < SSM_STATE_CONNECTED || !sess->priv)) {
		ERR_RL(sess, "Sending user msg failed, session isn't ready."
			" Session state is %s\n", ssm_state_str(sess->state));
		return;
	}

	srv_ops->recv(sess, sess->priv, msg->payl, len);

	atomic64_inc(&sess->stats.user_ib_msgs.recv_msg_cnt);
	atomic64_add(len, &sess->stats.user_ib_msgs.recv_size);
}

static void process_msg_user_ack(struct ibtrs_con *con)
{
	struct ibtrs_session *sess = con->sess;

	atomic_inc(&sess->peer_usr_msg_bufs);
	wake_up(&con->sess->mu_buf_wait_q);
}

static void ibtrs_handle_write(struct ibtrs_con *con, struct ibtrs_iu *iu,
			       struct ibtrs_msg_hdr *hdr, u32 id, u32 off)
{
	struct ibtrs_session *sess = con->sess;
	int ret;

	if (unlikely(ibtrs_validate_message(sess->queue_depth, hdr))) {
		ERR(sess,
		    "Processing I/O failed, message validation failed\n");
		ret = ibtrs_post_recv(con, iu);
		if (unlikely(ret != 0))
			ERR(sess,
			    "Failed to post receive buffer to HCA, err: %s\n",
			    strerror(ret));
		goto err;
	}

	pr_debug("recv completion, type 0x%02x, tag %u, id %u, off %u\n",
	    hdr->type, iu->tag, id, off);
	print_hex_dump_debug("", DUMP_PREFIX_OFFSET, 8, 1,
			     hdr, IBTRS_HDR_LEN + 32, true);
	ret = ibtrs_post_recv(con, iu);
	if (unlikely(ret != 0)) {
		ERR(sess, "Posting receive buffer to HCA failed, err: %s\n",
		    strerror(ret));
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
		ERR(sess, "Processing I/O request failed, "
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
	struct ibtrs_con *con;
	struct ibtrs_msg_user *msg;

	w = container_of(work, struct msg_work, work);
	con = w->con;
	msg = w->msg;
	kfree(w);
	process_msg_user(con, msg);
	kfree(msg);
}

static int ibtrs_schedule_msg(struct ibtrs_con *con, struct ibtrs_msg_user *msg)
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
	queue_work(con->sess->msg_wq, &w->work);
	return 0;
}

static void ibtrs_handle_recv(struct ibtrs_con *con,  struct ibtrs_iu *iu)
{
	struct ibtrs_msg_hdr *hdr;
	struct ibtrs_msg_sess_info *req;
	struct ibtrs_session *sess = con->sess;
	int ret;
	u8 type;

	hdr = (struct ibtrs_msg_hdr *)iu->buf;
	if (unlikely(ibtrs_validate_message(sess->queue_depth, hdr)))
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
			ERR_RL(sess, "Scheduling worker of user message "
			       "to user module failed, err: %s\n",
			       strerror(ret));
			goto err1;
		}
		ret = ibtrs_post_recv(con, iu);
		if (unlikely(ret)) {
			ERR_RL(sess, "Posting receive buffer of user message "
			       "to HCA failed, err: %s\n", strerror(ret));
			goto err2;
		}
		ret = ibtrs_send_usr_msg_ack(con);
		if (unlikely(ret)) {
			ERR_RL(sess, "Sending ACK for user message failed, "
			       "err: %s\n", strerror(ret));
			goto err2;
		}
		return;
	case IBTRS_MSG_SESS_INFO:
		ret = ibtrs_post_recv(con, iu);
		if (unlikely(ret)) {
			ERR_RL(sess, "Posting receive buffer of sess info "
			       "to HCA failed, err: %s\n", strerror(ret));
			goto err2;
		}
		req = (struct ibtrs_msg_sess_info *)hdr;
		strlcpy(sess->hostname, req->hostname, sizeof(sess->hostname));
		return;
	default:
		ERR(sess, "Processing received message failed, "
		    "unknown type: 0x%02x\n", type);
		goto err1;
	}

err1:
	ibtrs_post_recv(con, iu);
err2:
	ERR(sess, "Failed to process IBTRS message\n");
	csm_schedule_event(con, CSM_EV_CON_ERROR);
}

static void add_con_to_list(struct ibtrs_session *sess, struct ibtrs_con *con)
{
	mutex_lock(&sess->lock);
	list_add_tail(&con->list, &sess->con_list);
	mutex_unlock(&sess->lock);
}

static void remove_con_from_list(struct ibtrs_con *con)
{
	if (WARN_ON(!con->sess))
		return;
	mutex_lock(&con->sess->lock);
	list_del(&con->list);
	mutex_unlock(&con->sess->lock);
}

static void close_con(struct ibtrs_con *con)
{
	struct ibtrs_session *sess = con->sess;

	pr_debug("Closing connection %p\n", con);

	if (con->user)
		cancel_delayed_work(&sess->send_heartbeat_dwork);

	cancel_work_sync(&con->cq_work);
	destroy_workqueue(con->rdma_resp_wq);

	ib_con_destroy(&con->ib_con);
	if (!con->user && !con->device_being_removed)
		rdma_destroy_id(con->cm_id);

	destroy_workqueue(con->cq_wq);

	if (con->user) {
		/* notify possible user msg ACK thread waiting for a tx iu or
		 * user msg buffer so they can check the connection state, give
		 * up waiting and put back any tx_iu reserved
		 */
		wake_up(&sess->mu_buf_wait_q);
		wake_up(&sess->mu_iu_wait_q);
		destroy_workqueue(sess->msg_wq);
	}

	con->sess->active_cnt--;
}

static void destroy_con(struct ibtrs_con *con)
{
	remove_con_from_list(con);
	kfree(con);
}

static void destroy_sess(struct kref *kref)
{
	struct ibtrs_session *sess = container_of(kref, struct ibtrs_session,
						  kref);
	struct ibtrs_con *con, *con_next;

	if (sess->cm_id)
		rdma_destroy_id(sess->cm_id);

	destroy_workqueue(sess->sm_wq);

	list_for_each_entry_safe(con, con_next, &sess->con_list, list)
		destroy_con(con);

	mutex_lock(&sess_mutex);
	list_del(&sess->list);
	mutex_unlock(&sess_mutex);
	wake_up(&sess_list_waitq);

	INFO(sess, "Session is closed\n");
	kfree(sess);
}

int ibtrs_srv_sess_get(struct ibtrs_session *sess)
{
	return kref_get_unless_zero(&sess->kref);
}

void ibtrs_srv_sess_put(struct ibtrs_session *sess)
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

static void schedule_sess_put(struct ibtrs_session *sess)
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
	queue_work(destroy_wq, &w->work);
}

static void ibtrs_srv_sysfs_put_worker(struct work_struct *work)
{
	struct ibtrs_srv_sysfs_put_work *w;

	w = container_of(work, struct ibtrs_srv_sysfs_put_work, work);
	kobject_put(&w->sess->kobj_stats);
	kobject_put(&w->sess->kobj);

	kfree(w);
}

static void ibtrs_srv_schedule_sysfs_put(struct ibtrs_session *sess)
{
	struct ibtrs_srv_sysfs_put_work *w;

	w = kmalloc(sizeof(*w), GFP_KERNEL | __GFP_REPEAT);

	if (WARN_ON(!w))
		return;

	w->sess	= sess;

	INIT_WORK(&w->work, ibtrs_srv_sysfs_put_worker);
	queue_work(destroy_wq, &w->work);
}

static void ibtrs_free_dev(struct kref *ref)
{
	struct ibtrs_device *ndev =
		container_of(ref, struct ibtrs_device, ref);

	mutex_lock(&device_list_mutex);
	list_del(&ndev->entry);
	mutex_unlock(&device_list_mutex);
	ib_session_destroy(&ndev->ib_sess);
	if (ndev->ib_sess_destroy_completion)
		complete_all(ndev->ib_sess_destroy_completion);
	kfree(ndev);
}

static struct ibtrs_device *
ibtrs_find_get_device(struct rdma_cm_id *cm_id)
{
	struct ibtrs_device *ndev;
	int err;

	mutex_lock(&device_list_mutex);
	list_for_each_entry(ndev, &device_list, entry) {
		if (ndev->device->node_guid == cm_id->device->node_guid &&
		    kref_get_unless_zero(&ndev->ref))
			goto out_unlock;
	}

	ndev = kzalloc(sizeof(*ndev), GFP_KERNEL);
	if (!ndev)
		goto out_err;

	ndev->device = cm_id->device;
	kref_init(&ndev->ref);

	err = ib_session_init(cm_id->device, &ndev->ib_sess);
	if (err)
		goto out_free;

	list_add(&ndev->entry, &device_list);
	pr_debug("added %s.\n", ndev->device->name);
out_unlock:
	mutex_unlock(&device_list_mutex);
	return ndev;

out_free:
	kfree(ndev);
out_err:
	mutex_unlock(&device_list_mutex);
	return NULL;
}

static void ibtrs_srv_destroy_ib_session(struct ibtrs_session *sess)
{
	release_cont_bufs(sess);
	free_sess_bufs(sess);
	kref_put(&sess->dev->ref, ibtrs_free_dev);
}

static void process_err_wc(struct ibtrs_con *con, struct ib_wc *wc)
{
	struct ibtrs_iu *iu;

	if (wc->wr_id == (uintptr_t)&con->ib_con.beacon) {
		pr_debug("beacon received for con %p\n", con);
		csm_schedule_event(con, CSM_EV_BEACON_COMPLETED);
		return;
	}

	/* only wc->wr_id is ensured to be correct in erroneous WCs,
	 * we can't rely on wc->opcode, use iu->direction to determine if it's
	 * an tx or rx IU
	 */
	iu = (struct ibtrs_iu *)wc->wr_id;
	if (iu && iu->direction == DMA_TO_DEVICE &&
	    iu != con->sess->rdma_info_iu)
		put_tx_iu(con->sess, iu);

	if (wc->status != IB_WC_WR_FLUSH_ERR ||
	    (con->state != CSM_STATE_CLOSING &&
	     con->state != CSM_STATE_FLUSHING)) {
		/* suppress flush errors when the connection has
		 * just called rdma_disconnect() and is in
		 * DISCONNECTING state waiting for the second
		 * CM_DISCONNECTED event
		 */
		ERR_RL(con->sess, "%s (wr_id: 0x%llx,"
		       " type: %s, vendor_err: 0x%x, len: %u)\n",
		       ib_wc_status_msg(wc->status), wc->wr_id,
		       ib_wc_opcode_str(wc->opcode),
		       wc->vendor_err, wc->byte_len);
	}
	csm_schedule_event(con, CSM_EV_CON_ERROR);
}

static int process_wcs(struct ibtrs_con *con, struct ib_wc *wcs, size_t len)
{
	int i, ret;
	struct ibtrs_iu *iu;
	struct ibtrs_session *sess = con->sess;

	for (i = 0; i < len; i++) {
		struct ib_wc wc = wcs[i];

		if (unlikely(wc.status != IB_WC_SUCCESS)) {
			process_err_wc(con, &wc);
			continue;
		}

		/* pr_debug("cq complete with wr_id 0x%llx, len %u "
		 *  "status %d (%s) type %d (%s)\n", wc.wr_id,
		 *  wc.byte_len, wc.status, ib_wc_status_msg(wc.status),
		 *  wc.opcode, ib_wc_opcode_str(wc.opcode));
		 */

		switch (wc.opcode) {
		case IB_WC_SEND:
			iu = (struct ibtrs_iu *)(uintptr_t)wc.wr_id;
			if (iu == con->sess->rdma_info_iu)
				break;
			put_tx_iu(sess, iu);
			if (con->user)
				wake_up(&sess->mu_iu_wait_q);
			break;

		case IB_WC_RECV_RDMA_WITH_IMM: {
			u32 imm, id, off;
			struct ibtrs_msg_hdr *hdr;

			ibtrs_set_last_heartbeat(&sess->heartbeat);

			iu = (struct ibtrs_iu *)(uintptr_t)wc.wr_id;
			imm = be32_to_cpu(wc.ex.imm_data);
			if (imm == UINT_MAX) {
				ret = ibtrs_post_recv(con, iu);
				if (unlikely(ret != 0)) {
					ERR(sess, "post receive buffer failed,"
					    " err: %s\n", strerror(ret));
					return ret;
				}
				break;
			} else if (imm == UINT_MAX - 1) {
				ret = ibtrs_post_recv(con, iu);
				if (unlikely(ret))
					ERR_RL(sess, "Posting receive buffer of"
					       " user Ack msg to HCA failed,"
					       " err: %s\n", strerror(ret));
				process_msg_user_ack(con);
				break;
			}
			id = imm >> sess->off_len;
			off = imm & sess->off_mask;

			if (id > sess->queue_depth || off > rcv_buf_size) {
				ERR(sess, "Processing I/O failed, contiguous "
				    "buf addr is out of reserved area\n");
				ret = ibtrs_post_recv(con, iu);
				if (unlikely(ret != 0))
					ERR(sess, "Processing I/O failed, "
					    "post receive buffer failed, "
					    "err: %s\n", strerror(ret));
				return -EIO;
			}

			hdr = (struct ibtrs_msg_hdr *)
				(sess->rcv_buf_pool->rcv_bufs[id].buf + off);

			ibtrs_handle_write(con, iu, hdr, id, off);
			break;
		}

		case IB_WC_RDMA_WRITE:
			break;

		case IB_WC_RECV: {
			struct ibtrs_msg_hdr *hdr;

			ibtrs_set_last_heartbeat(&sess->heartbeat);
			iu = (struct ibtrs_iu *)(uintptr_t)wc.wr_id;
			hdr = (struct ibtrs_msg_hdr *)iu->buf;
			ibtrs_deb_msg_hdr("Received: ", hdr);
			ibtrs_handle_recv(con, iu);
			break;
		}

		default:
			ERR(sess, "Processing work completion failed,"
			    " WC has unknown opcode: %s\n",
			    ib_wc_opcode_str(wc.opcode));
			return -EINVAL;
		}
	}
	return 0;
}

static void ibtrs_srv_update_wc_stats(struct ibtrs_con *con, int cnt)
{
	int old_max = atomic_read(&con->sess->stats.wc_comp.max_wc_cnt);
	int act_max;

	while (cnt > old_max) {
		act_max = atomic_cmpxchg(&con->sess->stats.wc_comp.max_wc_cnt,
					 old_max, cnt);
		if (likely(act_max == old_max))
			break;
		old_max = act_max;
	}

	atomic64_inc(&con->sess->stats.wc_comp.calls);
	atomic64_add(cnt, &con->sess->stats.wc_comp.total_wc_cnt);
}

static int get_process_wcs(struct ibtrs_con *con, int *total_cnt)
{
	int cnt, err;

	do {
		cnt = ib_poll_cq(con->ib_con.cq, ARRAY_SIZE(con->wcs),
				 con->wcs);
		if (unlikely(cnt < 0)) {
			ERR(con->sess, "Polling completion queue failed, "
			    "err: %s\n", strerror(cnt));
			return cnt;
		}

		if (likely(cnt > 0)) {
			err = process_wcs(con, con->wcs, cnt);
			*total_cnt += cnt;
			if (unlikely(err))
				return err;
		}
	} while (cnt > 0);

	return 0;
}

static void wrapper_handle_cq_comp(struct work_struct *work)
{
	int err;
	struct ibtrs_con *con = container_of(work, struct ibtrs_con, cq_work);
	struct ibtrs_session *sess = con->sess;
	int total_cnt = 0;

	if (unlikely(con->state == CSM_STATE_CLOSED)) {
		ERR(sess, "Retrieving work completions from completion"
		    " queue failed, connection is disconnected\n");
		goto error;
	}

	err = get_process_wcs(con, &total_cnt);
	if (unlikely(err))
		goto error;

	while ((err = ib_req_notify_cq(con->ib_con.cq, IB_CQ_NEXT_COMP |
				       IB_CQ_REPORT_MISSED_EVENTS)) > 0) {
		pr_debug("Missed %d CQ notifications, processing missed WCs...\n",
		    err);
		err = get_process_wcs(con, &total_cnt);
		if (unlikely(err))
			goto error;
	}

	if (unlikely(err))
		goto error;

	ibtrs_srv_update_wc_stats(con, total_cnt);
	return;

error:
	csm_schedule_event(con, CSM_EV_CON_ERROR);
}

static void cq_event_handler(struct ib_cq *cq, void *ctx)
{
	struct ibtrs_con *con = ctx;

	/* queue_work() can return False here.
	 * The work can be already queued, When CQ notifications were already
	 * activiated and are activated again after the beacon was posted.
	 */
	if (con->state != CSM_STATE_CLOSED)
		queue_work(con->cq_wq, &con->cq_work);
}

static int accept(struct ibtrs_con *con)
{
	struct rdma_conn_param conn_param;
	int ret;
	struct ibtrs_session *sess = con->sess;

	memset(&conn_param, 0, sizeof(conn_param));
	conn_param.retry_count = retry_count;

	if (con->user)
		conn_param.rnr_retry_count = 7;

	ret = rdma_accept(con->cm_id, &conn_param);
	if (ret) {
		ERR(sess, "Accepting RDMA connection request failed,"
		    " err: %s\n", strerror(ret));
		return ret;
	}

	return 0;
}

static struct ibtrs_session *
__create_sess(struct rdma_cm_id *cm_id, const struct ibtrs_msg_sess_open *req)
{
	struct ibtrs_session *sess;
	int err;

	sess = kzalloc(sizeof(*sess), GFP_KERNEL);
	if (!sess) {
		err = -ENOMEM;
		goto out;
	}

	err = ibtrs_addr_to_str(&cm_id->route.addr.dst_addr, sess->addr,
				sizeof(sess->addr));
	if (err < 0)
		goto err1;

	sess->est_cnt = 0;
	sess->state_in_sysfs = false;
	sess->cur_cq_vector = -1;
	INIT_LIST_HEAD(&sess->con_list);
	mutex_init(&sess->lock);

	INIT_LIST_HEAD(&sess->tx_bufs);
	spin_lock_init(&sess->tx_bufs_lock);

	err = ib_get_max_wr_queue_size(cm_id->device);
	if (err < 0)
		goto err1;

	sess->wq_size = err - 1;

	sess->queue_depth		= sess_queue_depth;
	sess->con_cnt			= req->con_cnt;
	sess->ver			= min_t(u8, req->ver, IBTRS_VERSION);
	sess->primary_port_num		= cm_id->port_num;

	init_waitqueue_head(&sess->mu_iu_wait_q);
	init_waitqueue_head(&sess->mu_buf_wait_q);
	ibtrs_set_heartbeat_timeout(&sess->heartbeat,
				    default_heartbeat_timeout_ms <
				    MIN_HEARTBEAT_TIMEOUT_MS ?
				    MIN_HEARTBEAT_TIMEOUT_MS :
				    default_heartbeat_timeout_ms);
	atomic64_set(&sess->heartbeat.send_ts_ms, 0);
	atomic64_set(&sess->heartbeat.recv_ts_ms, 0);
	sess->heartbeat.addr = sess->addr;
	sess->heartbeat.hostname = sess->hostname;

	atomic_set(&sess->peer_usr_msg_bufs, USR_MSG_CNT);
	sess->dev = ibtrs_find_get_device(cm_id);
	if (!sess->dev) {
		err = -ENOMEM;
		WRN(sess, "Failed to alloc ibtrs_device\n");
		goto err1;
	}
	err = setup_cont_bufs(sess);
	if (err)
		goto err2;

	memcpy(sess->uuid, req->uuid, IBTRS_UUID_SIZE);
	err = ssm_init(sess);
	if (err) {
		WRN(sess, "Failed to initialize the session state machine\n");
		goto err3;
	}

	kref_init(&sess->kref);
	init_waitqueue_head(&sess->bufs_wait);

	list_add(&sess->list, &sess_list);
	INFO(sess, "IBTRS Session created (queue depth: %d)\n",
	     sess->queue_depth);

	return sess;

err3:
	release_cont_bufs(sess);
err2:
	kref_put(&sess->dev->ref, ibtrs_free_dev);
err1:
	kfree(sess);
out:
	return ERR_PTR(err);
}

inline const char *ibtrs_srv_get_sess_hostname(struct ibtrs_session *sess)
{
	return sess->hostname;
}
EXPORT_SYMBOL(ibtrs_srv_get_sess_hostname);

inline const char *ibtrs_srv_get_sess_addr(struct ibtrs_session *sess)
{
	return sess->addr;
}
EXPORT_SYMBOL(ibtrs_srv_get_sess_addr);

inline int ibtrs_srv_get_sess_qdepth(struct ibtrs_session *sess)
{
	return sess->queue_depth;
}
EXPORT_SYMBOL(ibtrs_srv_get_sess_qdepth);

static struct ibtrs_session *__find_active_sess(const char *uuid)
{
	struct ibtrs_session *n;

	list_for_each_entry(n, &sess_list, list) {
		if (!memcmp(n->uuid, uuid, sizeof(n->uuid)) &&
		    n->state != SSM_STATE_CLOSING &&
		    n->state != SSM_STATE_CLOSED)
			return n;
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
		pr_err("Rejecting RDMA connection request failed, err: %s\n",
		       strerror(ret));

	return ret;
}

static int find_next_bit_ring(int cur)
{
	int v = cpumask_next(cur, &cq_affinity_mask);

	if (v >= nr_cpu_ids)
		v = cpumask_first(&cq_affinity_mask);
	return v;
}

static int ibtrs_srv_get_next_cq_vector(struct ibtrs_session *sess)
{
	sess->cur_cq_vector = find_next_bit_ring(sess->cur_cq_vector);

	return sess->cur_cq_vector;
}

static void ssm_create_con_worker(struct work_struct *work)
{
	struct ssm_create_con_work *ssm_w =
			container_of(work, struct ssm_create_con_work, work);
	struct ibtrs_session *sess = ssm_w->sess;
	struct rdma_cm_id *cm_id = ssm_w->cm_id;
	bool user = ssm_w->user;
	struct ibtrs_con *con;
	int ret;
	u16 cq_size, wr_queue_size;

	kfree(ssm_w);

	if (sess->state == SSM_STATE_CLOSING ||
	    sess->state == SSM_STATE_CLOSED) {
		WRN(sess, "Creating connection failed, "
		    "session is being closed\n");
		ret = -ECOMM;
		goto err_reject;
	}

	con = kzalloc(sizeof(*con), GFP_KERNEL);
	if (!con) {
		ERR(sess, "Creating connection failed, "
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

	con->cq_vector = ibtrs_srv_get_next_cq_vector(sess);

	con->ib_con.addr = sess->addr;
	con->ib_con.hostname = sess->hostname;
	ret = ib_con_init(&con->ib_con, con->cm_id,
			  1, cq_event_handler, con, con->cq_vector, cq_size,
			  wr_queue_size, &con->sess->dev->ib_sess);
	if (ret)
		goto err_init;

	INIT_WORK(&con->cq_work, wrapper_handle_cq_comp);
	if (con->user)
		con->cq_wq = alloc_ordered_workqueue("%s",
						     WQ_HIGHPRI,
						     "ibtrs_srv_wq");
	else
		con->cq_wq = alloc_workqueue("%s",
					     WQ_CPU_INTENSIVE | WQ_HIGHPRI, 0,
					     "ibtrs_srv_wq");
	if (!con->cq_wq) {
		ERR(sess, "Creating connection failed, can't allocate "
		    "work queue for completion queue, err: %s\n",
		    strerror(ret));
		goto err_wq1;
	}

	con->rdma_resp_wq = alloc_workqueue("%s", 0, WQ_HIGHPRI,
					    "ibtrs_rdma_resp");

	if (!con->rdma_resp_wq) {
		ERR(sess, "Creating connection failed, can't allocate"
		    " work queue for send response, err: %s\n", strerror(ret));
		goto err_wq2;
	}

	ret = init_transfer_bufs(con);
	if (ret) {
		ERR(sess, "Creating connection failed, can't init"
		    " transfer buffers, err: %s\n", strerror(ret));
		goto err_buf;
	}

	csm_init(con);
	add_con_to_list(sess, con);

	cm_id->context = con;
	if (con->user) {
		con->sess->msg_wq = alloc_ordered_workqueue("sess_msg_wq", 0);
		if (!con->sess->msg_wq) {
			ERR(con->sess, "Failed to create user message"
			    " workqueue\n");
			ret = -ENOMEM;
			goto err_accept;
		}
	}

	pr_debug("accept request\n");
	ret = accept(con);
	if (ret)
		goto err_msg;

	if (con->user)
		con->sess->cm_id = cm_id;

	con->sess->active_cnt++;

	return;
err_msg:
	if (con->user)
		destroy_workqueue(con->sess->msg_wq);
err_accept:
	cm_id->context = NULL;
	remove_con_from_list(con);
err_buf:
	destroy_workqueue(con->rdma_resp_wq);
err_wq2:
	destroy_workqueue(con->cq_wq);
err_wq1:
	ib_con_destroy(&con->ib_con);
err_init:
	kfree(con);
err_reject:
	rdma_destroy_id(cm_id);

	ssm_schedule_event(sess, SSM_EV_CON_EST_ERR);
}

static int ssm_schedule_create_con(struct ibtrs_session *sess,
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

static int rdma_con_establish(struct rdma_cm_id *cm_id, const void *data,
			      size_t size)
{
	struct ibtrs_session *sess;
	int ret;
	const char *uuid = NULL;
	const struct ibtrs_msg_hdr *hdr = data;
	bool user = false;

	if (unlikely(!srv_ops_are_valid(srv_ops))) {
		pr_err("Establishing connection failed, "
		       "no user module registered!\n");
		ret = -ECOMM;
		goto err_reject;
	}

	if (unlikely((size < sizeof(struct ibtrs_msg_con_open)) ||
		     (size < sizeof(struct ibtrs_msg_sess_open)) ||
		     ibtrs_validate_message(0, hdr))) {
		pr_err("Establishing connection failed, "
		       "connection request payload size unexpected "
		       "%zu != %lu or %lu\n", size,
		       sizeof(struct ibtrs_msg_con_open),
		       sizeof(struct ibtrs_msg_sess_open));
		ret = -EINVAL;
		goto err_reject;
	}

	if (hdr->type == IBTRS_MSG_SESS_OPEN)
		uuid = ((struct ibtrs_msg_sess_open *)data)->uuid;
	else if (hdr->type == IBTRS_MSG_CON_OPEN)
		uuid = ((struct ibtrs_msg_con_open *)data)->uuid;

	mutex_lock(&sess_mutex);
	sess = __find_active_sess(uuid);
	if (sess) {
		if (unlikely(hdr->type == IBTRS_MSG_SESS_OPEN)) {
			INFO(sess, "Connection request rejected, "
			     "session already exists\n");
			mutex_unlock(&sess_mutex);
			ret = -EEXIST;
			goto err_reject;
		}
		if (!ibtrs_srv_sess_get(sess)) {
			INFO(sess, "Connection request rejected,"
			     " session is being closed\n");
			mutex_unlock(&sess_mutex);
			ret = -EINVAL;
			goto err_reject;
		}
	} else {
		if (unlikely(hdr->type == IBTRS_MSG_CON_OPEN)) {
			mutex_unlock(&sess_mutex);
			pr_info("Connection request rejected,"
				" received con_open msg but no active session"
				" exists.\n");
			ret = -EINVAL;
			goto err_reject;
		}

		sess = __create_sess(cm_id, (struct ibtrs_msg_sess_open *)data);
		if (IS_ERR(sess)) {
			mutex_unlock(&sess_mutex);
			ret = PTR_ERR(sess);
			pr_err("Establishing connection failed, "
			       "creating local session resource failed, err:"
			       " %s\n", strerror(ret));
			goto err_reject;
		}
		ibtrs_srv_sess_get(sess);
		user = true;
	}

	mutex_unlock(&sess_mutex);

	ret = ssm_schedule_create_con(sess, cm_id, user);
	if (ret) {
		ERR(sess, "Unable to schedule creation of connection,"
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

static int ibtrs_srv_rdma_cm_ev_handler(struct rdma_cm_id *cm_id,
					struct rdma_cm_event *event)
{
	struct ibtrs_con *con = cm_id->context;
	int ret = 0;

	pr_debug("cma_event type %d cma_id %p(%s) on con: %p\n", event->event,
	    cm_id, rdma_event_msg(event->event), con);
	if (!con && event->event != RDMA_CM_EVENT_CONNECT_REQUEST) {
		pr_info("Ignore cma_event type %d cma_id %p(%s)\n",
			event->event, cm_id, rdma_event_msg(event->event));
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

		ERR_RL(con->sess,
		       "IB Device was removed, disconnecting session.\n");

		con->device_being_removed = true;
		init_completion(&dc);
		con->sess->dev->ib_sess_destroy_completion = &dc;

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
		ERR_RL(con->sess, "CM error (CM event: %s, err: %s)\n",
		       rdma_event_msg(event->event), strerror(event->status));

		csm_schedule_event(con, CSM_EV_CON_ERROR);
		break;
	case RDMA_CM_EVENT_REJECTED:
		/* reject status is defined in enum, not errno */
		ERR_RL(con->sess,
		       "Connection rejected (CM event: %s, err: %s)\n",
		       rdma_event_msg(event->event),
		       rdma_reject_msg(cm_id, event->status));
		csm_schedule_event(con, CSM_EV_CON_ERROR);
		break;
	default:
		WRN(con->sess, "Ignoring unexpected CM event %s, err %s\n",
		    rdma_event_msg(event->event), strerror(event->status));
		break;
	}
	return ret;
}

static int ibtrs_srv_cm_init(struct rdma_cm_id **cm_id, struct sockaddr *addr,
			     enum rdma_port_space ps)
{
	int ret;

	*cm_id = rdma_create_id(&init_net, ibtrs_srv_rdma_cm_ev_handler, NULL,
				ps, IB_QPT_RC);
	if (IS_ERR(*cm_id)) {
		ret = PTR_ERR(*cm_id);
		pr_err("Creating id for RDMA connection failed, err: %s\n",
		       strerror(ret));
		goto err_out;
	}
	pr_debug("created cm_id %p\n", *cm_id);
	ret = rdma_bind_addr(*cm_id, addr);
	if (ret) {
		pr_err("Binding RDMA address failed, err: %s\n", strerror(ret));
		goto err_cm;
	}
	pr_debug("rdma_bind_addr successful\n");
	/* we currently accept 64 rdma_connects */
	ret = rdma_listen(*cm_id, 64);
	if (ret) {
		pr_err("Listening on RDMA connection failed, err: %s\n",
		       strerror(ret));
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
		    be64_to_cpu(rdma_get_service_id(*cm_id, addr)));
		break;
	default:
		pr_debug("listening on address family %u\n", addr->sa_family);
	}

	return 0;

err_cm:
	rdma_destroy_id(*cm_id);
err_out:
	return ret;
}

static int ibtrs_srv_rdma_init(void)
{
	int ret = 0;
	struct sockaddr_in6 sin = {
		.sin6_family	= AF_INET6,
		.sin6_addr	= IN6ADDR_ANY_INIT,
		.sin6_port	= htons(IBTRS_SERVER_PORT),
	};
	struct sockaddr_ib sib = {
		.sib_family			= AF_IB,
		.sib_addr.sib_subnet_prefix	= 0ULL,
		.sib_addr.sib_interface_id	= 0ULL,
		.sib_sid	= cpu_to_be64(RDMA_IB_IP_PS_IB |
					      IBTRS_SERVER_PORT),
		.sib_sid_mask	= cpu_to_be64(0xffffffffffffffffULL),
		.sib_pkey	= cpu_to_be16(0xffff),
	};

	/*
	 * We accept both IPoIB and IB connections, so we need to keep
	 * two cm id's, one for each socket type and port space.
	 * If the cm initialization of one of the id's fails, we abort
	 * everything.
	 */

	ret = ibtrs_srv_cm_init(&cm_id_ip, (struct sockaddr *)&sin,
				RDMA_PS_TCP);
	if (ret)
		return ret;

	ret = ibtrs_srv_cm_init(&cm_id_ib, (struct sockaddr *)&sib, RDMA_PS_IB);
	if (ret)
		goto err_cm_ib;

	return ret;

err_cm_ib:
	rdma_destroy_id(cm_id_ip);
	return ret;
}

static void ibtrs_srv_destroy_buf_pool(void)
{
	struct ibtrs_rcv_buf_pool *pool, *pool_next;

	mutex_lock(&buf_pool_mutex);
	list_for_each_entry_safe(pool, pool_next, &free_buf_pool_list, list) {
		list_del(&pool->list);
		nr_free_buf_pool--;
		free_recv_buf_pool(pool);
	}
	mutex_unlock(&buf_pool_mutex);
}

static void ibtrs_srv_alloc_ini_buf_pool(void)
{
	struct ibtrs_rcv_buf_pool *pool;
	int i;

	if (init_pool_size == 0)
		return;

	pr_info("Trying to allocate RDMA buffers pool for %d client(s)\n",
		init_pool_size);
	for (i = 0; i < init_pool_size; i++) {
		pool = alloc_rcv_buf_pool();
		if (!pool) {
			pr_err("Failed to allocate initial RDMA buffer pool"
			       " #%d\n", i + 1);
			break;
		}
		mutex_lock(&buf_pool_mutex);
		list_add(&pool->list, &free_buf_pool_list);
		nr_free_buf_pool++;
		nr_total_buf_pool++;
		mutex_unlock(&buf_pool_mutex);
		pr_debug("Allocated buffer pool #%d\n", i);
	}

	pr_info("Allocated RDMA buffers pool for %d client(s)\n", i);
}

int ibtrs_srv_register(const struct ibtrs_srv_ops *ops)
{
	int err;

	if (srv_ops) {
		pr_err("Registration failed, module %s already registered,"
		       " only 1 user module supported\n",
		srv_ops->owner->name);
		return -ENOTSUPP;
	}

	if (unlikely(!srv_ops_are_valid(ops))) {
		pr_err("Registration failed, user module supploed invalid ops"
		       " parameter\n");
		return -EFAULT;
	}

	ibtrs_srv_alloc_ini_buf_pool();

	err = ibtrs_srv_rdma_init();
	if (err) {
		pr_err("Can't init RDMA resource, err: %s\n", strerror(err));
		return err;
	}
	srv_ops = ops;

	return 0;
}
EXPORT_SYMBOL(ibtrs_srv_register);

inline void ibtrs_srv_queue_close(struct ibtrs_session *sess)
{
	ssm_schedule_event(sess, SSM_EV_SYSFS_DISCONNECT);
}

static void close_sessions(void)
{
	struct ibtrs_session *sess;

	mutex_lock(&sess_mutex);
	list_for_each_entry(sess, &sess_list, list) {
		if (!ibtrs_srv_sess_get(sess))
			continue;
		ssm_schedule_event(sess, SSM_EV_SESS_CLOSE);
		ibtrs_srv_sess_put(sess);
	}
	mutex_unlock(&sess_mutex);

	wait_event(sess_list_waitq, list_empty(&sess_list));
}

void ibtrs_srv_unregister(const struct ibtrs_srv_ops *ops)
{
	if (!srv_ops) {
		pr_warn("Nothing to unregister - srv_ops = NULL\n");
		return;
	}

	/* TODO: in order to support registration of multiple modules,
	 * introduce a list with srv_ops and search for the correct
	 * one.
	 */

	if (srv_ops != ops) {
		pr_err("Ops is not the ops we have registered\n");
		return;
	}

	rdma_destroy_id(cm_id_ip);
	cm_id_ip = NULL;
	rdma_destroy_id(cm_id_ib);
	cm_id_ib = NULL;
	close_sessions();
	flush_workqueue(destroy_wq);
	ibtrs_srv_destroy_buf_pool();
	srv_ops = NULL;
}
EXPORT_SYMBOL(ibtrs_srv_unregister);

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

static void csm_init(struct ibtrs_con *con)
{
	pr_debug("initializing csm to %s\n", csm_state_str(CSM_STATE_REQUESTED));
	csm_set_state(con, CSM_STATE_REQUESTED);
}

static int send_msg_sess_open_resp(struct ibtrs_con *con)
{
	struct ibtrs_msg_sess_open_resp *msg;
	int err;
	struct ibtrs_session *sess = con->sess;

	msg = sess->rdma_info_iu->buf;

	fill_ibtrs_msg_sess_open_resp(msg, con);

	err = ibtrs_post_send(con->ib_con.qp, con->sess->dev->ib_sess.mr,
			      sess->rdma_info_iu, msg->hdr.tsize);
	if (unlikely(err))
		ERR(sess, "Sending sess open resp failed, "
			  "posting msg to QP failed, err: %s\n", strerror(err));

	return err;
}

static void queue_heartbeat_dwork(struct ibtrs_session *sess)
{
	ibtrs_set_last_heartbeat(&sess->heartbeat);
	WARN_ON(!queue_delayed_work(sess->sm_wq,
				    &sess->send_heartbeat_dwork,
				    HEARTBEAT_INTV_JIFFIES));
	WARN_ON(!queue_delayed_work(sess->sm_wq,
				    &sess->check_heartbeat_dwork,
				    HEARTBEAT_INTV_JIFFIES));
}

static void csm_requested(struct ibtrs_con *con, enum csm_ev ev)
{
	struct ibtrs_session *sess = con->sess;
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
		ERR(sess, "Connection received unexpected event %s "
		    "in %s state.\n", csm_ev_str(ev), csm_state_str(state));
	}
}

static void csm_connected(struct ibtrs_con *con, enum csm_ev ev)
{
	struct ibtrs_session *sess = con->sess;
	enum csm_state state = con->state;

	pr_debug("con %p, event %s\n", con, csm_ev_str(ev));
	switch (ev) {
	case CSM_EV_CON_ERROR:
	case CSM_EV_SESS_CLOSING: {
		int err;

		csm_set_state(con, CSM_STATE_CLOSING);
		err = rdma_disconnect(con->cm_id);
		if (err)
			ERR(sess, "Connection received event %s "
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
		int err, cnt = 0;

		csm_set_state(con, CSM_STATE_FLUSHING);
		err = rdma_disconnect(con->cm_id);
		if (err)
			ERR(sess, "Connection received event %s "
			    "in %s state, new state is %s, but failed to "
			    "disconnect connection.\n", csm_ev_str(ev),
			    csm_state_str(state), csm_state_str(con->state));

		wait_event(sess->bufs_wait,
			   !atomic_read(&sess->stats.rdma_stats.inflight));
		pr_debug("posting beacon on con %p\n", con);
		err = post_beacon(&con->ib_con);
		if (err) {
			ERR(sess, "Connection received event %s "
			    "in %s state, new state is %s but failed to post"
			    " beacon, closing connection.\n", csm_ev_str(ev),
			    csm_state_str(state), csm_state_str(con->state));
			goto destroy;
		}

		err = ibtrs_request_cq_notifications(&con->ib_con);
		if (unlikely(err < 0)) {
			WRN(con->sess, "Requesting CQ Notification for"
			    " ib_con failed. Connection will be destroyed\n");
			goto destroy;
		} else if (err > 0) {
			err = get_process_wcs(con, &cnt);
			if (unlikely(err))
				goto destroy;
			break;
		}
		break;

destroy:
		csm_set_state(con, CSM_STATE_CLOSED);
		close_con(con);
		ssm_schedule_event(sess, SSM_EV_CON_DISCONNECTED);

		break;
		}
	default:
		ERR(sess, "Connection received unexpected event %s "
		    "in %s state\n", csm_ev_str(ev), csm_state_str(state));
	}
}

static void csm_closing(struct ibtrs_con *con, enum csm_ev ev)
{
	struct ibtrs_session *sess = con->sess;
	enum csm_state state = con->state;

	pr_debug("con %p, event %s\n", con, csm_ev_str(ev));
	switch (ev) {
	case CSM_EV_DEVICE_REMOVAL:
	case CSM_EV_CON_DISCONNECTED: {
		int err, cnt = 0;

		csm_set_state(con, CSM_STATE_FLUSHING);

		wait_event(sess->bufs_wait,
			   !atomic_read(&sess->stats.rdma_stats.inflight));

		pr_debug("posting beacon on con %p\n", con);
		if (post_beacon(&con->ib_con)) {
			ERR(sess, "Connection received event %s "
			    "in %s state, new state is %s but failed to post"
			    " beacon, closing connection.\n", csm_ev_str(ev),
			    csm_state_str(state), csm_state_str(con->state));
			goto destroy;
		}

		err = ibtrs_request_cq_notifications(&con->ib_con);
		if (unlikely(err < 0)) {
			WRN(con->sess, "Requesting CQ Notification for"
			    " ib_con failed. Connection will be destroyed\n");
			goto destroy;
		} else if (err > 0) {
			err = get_process_wcs(con, &cnt);
			if (unlikely(err))
				goto destroy;
			break;
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
		ERR(sess, "Connection received unexpected event %s "
		    "in %s state\n", csm_ev_str(ev), csm_state_str(state));
	}
}

static void csm_flushing(struct ibtrs_con *con, enum csm_ev ev)
{
	struct ibtrs_session *sess = con->sess;
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
		ERR(sess, "Connection received unexpected event %s "
		    "in %s state\n", csm_ev_str(ev), csm_state_str(state));
	}
}

static void csm_closed(struct ibtrs_con *con, enum csm_ev ev)
{
	/* in this state, we ignore every event scheduled for this connection
	 * and just wait for the session workqueue to be flushed and the
	 * connection freed
	 */
	pr_debug("con %p, event %s\n", con, csm_ev_str(ev));
}

typedef void (ibtrs_srv_csm_ev_handler_fn)(struct ibtrs_con *, enum csm_ev);

static ibtrs_srv_csm_ev_handler_fn *ibtrs_srv_csm_ev_handlers[] = {
	[CSM_STATE_REQUESTED]		= csm_requested,
	[CSM_STATE_CONNECTED]		= csm_connected,
	[CSM_STATE_CLOSING]		= csm_closing,
	[CSM_STATE_FLUSHING]		= csm_flushing,
	[CSM_STATE_CLOSED]		= csm_closed,
};

static inline void ibtrs_srv_csm_ev_handle(struct ibtrs_con *con,
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

static void csm_schedule_event(struct ibtrs_con *con, enum csm_ev ev)
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

static void sess_schedule_csm_event(struct ibtrs_session *sess, enum csm_ev ev)
{
	struct ibtrs_con *con;

	list_for_each_entry(con, &sess->con_list, list)
		csm_schedule_event(con, ev);
}

static void remove_sess_from_sysfs(struct ibtrs_session *sess)
{
	if (!sess->state_in_sysfs)
		return;

	kobject_del(&sess->kobj_stats);
	kobject_del(&sess->kobj);
	sess->state_in_sysfs = false;

	ibtrs_srv_schedule_sysfs_put(sess);
}

static __always_inline int
__ibtrs_srv_request_cq_notifications(struct ibtrs_con *con)
{
	return ibtrs_request_cq_notifications(&con->ib_con);
}

static int ibtrs_srv_request_cq_notifications(struct ibtrs_session *sess)
{
	struct ibtrs_con *con;
	int err, cnt = 0;

	list_for_each_entry(con, &sess->con_list, list)  {
		if (con->state == CSM_STATE_CONNECTED) {
			err = __ibtrs_srv_request_cq_notifications(con);
			if (unlikely(err < 0)) {
				return err;
			} else if (err > 0) {
				err = get_process_wcs(con, &cnt);
				if (unlikely(err))
					return err;
			}
		}
	}

	return 0;
}

static void ssm_idle(struct ibtrs_session *sess, enum ssm_ev ev)
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
			ibtrs_srv_destroy_ib_session(sess);
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
				ERR(sess,
				    "Session sysfs files already exist,"
				    " possibly a user-space process is"
				    " holding them\n");
			else
				ERR(sess,
				    "Create session sysfs files failed,"
				    " err: %s\n", strerror(err));
			goto destroy;
		}

		sess->state_in_sysfs = true;

		err = ibtrs_srv_sess_ev(sess, IBTRS_SRV_SESS_EV_CONNECTED);
		if (err) {
			ERR(sess, "Notifying user session event"
			    " failed, err: %s\n. Session is closed",
			    strerror(err));
			goto destroy;
		}

		ssm_set_state(sess, SSM_STATE_CONNECTED);
		err = ibtrs_srv_request_cq_notifications(sess);
		if (err) {
			ERR(sess, "Requesting CQ completion notifications"
			    " failed, err: %s. Session will be closed.\n",
			    strerror(err));
			goto destroy;
		}

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
		ERR(sess, "Session received unexpected event %s "
		    "in %s state.\n", ssm_ev_str(ev), ssm_state_str(state));
	}
}

static void ssm_connected(struct ibtrs_session *sess, enum ssm_ev ev)
{
	enum ssm_state state = sess->state;

	pr_debug("sess %p, event %s, est_cnt=%d\n", sess, ssm_ev_str(ev),
	    sess->est_cnt);
	switch (ev) {
	case SSM_EV_CON_DISCONNECTED:
		remove_sess_from_sysfs(sess);
		sess->est_cnt--;

		ssm_set_state(sess, SSM_STATE_CLOSING);
		ibtrs_srv_sess_ev(sess, IBTRS_SRV_SESS_EV_DISCONNECTING);
		break;
	case SSM_EV_SESS_CLOSE:
	case SSM_EV_SYSFS_DISCONNECT:
		remove_sess_from_sysfs(sess);
		ssm_set_state(sess, SSM_STATE_CLOSING);
		ibtrs_srv_sess_ev(sess, IBTRS_SRV_SESS_EV_DISCONNECTING);

		sess_schedule_csm_event(sess, CSM_EV_SESS_CLOSING);
		break;
	default:
		ERR(sess, "Session received unexpected event %s "
		    "in %s state.\n", ssm_ev_str(ev), ssm_state_str(state));
	}
}

static void ssm_closing(struct ibtrs_session *sess, enum ssm_ev ev)
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
			ibtrs_srv_destroy_ib_session(sess);
			ssm_set_state(sess, SSM_STATE_CLOSED);
			ibtrs_srv_sess_ev(sess, IBTRS_SRV_SESS_EV_DISCONNECTED);
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
		ERR(sess, "Session received unexpected event %s "
		    "in %s state.\n", ssm_ev_str(ev), ssm_state_str(state));
	}
}

static void ssm_closed(struct ibtrs_session *sess, enum ssm_ev ev)
{
	/* in this state, we ignore every event and wait for the session
	 * to be destroyed
	 */
	pr_debug("sess %p, event %s, est_cnt=%d\n", sess, ssm_ev_str(ev),
	    sess->est_cnt);
}

typedef void (ssm_ev_handler_fn)(struct ibtrs_session *, enum ssm_ev);

static ssm_ev_handler_fn *ibtrs_srv_ev_handlers[] = {
	[SSM_STATE_IDLE]		= ssm_idle,
	[SSM_STATE_CONNECTED]		= ssm_connected,
	[SSM_STATE_CLOSING]		= ssm_closing,
	[SSM_STATE_CLOSED]		= ssm_closed,
};

static void check_heartbeat_work(struct work_struct *work)
{
	struct ibtrs_session *sess;

	sess = container_of(to_delayed_work(work), struct ibtrs_session,
			    check_heartbeat_dwork);

	if (ibtrs_heartbeat_timeout_is_expired(&sess->heartbeat)) {
		ssm_schedule_event(sess, SSM_EV_SESS_CLOSE);
		return;
	}

	ibtrs_heartbeat_warn(&sess->heartbeat);

	if (WARN_ON(!queue_delayed_work(sess->sm_wq,
					&sess->check_heartbeat_dwork,
					HEARTBEAT_INTV_JIFFIES)))
		WRN_RL(sess, "Schedule check heartbeat work failed, "
		       "check_heartbeat worker already queued?\n");
}

static void send_heartbeat_work(struct work_struct *work)
{
	struct ibtrs_session *sess;
	int err;

	sess = container_of(to_delayed_work(work), struct ibtrs_session,
			    send_heartbeat_dwork);

	if (ibtrs_heartbeat_send_ts_diff_ms(&sess->heartbeat) >=
	    HEARTBEAT_INTV_MS) {
		err = send_heartbeat(sess);
		if (unlikely(err)) {
			WRN_RL(sess,
			       "Sending heartbeat failed, err: %s,"
			       " no further heartbeat will be sent\n",
			       strerror(err));
			return;
		}
	}

	if (WARN_ON(!queue_delayed_work(sess->sm_wq,
					&sess->send_heartbeat_dwork,
					HEARTBEAT_INTV_JIFFIES)))
		WRN_RL(sess, "schedule send heartbeat work failed, "
		       "send_heartbeat worker already queued?\n");
}

static inline void ssm_ev_handle(struct ibtrs_session *sess, enum ssm_ev ev)
{
	return (*ibtrs_srv_ev_handlers[sess->state])(sess, ev);
}

static void ssm_worker(struct work_struct *work)
{
	struct ssm_work *ssm_w = container_of(work, struct ssm_work, work);

	ssm_ev_handle(ssm_w->sess, ssm_w->ev);
	kfree(ssm_w);
}

static int ssm_schedule_event(struct ibtrs_session *sess, enum ssm_ev ev)
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

static int ssm_init(struct ibtrs_session *sess)
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
			       " err: %s\n", strerror(ret));
		goto out;
	}

	mempool_debugfs_dir = debugfs_create_dir("mempool",
						 ibtrs_srv_debugfs_dir);
	if (IS_ERR_OR_NULL(mempool_debugfs_dir)) {
		ret = PTR_ERR(mempool_debugfs_dir);
		pr_warn("Failed to create mempool debugfs directory,"
		       " err: %s\n", strerror(ret));
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
		       " err: %s\n", strerror(err));
		return err;
	}

	destroy_wq = alloc_workqueue("ibtrs_server_destroy_wq", 0, 0);
	if (!destroy_wq) {
		pr_err("Failed to load module,"
		       " alloc ibtrs_server_destroy_wq failed\n");
		return -ENOMEM;
	}

	err = ibtrs_srv_create_sysfs_files();
	if (err) {
		pr_err("Failed to load module, can't create sysfs files,"
		       " err: %s\n", strerror(err));
		goto out_destroy_wq;
	}

	err = ibtrs_srv_create_debugfs_files();
	if (err)
		pr_warn("Unable to create debugfs files, err: %s."
		       " Continuing without debugfs\n", strerror(err));

	return 0;

out_destroy_wq:
	destroy_workqueue(destroy_wq);
	return err;
}

static void __exit ibtrs_server_exit(void)
{
	pr_info("Unloading module\n");
	ibtrs_srv_destroy_debugfs_files();
	ibtrs_srv_destroy_sysfs_files();
	destroy_workqueue(destroy_wq);

	pr_info("Module unloaded\n");
}

module_init(ibtrs_server_init);
module_exit(ibtrs_server_exit);
