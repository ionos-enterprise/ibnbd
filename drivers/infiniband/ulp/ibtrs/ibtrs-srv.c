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
MODULE_DESCRIPTION("IBTRS Server");
MODULE_VERSION(IBTRS_VER_STRING);
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

static void close_sess(struct ibtrs_srv_sess *sess);

struct ibtrs_srv_ctx {
	struct ibtrs_srv_ops ops;
	struct rdma_cm_id *cm_id_ip;
	struct rdma_cm_id *cm_id_ib;
	struct mutex sess_mutex;
	struct list_head sess_list;
};

struct ibtrs_srv_con {
	struct ibtrs_con	c;
	unsigned		cid;
	atomic_t		wr_cnt;
	struct ibtrs_srv_sess	*sess;
};

struct ibtrs_srv_op {
	struct ibtrs_srv_con		*con;
	u32				msg_id;
	u8				dir;
	u64				data_dma_addr;
	struct ibtrs_msg_req_rdma_write *req;
	struct ib_rdma_wr		*tx_wr;
	struct ib_sge			*tx_sg;
};

static bool __ibtrs_srv_change_state(struct ibtrs_srv_sess *sess,
				     enum ibtrs_srv_state new_state)
{
	enum ibtrs_srv_state old_state;
	bool changed = false;

	old_state = sess->state;
	switch (new_state) {
	case IBTRS_SRV_CONNECTED:
		switch (old_state) {
		case IBTRS_SRV_CONNECTING:
			changed = true;
			/* FALLTHRU */
		default:
			break;
		}
		break;
	case IBTRS_SRV_CLOSING:
		switch (old_state) {
		case IBTRS_SRV_CONNECTING:
		case IBTRS_SRV_CONNECTED:
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
		sess->state = new_state;

	return changed;
}

static bool ibtrs_srv_change_state_get_old(struct ibtrs_srv_sess *sess,
					   enum ibtrs_srv_state new_state,
					   enum ibtrs_srv_state *old_state)
{
	bool changed;

	spin_lock_irq(&sess->state_lock);
	*old_state = sess->state;
	changed = __ibtrs_srv_change_state(sess, new_state);
	spin_unlock_irq(&sess->state_lock);

	return changed;
}

static bool ibtrs_srv_change_state(struct ibtrs_srv_sess *sess,
				   enum ibtrs_srv_state new_state)
{
	enum ibtrs_srv_state old_state;

	return ibtrs_srv_change_state_get_old(sess, new_state, &old_state);
}

int ibtrs_srv_current_hca_port_to_str(struct ibtrs_srv_sess *sess,
				      char *buf, size_t len)
{
	struct ibtrs_srv_con *usr_con = sess->con[0];
	char str[16] = "n/a\n";
	int sz = 4;

	if (usr_con)
		len = scnprintf(str, sizeof(str), "%u\n",
				usr_con->c.cm_id->port_num);
	strncpy(buf, str, len);

	return sz;
}

const char *ibtrs_srv_get_sess_hca_name(struct ibtrs_srv_sess *sess)
{
	struct ibtrs_srv_con *usr_con = sess->con[0];

	if (usr_con)
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

static void ibtrs_srv_stats_dec_inflight(struct ibtrs_srv_sess *sess)
{
	atomic_dec_return(&sess->stats.rdma_stats.inflight);
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
	}

	return -EINVAL;
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
	}

	return -EINVAL;
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
	}

	return -EINVAL;
}

int ibtrs_srv_stats_wc_completion_to_str(struct ibtrs_srv_sess *sess, char *buf,
					 size_t len)
{
	return snprintf(buf, len, "%ld %ld\n",
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
	}

	return -EINVAL;
}

static inline bool srv_ops_are_valid(const struct ibtrs_srv_ops *ops)
{
	return ops && ops->sess_ev && ops->rdma_ev && ops->recv;
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
	size_t sg_cnt;
	int err, i, offset;

	sg_cnt = le32_to_cpu(id->req->sg_cnt);
	if (unlikely(!sg_cnt))
		return -EINVAL;

	offset = 0;
	for (i = 0; i < sg_cnt; i++) {
		struct ib_sge *list;

		wr		= &id->tx_wr[i];
		list		= &id->tx_sg[i];
		list->addr	= id->data_dma_addr + offset;
		list->length	= le32_to_cpu(id->req->desc[i].len);

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
		wr->remote_addr	= le64_to_cpu(id->req->desc[i].addr);
		wr->rkey	= le32_to_cpu(id->req->desc[i].key);

		if (i < (sg_cnt - 1)) {
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

	err = ib_post_send(id->con->c.qp, &id->tx_wr[0].wr, &bad_wr);
	if (unlikely(err))
		ibtrs_err(sess,
			  "Posting RDMA-Write-Request to QP failed, err: %d\n",
			  err);

	return err;
}

static void ibtrs_srv_ack_done(struct ib_cq *cq, struct ib_wc *wc)
{
	struct ibtrs_srv_con *con = cq->cq_context;
	struct ibtrs_srv_sess *sess = con->sess;

	if (unlikely(wc->status != IB_WC_SUCCESS)) {
		ibtrs_err(sess, "Failed ACK: %s\n",
			  ib_wc_status_msg(wc->status));
		close_sess(sess);
	}
}

static struct ib_cqe ack_cqe = {
	.done = ibtrs_srv_ack_done
};

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
	err = ibtrs_post_rdma_write_imm_empty(&con->c, &ack_cqe, imm, flags);
	if (unlikely(err))
		ibtrs_err_rl(sess, "ib_post_send(), err: %d\n", err);

	return err;
}

/*
 * ibtrs_srv_resp_rdma() - sends response to the client.
 *
 * Context: any
 */
int ibtrs_srv_resp_rdma(struct ibtrs_srv_op *id, int status)
{
	struct ibtrs_srv_con *con = id->con;
	struct ibtrs_srv_sess *sess = con->sess;
	int err;

	if (unlikely(!id))
		return -EINVAL;

	if (unlikely(sess->state != IBTRS_SRV_CONNECTED)) {
		ibtrs_err_rl(sess, "Sending I/O response failed, "
			     " session is disconnected, sess state %s\n",
			     ibtrs_srv_state_str(sess->state));
		return -ECOMM;
	}
	if (status || id->dir == WRITE) {
		err = send_io_resp_imm(con, id->msg_id, status);
		if (unlikely(err)) {
			ibtrs_err_rl(sess,
				     "Sending imm msg failed, err: %d\n",
				     err);
			close_sess(sess);
		}
	} else {
		err = rdma_write_sg(id);
		if (unlikely(err)) {
			ibtrs_err_rl(sess,
				     "Sending I/O read response failed, err: %d\n",
				     err);
			close_sess(sess);
		}
	}
	ibtrs_srv_stats_dec_inflight(sess);

	return err;
}
EXPORT_SYMBOL(ibtrs_srv_resp_rdma);

static void ibtrs_srv_usr_send_done(struct ib_cq *cq, struct ib_wc *wc);

int ibtrs_srv_send(struct ibtrs_srv_sess *sess, const struct kvec *vec,
		   size_t nr)
{
	struct ibtrs_srv_con *usr_con = sess->con[0];
	struct ibtrs_msg_user *msg;
	struct ibtrs_iu *iu;
	size_t len;
	int err;

	len = kvec_length(vec, nr);
	if (unlikely(len > MAX_REQ_SIZE - sizeof(*msg))) {
		ibtrs_err(sess, "Message size is too long: %zu\n", len);
		return -EMSGSIZE;
	}
	iu = ibtrs_usr_msg_get(&sess->s);
	if (unlikely(!iu)) {
		/* We are in disconnecting state, just return */
		ibtrs_err_rl(sess, "Sending user message failed, disconnecting");
		return -ECOMM;
	}

	msg = iu->buf;
	msg->type = cpu_to_le16(IBTRS_MSG_USER);
	msg->psize = cpu_to_le16(len);
	copy_from_kvec(msg->payl, vec, len);

	len += sizeof(*msg);

	err = ibtrs_post_send(&usr_con->c, iu, len, ibtrs_srv_usr_send_done);
	if (unlikely(err)) {
		ibtrs_err_rl(sess, "Sending message failed, posting message to QP"
			     " failed, err: %d\n", err);
		goto err_post_send;
	}
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
	if (unlikely(!sess->rcv_buf_pool)) {
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
	while (i--) {
		buf = &sess->rcv_buf_pool->rcv_bufs[i];
		ib_dma_unmap_single(sess->s.ib_dev->dev, buf->rdma_addr,
				    rcv_buf_size, DMA_BIDIRECTIONAL);
	}
	return err;
}

static int alloc_sess_tx_bufs(struct ibtrs_srv_sess *sess)
{
	struct ibtrs_srv_op *id;
	int i, err;

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

static void ibtrs_srv_update_wc_stats(struct ibtrs_srv_con *con)
{
	atomic64_inc(&con->sess->stats.wc_comp.calls);
	atomic64_inc(&con->sess->stats.wc_comp.total_wc_cnt);
}

static void ibtrs_srv_info_rsp_done(struct ib_cq *cq, struct ib_wc *wc)
{
	struct ibtrs_srv_con *con = cq->cq_context;
	struct ibtrs_srv_sess *sess = con->sess;
	struct ibtrs_srv_ctx *ctx = sess->ctx;
	struct ibtrs_iu *iu;
	int err;

	iu = container_of(wc->wr_cqe, struct ibtrs_iu, cqe);
	ibtrs_iu_free(iu, DMA_TO_DEVICE, sess->s.ib_dev->dev);

	if (unlikely(wc->status != IB_WC_SUCCESS)) {
		ibtrs_err(sess, "Sess info response send failed: %s\n",
			  ib_wc_status_msg(wc->status));
		close_sess(sess);
		return;
	}
	WARN_ON(wc->opcode != IB_WC_SEND);

	err = ibtrs_srv_create_sess_files(sess);
	if (unlikely(err))
		/* Consider as not a fatal error */
		ibtrs_err(sess,
			  "ibtrs_srv_create_sess_files(): err %d\n", err);

	ibtrs_srv_change_state(sess, IBTRS_SRV_CONNECTED);
	ibtrs_srv_update_wc_stats(con);

	/*
	 * We do not account number of established connections at the current
	 * moment, we rely on the client, which should send info request when
	 * all connections are successfully established.  Thus, simply notify
	 * listener with proper event when info response is successfully sent.
	 */
	ctx->ops.sess_ev(sess, IBTRS_SRV_SESS_EV_CONNECTED, sess->priv);
}

static int post_recv_sess(struct ibtrs_srv_sess *sess);

static int process_info_req(struct ibtrs_srv_con *con,
			    struct ibtrs_msg_info_req *msg)
{
	struct ibtrs_srv_sess *sess = con->sess;
	struct ibtrs_msg_info_rsp *rsp;
	struct ibtrs_iu *tx_iu;
	size_t tx_sz;
	int i, err;
	u64 addr;

	err = post_recv_sess(sess);
	if (unlikely(err)) {
		ibtrs_err(sess, "post_recv_sess(), err: %d\n", err);
		return err;
	}
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
	err = ibtrs_post_send(&con->c, tx_iu, tx_sz, ibtrs_srv_info_rsp_done);
	if (unlikely(err)) {
		ibtrs_err(sess, "ibtrs_post_send(), err: %d\n", err);
		ibtrs_iu_free(tx_iu, DMA_TO_DEVICE, sess->s.ib_dev->dev);
	}

	return err;
}

static void ibtrs_srv_info_req_done(struct ib_cq *cq, struct ib_wc *wc)
{
	struct ibtrs_srv_con *con = cq->cq_context;
	struct ibtrs_srv_sess *sess = con->sess;
	struct ibtrs_msg_info_req *msg;
	struct ibtrs_iu *iu;
	int err;

	WARN_ON(con->cid);

	iu = container_of(wc->wr_cqe, struct ibtrs_iu, cqe);
	if (unlikely(wc->status != IB_WC_SUCCESS)) {
		ibtrs_err(sess, "Sess info request receive failed: %s\n",
			  ib_wc_status_msg(wc->status));
		goto close;
	}
	WARN_ON(wc->opcode != IB_WC_RECV);

	if (unlikely(wc->byte_len < sizeof(*msg))) {
		ibtrs_err(sess, "Sess info request is malformed: size %d\n",
			  wc->byte_len);
		goto close;
	}
	msg = iu->buf;
	if (unlikely(le32_to_cpu(msg->type) != IBTRS_MSG_INFO_REQ)) {
		ibtrs_err(sess, "Sess info request is malformed: type %d\n",
			  le32_to_cpu(msg->type));
		goto close;
	}
	err = process_info_req(con, msg);
	if (unlikely(err))
		goto close;

out:
	ibtrs_iu_free(iu, DMA_FROM_DEVICE, sess->s.ib_dev->dev);
	return;
close:
	close_sess(sess);
	goto out;
}

static int post_recv_info_req(struct ibtrs_srv_con *con)
{
	struct ibtrs_srv_sess *sess = con->sess;
	struct ibtrs_iu *rx_iu;
	int err;

	rx_iu = ibtrs_iu_alloc(0, sizeof(struct ibtrs_msg_info_req),
			       GFP_KERNEL, sess->s.ib_dev->dev,
			       DMA_FROM_DEVICE);
	if (unlikely(!rx_iu)) {
		ibtrs_err(sess, "ibtrs_iu_alloc(): no memory\n");
		return -ENOMEM;
	}
	/* Prepare for getting info response */
	err = ibtrs_post_recv(&con->c, rx_iu, ibtrs_srv_info_req_done);
	if (unlikely(err)) {
		ibtrs_err(sess, "ibtrs_post_recv(), err: %d\n", err);
		ibtrs_iu_free(rx_iu, DMA_FROM_DEVICE, sess->s.ib_dev->dev);
		return err;;
	}

	return 0;
}

static void ibtrs_srv_rdma_done(struct ib_cq *cq, struct ib_wc *wc);

static struct ib_cqe io_comp_cqe = {
	.done = ibtrs_srv_rdma_done
};

static int post_recv_io(struct ibtrs_srv_con *con)
{
	struct ibtrs_srv_sess *sess = con->sess;
	int i, err;

	for (i = 0; i < sess->queue_depth; i++) {
		err = ibtrs_post_recv_empty(&con->c, &io_comp_cqe);
		if (unlikely(err))
			return err;
	}

	return 0;
}

static void ibtrs_srv_usr_recv_done(struct ib_cq *cq, struct ib_wc *wc);

static int post_recv_usr(struct ibtrs_srv_con *con)
{
	struct ibtrs_srv_sess *sess = con->sess;
	struct ibtrs_iu *iu;
	int i, err;

	for (i = 0; i < USR_CON_BUF_SIZE; i++) {
		iu = sess->s.usr_rx_ring[i];
		err = ibtrs_post_recv(&con->c, iu, ibtrs_srv_usr_recv_done);
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

static int post_recv_sess(struct ibtrs_srv_sess *sess)
{
	int err, cid;

	for (cid = 0; cid < sess->con_cnt; cid++) {
		err = post_recv(sess->con[cid]);
		if (unlikely(err)) {
			ibtrs_err(sess, "post_recv(), err: %d\n", err);
			return err;
		}
	}

	return 0;
}

static void free_sess_bufs(struct ibtrs_srv_sess *sess)
{
	ibtrs_iu_free_sess_rx_bufs(&sess->s);
	free_sess_tx_bufs(sess);
}

static void process_rdma_write_req(struct ibtrs_srv_con *con,
				   struct ibtrs_msg_req_rdma_write *req,
				   u32 buf_id, u32 off)
{
	struct ibtrs_srv_sess *sess = con->sess;
	struct ibtrs_srv_ctx *ctx = sess->ctx;
	struct ibtrs_srv_op *id;
	size_t sg_cnt;
	int ret;

	if (unlikely(sess->state != IBTRS_SRV_CONNECTED)) {
		ibtrs_err_rl(sess, "Processing RDMA-Write-Req request failed, "
			     " session is disconnected, sess state %s\n",
			     ibtrs_srv_state_str(sess->state));
		return;
	}
	sg_cnt = le32_to_cpu(req->sg_cnt);
	ibtrs_srv_update_rdma_stats(&sess->stats, off, true);
	id = sess->ops_ids[buf_id];
	kfree(id->tx_wr);
	kfree(id->tx_sg);
	id->con		= con;
	id->dir		= READ;
	id->msg_id	= buf_id;
	id->req		= req;
	id->tx_wr	= kcalloc(sg_cnt, sizeof(*id->tx_wr), GFP_KERNEL);
	id->tx_sg	= kcalloc(sg_cnt, sizeof(*id->tx_sg), GFP_KERNEL);
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
		close_sess(sess);
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

	if (unlikely(sess->state != IBTRS_SRV_CONNECTED)) {
		ibtrs_err_rl(sess, "Processing RDMA-Write request failed, "
			     " session is disconnected, sess state %s\n",
			     ibtrs_srv_state_str(sess->state));
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
		close_sess(sess);
	}
	ibtrs_srv_stats_dec_inflight(sess);
}

static int ibtrs_send_usr_msg_ack(struct ibtrs_srv_con *con)
{
	struct ibtrs_srv_sess *sess;
	int err;

	sess = con->sess;

	if (unlikely(sess->state != IBTRS_SRV_CONNECTED)) {
		ibtrs_err_rl(sess, "Sending user msg ack failed, disconnected,"
			     " session state is %s\n",
			     ibtrs_srv_state_str(sess->state));
		return -ECOMM;
	}
	err = ibtrs_post_rdma_write_imm_empty(&con->c, &ack_cqe,
					      IBTRS_ACK_IMM,
					      IB_SEND_SIGNALED);
	if (unlikely(err)) {
		ibtrs_err_rl(sess, "Sending user Ack msg failed, err: %d\n",
			     err);
		return err;
	}

	return 0;
}

static void process_io_req(struct ibtrs_srv_con *con, void *msg,
			   u32 id, u32 off)
{
	struct ibtrs_srv_sess *sess = con->sess;
	unsigned type;

	type = le16_to_cpu(le16_to_cpu(*(__le16 *)msg));

	switch (type) {
	case IBTRS_MSG_RDMA_WRITE:
		process_rdma_write(con, msg, id, off);
		break;
	case IBTRS_MSG_REQ_RDMA_WRITE:
		process_rdma_write_req(con, msg, id, off);
		break;
	default:
		ibtrs_err(sess, "Processing I/O request failed, "
			  "unknown message type received: 0x%02x\n", type);
		goto err;
	}

	return;

err:
	close_sess(sess);
}

static void ibtrs_srv_rdma_done(struct ib_cq *cq, struct ib_wc *wc)
{
	struct ibtrs_srv_con *con = cq->cq_context;
	struct ibtrs_srv_sess *sess = con->sess;
	u32 imm, msg_id, off;
	void *buf;
	int err;

	WARN_ON(!con->cid);

	if (unlikely(wc->status != IB_WC_SUCCESS)) {
		if (wc->status != IB_WC_WR_FLUSH_ERR) {
			ibtrs_err(sess, "%s (wr_cqe: %p,"
				  " type: %s, vendor_err: 0x%x, len: %u)\n",
				  ib_wc_status_msg(wc->status), wc->wr_cqe,
				  ib_wc_opcode_str(wc->opcode),
				  wc->vendor_err, wc->byte_len);
			close_sess(sess);
		}
		return;
	}
	ibtrs_srv_update_wc_stats(con);

	switch (wc->opcode) {
	case IB_WC_RDMA_WRITE:
		/*
		 * post_send() RDMA write completions of IO reqs (read/write)
		 */
		break;
	case IB_WC_RECV_RDMA_WITH_IMM:
		/*
		 * post_recv() RDMA write completions of IO reqs (read/write)
		 */
		if (WARN_ON(wc->wr_cqe != &io_comp_cqe))
			return;
		err = ibtrs_post_recv_empty(&con->c, &io_comp_cqe);
		if (unlikely(err)) {
			ibtrs_err(sess, "ibtrs_post_recv(), err: %d\n", err);
			close_sess(sess);
			break;
		}
		imm = be32_to_cpu(wc->ex.imm_data);
		msg_id = imm >> sess->off_len;
		off = imm & sess->off_mask;

		if (unlikely(msg_id > sess->queue_depth ||
			     off > rcv_buf_size)) {
			ibtrs_err(sess, "Processing I/O failed, contiguous "
				  "buf addr is out of reserved area\n");
			close_sess(sess);
			return;
		}
		buf = sess->rcv_buf_pool->rcv_bufs[msg_id].buf + off;
		process_io_req(con, buf, msg_id, off);
		break;
	default:
		ibtrs_wrn(sess, "Unexpected WC type: %s\n",
			  ib_wc_opcode_str(wc->opcode));
		return;
	}
}

static void ibtrs_srv_usr_send_done(struct ib_cq *cq, struct ib_wc *wc)
{
	struct ibtrs_srv_con *con = cq->cq_context;
	struct ibtrs_srv_sess *sess = con->sess;
	struct ibtrs_iu *iu;

	WARN_ON(con->cid);

	iu = container_of(wc->wr_cqe, struct ibtrs_iu, cqe);
	ibtrs_usr_msg_return_iu(&sess->s, iu);

	if (unlikely(wc->status != IB_WC_SUCCESS)) {
		ibtrs_err(sess, "User message send failed: %s\n",
			  ib_wc_status_msg(wc->status));
		close_sess(sess);
		return;
	}
	WARN_ON(wc->opcode != IB_WC_SEND);

	ibtrs_srv_update_wc_stats(con);
}

static void process_msg(struct ibtrs_srv_sess *sess, struct ibtrs_msg_user *msg)
{
	struct ibtrs_srv_ctx *ctx = sess->ctx;
	size_t len;

	/*
	 * Callback is called directly, obviously it may sleep somewhere.
	 */
	might_sleep();

	len = le16_to_cpu(msg->psize);
	atomic64_inc(&sess->stats.user_ib_msgs.recv_msg_cnt);
	atomic64_add(len + sizeof(*msg), &sess->stats.user_ib_msgs.recv_size);

	ctx->ops.recv(sess, sess->priv, msg->payl, len);
}

static void ibtrs_srv_usr_recv_done(struct ib_cq *cq, struct ib_wc *wc);

static int process_usr_msg(struct ibtrs_srv_con *con, struct ib_wc *wc)
{
	struct ibtrs_srv_sess *sess = con->sess;
	struct ibtrs_msg_user *msg;
	int err = -EMSGSIZE;
	struct ibtrs_iu *iu;
	unsigned type;

	if (unlikely(wc->byte_len < sizeof(*msg))) {
		ibtrs_err(sess, "Malformed user message: size %d\n",
			  wc->byte_len);
		goto out;
	}
	iu = container_of(wc->wr_cqe, struct ibtrs_iu, cqe);
	msg = iu->buf;
	type = le16_to_cpu(msg->type);

	switch (type) {
	case IBTRS_MSG_USER:
		process_msg(sess, msg);

		err = ibtrs_post_recv(&con->c, iu, ibtrs_srv_usr_recv_done);
		if (unlikely(err)) {
			ibtrs_err(sess, "ibtrs_post_recv(), err: %d\n", err);
			goto out;
		}
		err = ibtrs_send_usr_msg_ack(con);
		if (unlikely(err)) {
			ibtrs_err(sess, "ibtrs_send_usr_msg_ack(), err: %d\n",
				  err);
			goto out;
		}
		break;
	default:
		ibtrs_err(sess, "Received message of unknown type: 0x%02x\n",
			  type);
		goto out;
	}

out:
	return err;
}

static int process_usr_msg_ack(struct ibtrs_srv_con *con, struct ib_wc *wc)
{
	struct ibtrs_srv_sess *sess = con->sess;
	struct ibtrs_iu *iu;
	int err;
	u32 imm;

	iu = container_of(wc->wr_cqe, struct ibtrs_iu, cqe);
	imm = be32_to_cpu(wc->ex.imm_data);
	if (WARN_ON(imm != IBTRS_ACK_IMM))
		return -ENOENT;

	ibtrs_usr_msg_put(&sess->s);

	err = ibtrs_post_recv(&con->c, iu, ibtrs_srv_usr_recv_done);
	if (unlikely(err))
		ibtrs_err(sess, "ibtrs_post_recv(), err: %d\n", err);

	return err;
}

static void ibtrs_srv_usr_recv_done(struct ib_cq *cq, struct ib_wc *wc)
{
	struct ibtrs_srv_con *con = cq->cq_context;
	struct ibtrs_srv_sess *sess = con->sess;
	int err;

	WARN_ON(con->cid);

	if (unlikely(wc->status != IB_WC_SUCCESS)) {
		if (wc->status != IB_WC_WR_FLUSH_ERR) {
			ibtrs_err(sess,
				  "User message or user ACK recv failed: %s\n",
				  ib_wc_status_msg(wc->status));
			goto err;
		}
		return;
	}
	ibtrs_srv_update_wc_stats(con);

	switch (wc->opcode) {
	case IB_WC_RECV:
		err = process_usr_msg(con, wc);
		break;
	case IB_WC_RECV_RDMA_WITH_IMM:
		err = process_usr_msg_ack(con, wc);
		break;
	default:
		ibtrs_err(sess, "Unknown opcode: 0x%02x\n", wc->opcode);
		goto err;
	}
	if (unlikely(err))
		goto err;

	return;

err:
	close_sess(sess);
}

const char *ibtrs_srv_get_sess_hostname(struct ibtrs_srv_sess *sess)
{
	return sess->s.addr.hostname;
}
EXPORT_SYMBOL(ibtrs_srv_get_sess_hostname);

const struct sockaddr *
ibtrs_srv_get_sess_sockaddr(struct ibtrs_srv_sess *sess)
{
	return (const struct sockaddr *)&sess->s.addr.sockaddr;
}
EXPORT_SYMBOL(ibtrs_srv_get_sess_sockaddr);

int ibtrs_srv_get_sess_qdepth(struct ibtrs_srv_sess *sess)
{
	return sess->queue_depth;
}
EXPORT_SYMBOL(ibtrs_srv_get_sess_qdepth);

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

static void ibtrs_srv_close_work(struct work_struct *work)
{
	struct ibtrs_srv_sess *sess;
	struct ibtrs_srv_ctx *ctx;
	struct ibtrs_srv_con *con;
	int i;

	sess = container_of(work, typeof(*sess), close_work);
	ctx = sess->ctx;

	if (sess->was_connected)
		ctx->ops.sess_ev(sess, IBTRS_SRV_SESS_EV_DISCONNECTED,
				 sess->priv);
	ibtrs_srv_destroy_sess_files(sess);

	mutex_lock(&ctx->sess_mutex);
	list_del(&sess->ctx_list);
	mutex_unlock(&ctx->sess_mutex);

	for (i = 0; i < sess->con_cnt; i++) {
		con = sess->con[i];
		if (!con)
			continue;

		rdma_disconnect(con->c.cm_id);
		ib_drain_qp(con->c.qp);
	}
	release_cont_bufs(sess);
	free_sess_bufs(sess);

	for (i = 0; i < sess->con_cnt; i++) {
		con = sess->con[i];
		if (!con)
			continue;

		ibtrs_cq_qp_destroy(&con->c);
		rdma_destroy_id(con->c.cm_id);
		kfree(con);
	}
	ibtrs_ib_dev_put(sess->s.ib_dev);
	ibtrs_srv_change_state(sess, IBTRS_SRV_CLOSED);
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
	msg.version = cpu_to_le16(IBTRS_VERSION);
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
	msg.version = cpu_to_le16(IBTRS_VERSION);
	msg.errno = cpu_to_le16(errno);

	err = rdma_reject(cm_id, &msg, sizeof(msg));
	if (err)
		pr_err("rdma_reject(), err: %d\n", err);

	return err;
}

static struct ibtrs_srv_sess *
__find_sess(struct ibtrs_srv_ctx *ctx, const char *uuid)
{
	struct ibtrs_srv_sess *sess;

	list_for_each_entry(sess, &ctx->sess_list, ctx_list) {
		if (!memcmp(&sess->s.uuid, uuid, sizeof(sess->s.uuid)))
			return sess;
	}

	return NULL;
}

static int create_con(struct ibtrs_srv_sess *sess,
		      struct rdma_cm_id *cm_id,
		      unsigned cid)
{
	u16 cq_size, wr_queue_size;
	struct ibtrs_srv_con *con;
	int err, cq_vector;

	con = kzalloc(sizeof(*con), GFP_KERNEL);
	if (unlikely(!con)) {
		ibtrs_err(sess, "kzalloc() failed\n");
		err = -ENOMEM;
		goto err;
	}

	con->c.cm_id = cm_id;
	con->sess = sess;
	con->cid = cid;
	atomic_set(&con->wr_cnt, 0);

	if (con->cid == 0) {
		cq_size       = USR_CON_BUF_SIZE + 1;
		wr_queue_size = USR_CON_BUF_SIZE + 1;
	} else {
		cq_size       = sess->queue_depth;
		wr_queue_size = cm_id->device->attrs.max_qp_wr - 1;
	}

	cq_vector = ibtrs_srv_get_next_cq_vector(sess);

	/* TODO: SOFTIRQ can be faster, but be careful with softirq context */
	err = ibtrs_cq_qp_create(&sess->s, &con->c, 1, cq_vector, cq_size,
				 wr_queue_size, IB_POLL_WORKQUEUE);
	if (unlikely(err)) {
		ibtrs_err(sess, "ibtrs_cq_qp_create(), err: %d\n", err);
		goto free_con;
	}
	if (con->cid == 0) {
		err = post_recv_info_req(con);
		if (unlikely(err))
			goto free_cqqp;
	}
	WARN_ON(sess->con[cid]);
	sess->con[cid] = con;

	return 0;

free_cqqp:
	ibtrs_cq_qp_destroy(&con->c);
free_con:
	kfree(con);

err:
	return err;
}

static struct ibtrs_srv_sess *__alloc_sess(struct ibtrs_srv_ctx *ctx,
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

	sess->state = IBTRS_SRV_CONNECTING;
	sess->ctx = ctx;
	sess->con_cnt = con_cnt;
	sess->cur_cq_vector = -1;
	sess->queue_depth = sess_queue_depth;
	sess->s.addr.sockaddr = cm_id->route.addr.dst_addr;

	memcpy(&sess->s.uuid, uuid, sizeof(sess->s.uuid));
	spin_lock_init(&sess->state_lock);

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

static int ibtrs_rdma_connect(struct rdma_cm_id *cm_id,
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
	if (unlikely(version >> 8 != IBTRS_VER_MAJOR)) {
		pr_err("Unsupported major IBTRS version: %d", version);
		goto reject_w_econnreset;
	}
	con_cnt = le16_to_cpu(msg->cid_num);
	if (unlikely(con_cnt > 4096)) {
		/* Sanity check */
		pr_err("Too many connections requested: %d\n", con_cnt);
		goto reject_w_econnreset;
	}
	cid = le16_to_cpu(msg->cid);
	if (unlikely(cid >= con_cnt)) {
		/* Sanity check */
		pr_err("Incorrect cid: %d >= %d\n", cid, con_cnt);
		goto reject_w_econnreset;
	}
	mutex_lock(&ctx->sess_mutex);
	sess = __find_sess(ctx, msg->uuid);
	if (sess) {
		if (unlikely(sess->state != IBTRS_SRV_CONNECTING)) {
			ibtrs_err(sess, "Session in wrong state: %s\n",
				  ibtrs_srv_state_str(sess->state));
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
		sess = __alloc_sess(ctx, cm_id, con_cnt, msg->uuid);
		if (unlikely(IS_ERR(sess))) {
			mutex_unlock(&ctx->sess_mutex);
			err = PTR_ERR(sess);
			goto reject_w_err;
		}
	}
	err = create_con(sess, cm_id, cid);
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
	close_sess(sess);
	mutex_unlock(&ctx->sess_mutex);
	goto reject_w_err;
}

static void ibtrs_rdma_disconnect(struct ibtrs_srv_con *con)
{
	struct ibtrs_srv_sess *sess = con->sess;

	close_sess(sess);
}

static void ibtrs_rdma_conn_error(struct ibtrs_srv_con *con)
{
	struct ibtrs_srv_sess *sess = con->sess;

	close_sess(sess);
}

static void ibtrs_rdma_device_removal(struct ibtrs_srv_con *con)
{
	struct ibtrs_srv_sess *sess = con->sess;

	close_sess(sess);
}

static int ibtrs_srv_rdma_cm_handler(struct rdma_cm_id *cm_id,
				     struct rdma_cm_event *event)
{
	struct ibtrs_srv_con *con = NULL;
	int err = 0;

	if (cm_id->qp) {
		struct ibtrs_con *ibtrs_con = cm_id->qp->qp_context;

		con = container_of(ibtrs_con, struct ibtrs_srv_con, c);
	}

	switch (event->event) {
	case RDMA_CM_EVENT_CONNECT_REQUEST:
		err = ibtrs_rdma_connect(cm_id, event->param.conn.private_data,
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
		ibtrs_rdma_conn_error(con);
		break;
	case RDMA_CM_EVENT_DISCONNECTED:
	case RDMA_CM_EVENT_ADDR_CHANGE:
	case RDMA_CM_EVENT_TIMEWAIT_EXIT:
		ibtrs_rdma_disconnect(con);
		break;
	case RDMA_CM_EVENT_DEVICE_REMOVAL:
		ibtrs_rdma_device_removal(con);
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

	cm_id = rdma_create_id(&init_net, ibtrs_srv_rdma_cm_handler,
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
	close_sess(sess);
}

static void close_sess(struct ibtrs_srv_sess *sess)
{
	enum ibtrs_srv_state old_state;

	if (ibtrs_srv_change_state_get_old(sess, IBTRS_SRV_CLOSING,
					   &old_state)) {
		sess->was_connected = (old_state == IBTRS_SRV_CONNECTED);
		queue_work(ibtrs_wq, &sess->close_work);
	}
	WARN_ON(sess->state != IBTRS_SRV_CLOSING);
}

static void close_sessions(struct ibtrs_srv_ctx *ctx)
{
	struct ibtrs_srv_sess *sess;

	mutex_lock(&ctx->sess_mutex);
	list_for_each_entry(sess, &ctx->sess_list, ctx_list)
		close_sess(sess);
	mutex_unlock(&ctx->sess_mutex);
	flush_workqueue(ibtrs_wq);
}

void ibtrs_srv_close(struct ibtrs_srv_ctx *ctx)
{
	rdma_destroy_id(ctx->cm_id_ip);
	rdma_destroy_id(ctx->cm_id_ib);
	close_sessions(ctx);
	free_srv_ctx(ctx);
}
EXPORT_SYMBOL(ibtrs_srv_close);

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
	pr_info("Loading module %s, version: %s "
		"(retry_count: %d, cq_affinity_list: %s, "
		"max_io_size: %d, sess_queue_depth: %d, "
		"init_pool_size: %d, pool_size_hi_wm: %d, "
		"hostname: %s)\n",
		KBUILD_MODNAME, IBTRS_VER_STRING, retry_count,
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
