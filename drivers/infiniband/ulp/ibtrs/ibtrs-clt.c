#define pr_fmt(fmt) KBUILD_MODNAME " L" __stringify(__LINE__) ": " fmt

#include <linux/module.h>
#include <linux/wait.h>
#include <linux/scatterlist.h>
#include <linux/random.h>
#include <linux/utsname.h>
#include <rdma/rdma_cm.h>
#include <rdma/ib_cm.h>
#include <rdma/ib_fmr_pool.h>
#include <rdma/ibtrs.h>
#include <linux/list.h>

#include "ibtrs-pri.h"
#include "ibtrs-clt.h"
#include "ibtrs-log.h"

#define CONS_PER_SESSION (nr_cons_per_session + 1)
#define RECONNECT_SEED 8
#define MAX_SEGMENTS 31

#define IBTRS_CONNECT_TIMEOUT_MS 5000

MODULE_AUTHOR("ibnbd@profitbricks.com");
MODULE_DESCRIPTION("IBTRS Client");
MODULE_VERSION(IBTRS_VER_STRING);
MODULE_LICENSE("GPL");

static bool use_fr;
module_param(use_fr, bool, 0444);
MODULE_PARM_DESC(use_fr, "use FRWR mode for memory registration if possible."
		 " (default: 0)");

static ushort nr_cons_per_session;
module_param(nr_cons_per_session, ushort, 0444);
MODULE_PARM_DESC(nr_cons_per_session, "Number of connections per session."
		 " (default: NR_CPUS)");

static int retry_count = 7;

static int retry_count_set(const char *val, const struct kernel_param *kp)
{
	int err, ival;

	err = kstrtoint(val, 0, &ival);
	if (err)
		return err;

	if (ival < MIN_RTR_CNT || ival > MAX_RTR_CNT)
		return -EINVAL;

	retry_count = ival;

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

static int fmr_sg_cnt = 4;
module_param_named(fmr_sg_cnt, fmr_sg_cnt, int, 0644);
MODULE_PARM_DESC(fmr_sg_cnt, "when sg_cnt is bigger than fmr_sg_cnt, enable"
		 " FMR (default: 4)");

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

static void ibtrs_rdma_error_recovery(struct ibtrs_clt_con *con);
static void ibtrs_clt_rdma_done(struct ib_cq *cq, struct ib_wc *wc);

static struct workqueue_struct *ibtrs_wq;

/* rdma_req which connect iu with sglist received from user */
struct rdma_req {
	struct list_head        list;
	struct ibtrs_iu		*iu;
	struct scatterlist	*sglist; /* list holding user data */
	unsigned int		sg_cnt;
	unsigned int		sg_size;
	u32			data_len;
	void			*priv;
	bool			in_use;
	struct ibtrs_clt_con	*con;
	union {
		struct ib_pool_fmr	**fmr_list;
		struct ibtrs_fr_desc	**fr_list;
	};
	void			*map_page;
	struct ibtrs_tag	*tag;
	u16			nmdesc;
	enum dma_data_direction dir;
	unsigned long		start_time;
};

struct ibtrs_clt_con {
	struct ibtrs_con	c;
	unsigned		cid;
	unsigned		cpu;
	atomic_t		io_cnt;
	struct ibtrs_clt_sess	*sess;
	struct ibtrs_fr_pool	*fr_pool;
	int			cm_err;
};

struct msg_work {
	struct work_struct	work;
	struct ibtrs_clt_con	*con;
	void                    *msg;
};

static inline void ibtrs_clt_state_lock(void)
{
	rcu_read_lock();
	/* Paired with state change */
	smp_rmb();
}

static inline void ibtrs_clt_state_unlock(void)
{
	rcu_read_unlock();
}

static void ibtrs_clt_free_sg_list_distr_stats(struct ibtrs_clt_sess *sess)
{
	int i;

	for (i = 0; i < num_online_cpus(); i++)
		kfree(sess->stats.sg_list_distr[i]);
	kfree(sess->stats.sg_list_distr);
	sess->stats.sg_list_distr = NULL;
	kfree(sess->stats.sg_list_total);
	sess->stats.sg_list_total = NULL;
}

static void ibtrs_clt_free_cpu_migr_stats(struct ibtrs_clt_sess *sess)
{
	kfree(sess->stats.cpu_migr.to);
	sess->stats.cpu_migr.to = NULL;
	kfree(sess->stats.cpu_migr.from);
	sess->stats.cpu_migr.from = NULL;
}

static void ibtrs_clt_free_rdma_lat_stats(struct ibtrs_clt_sess *sess)
{
	int i;

	for (i = 0; i < num_online_cpus(); i++)
		kfree(sess->stats.rdma_lat_distr[i]);

	kfree(sess->stats.rdma_lat_distr);
	sess->stats.rdma_lat_distr = NULL;
	kfree(sess->stats.rdma_lat_max);
	sess->stats.rdma_lat_max = NULL;
}

static void ibtrs_clt_free_wc_comp_stats(struct ibtrs_clt_sess *sess)
{
	kfree(sess->stats.wc_comp);
	sess->stats.wc_comp = NULL;
}

static void ibtrs_clt_free_rdma_stats(struct ibtrs_clt_sess *sess)
{
	kfree(sess->stats.rdma_stats);
	sess->stats.rdma_stats = NULL;
}

static void ibtrs_clt_free_stats(struct ibtrs_clt_sess *sess)
{
	ibtrs_clt_free_rdma_stats(sess);
	ibtrs_clt_free_rdma_lat_stats(sess);
	ibtrs_clt_free_cpu_migr_stats(sess);
	ibtrs_clt_free_sg_list_distr_stats(sess);
	ibtrs_clt_free_wc_comp_stats(sess);
}

int ibtrs_clt_get_user_queue_depth(struct ibtrs_clt_sess *sess)
{
	return sess->user_queue_depth;
}

int ibtrs_clt_set_user_queue_depth(struct ibtrs_clt_sess *sess,
					  u16 queue_depth)
{
	if (queue_depth < 1 ||
	    queue_depth > sess->queue_depth) {
		ibtrs_err(sess, "Queue depth %u is out of range (1 - %u)",
			  queue_depth,
			  sess->queue_depth);
		return -EINVAL;
	}

	sess->user_queue_depth = queue_depth;
	return 0;
}

bool ibtrs_clt_sess_is_connected(const struct ibtrs_clt_sess *sess)
{
	return sess->state == IBTRS_CLT_CONNECTED;
}

static inline bool clt_ops_are_valid(const struct ibtrs_clt_ops *ops)
{
	return ops && ops->rdma_ev && ops->sess_ev && ops->recv;
}

/**
 * struct ibtrs_fr_desc - fast registration work request arguments
 * @entry: Entry in ibtrs_fr_pool.free_list.
 * @mr:    Memory region.
 * @frpl:  Fast registration page list.
 */
struct ibtrs_fr_desc {
	struct list_head		entry;
	struct ib_mr			*mr;
};

/**
 * struct ibtrs_fr_pool - pool of fast registration descriptors
 *
 * An entry is available for allocation if and only if it occurs in @free_list.
 *
 * @size:      Number of descriptors in this pool.
 * @max_page_list_len: Maximum fast registration work request page list length.
 * @lock:      Protects free_list.
 * @free_list: List of free descriptors.
 * @desc:      Fast registration descriptor pool.
 */
struct ibtrs_fr_pool {
	int			size;
	int			max_page_list_len;
	spinlock_t		lock;
	struct list_head	free_list;
	struct ibtrs_fr_desc	desc[0];
};

/**
 * struct ibtrs_map_state - per-request DMA memory mapping state
 * @desc:	    Pointer to the element of the SRP buffer descriptor array
 *		    that is being filled in.
 * @pages:	    Array with DMA addresses of pages being considered for
 *		    memory registration.
 * @base_dma_addr:  DMA address of the first page that has not yet been mapped.
 * @dma_len:	    Number of bytes that will be registered with the next
 *		    FMR or FR memory registration call.
 * @total_len:	    Total number of bytes in the sg-list being mapped.
 * @npages:	    Number of page addresses in the pages[] array.
 * @nmdesc:	    Number of FMR or FR memory descriptors used for mapping.
 * @ndesc:	    Number of buffer descriptors that have been filled in.
 */
struct ibtrs_map_state {
	union {
		struct ib_pool_fmr	**next_fmr;
		struct ibtrs_fr_desc	**next_fr;
	};
	struct ibtrs_sg_desc	*desc;
	union {
		u64			*pages;
		struct scatterlist      *sg;
	};
	dma_addr_t		base_dma_addr;
	u32			dma_len;
	u32			total_len;
	u32			npages;
	u32			nmdesc;
	u32			ndesc;
	enum dma_data_direction dir;
};

static inline struct ibtrs_tag *__ibtrs_get_tag(struct ibtrs_clt_sess *sess,
						int cpu_id)
{
	size_t max_depth = sess->user_queue_depth;
	struct ibtrs_tag *tag;
	int cpu, bit;

	cpu = get_cpu();
	do {
		bit = find_first_zero_bit(sess->tags_map, max_depth);
		if (unlikely(bit >= max_depth)) {
			put_cpu();
			return NULL;
		}

	} while (unlikely(test_and_set_bit_lock(bit, sess->tags_map)));
	put_cpu();

	tag = GET_TAG(sess, bit);
	WARN_ON(tag->mem_id != bit);
	tag->cpu_id = (cpu_id != -1 ? cpu_id : cpu);

	return tag;
}

static inline void __ibtrs_put_tag(struct ibtrs_clt_sess *sess,
				   struct ibtrs_tag *tag)
{
	clear_bit_unlock(tag->mem_id, sess->tags_map);
}

struct ibtrs_tag *ibtrs_get_tag(struct ibtrs_clt_sess *sess, int cpu_id,
				size_t nr_bytes, int can_wait)
{
	struct ibtrs_tag *tag;
	DEFINE_WAIT(wait);

	/* Is not used for now */
	(void)nr_bytes;

	tag = __ibtrs_get_tag(sess, cpu_id);
	if (likely(tag) || !can_wait)
		return tag;

	do {
		prepare_to_wait(&sess->tags_wait, &wait, TASK_UNINTERRUPTIBLE);
		tag = __ibtrs_get_tag(sess, cpu_id);
		if (likely(tag))
			break;

		io_schedule();
	} while (1);

	finish_wait(&sess->tags_wait, &wait);

	return tag;
}
EXPORT_SYMBOL(ibtrs_get_tag);

void ibtrs_put_tag(struct ibtrs_clt_sess *sess, struct ibtrs_tag *tag)
{
	if (WARN_ON(tag->mem_id >= sess->queue_depth))
		return;
	if (WARN_ON(!test_bit(tag->mem_id, sess->tags_map)))
		return;

	__ibtrs_put_tag(sess, tag);

	/* Putting a tag is a barrier, so we will observe
	 * new entry in the wait list, no worries.
	 */
	if (waitqueue_active(&sess->tags_wait))
		wake_up(&sess->tags_wait);
}
EXPORT_SYMBOL(ibtrs_put_tag);

/**
 * ibtrs_destroy_fr_pool() - free the resources owned by a pool
 * @pool: Fast registration pool to be destroyed.
 */
static void ibtrs_destroy_fr_pool(struct ibtrs_fr_pool *pool)
{
	struct ibtrs_fr_desc *d;
	int i, err;

	if (!pool)
		return;

	for (i = 0, d = &pool->desc[0]; i < pool->size; i++, d++) {
		if (d->mr) {
			err = ib_dereg_mr(d->mr);
			if (err)
				pr_err("Failed to deregister memory region,"
				       " err: %d\n", err);
		}
	}
	kfree(pool);
}

/**
 * ibtrs_create_fr_pool() - allocate and initialize a pool for fast registration
 * @device:            IB device to allocate fast registration descriptors for.
 * @pd:                Protection domain associated with the FR descriptors.
 * @pool_size:         Number of descriptors to allocate.
 * @max_page_list_len: Maximum fast registration work request page list length.
 */
static struct ibtrs_fr_pool *ibtrs_create_fr_pool(struct ib_device *device,
						  struct ib_pd *pd,
						  int pool_size,
						  int max_page_list_len)
{
	struct ibtrs_fr_pool *pool;
	struct ibtrs_fr_desc *d;
	struct ib_mr *mr;
	int i, ret;

	if (pool_size <= 0) {
		pr_warn("Creating fr pool failed, invalid pool size %d\n",
			pool_size);
		ret = -EINVAL;
		goto err;
	}

	pool = kzalloc(sizeof(*pool) + pool_size * sizeof(*d), GFP_KERNEL);
	if (!pool) {
		ret = -ENOMEM;
		goto err;
	}

	pool->size = pool_size;
	pool->max_page_list_len = max_page_list_len;
	spin_lock_init(&pool->lock);
	INIT_LIST_HEAD(&pool->free_list);

	for (i = 0, d = &pool->desc[0]; i < pool->size; i++, d++) {
		mr = ib_alloc_mr(pd, IB_MR_TYPE_MEM_REG, max_page_list_len);
		if (IS_ERR(mr)) {
			pr_warn("Failed to allocate fast region memory\n");
			ret = PTR_ERR(mr);
			goto destroy_pool;
		}
		d->mr = mr;
		list_add_tail(&d->entry, &pool->free_list);
	}

	return pool;

destroy_pool:
	ibtrs_destroy_fr_pool(pool);
err:
	return ERR_PTR(ret);
}

/**
 * ibtrs_fr_pool_get() - obtain a descriptor suitable for fast registration
 * @pool: Pool to obtain descriptor from.
 */
static struct ibtrs_fr_desc *ibtrs_fr_pool_get(struct ibtrs_fr_pool *pool)
{
	struct ibtrs_fr_desc *d = NULL;

	spin_lock_bh(&pool->lock);
	if (!list_empty(&pool->free_list)) {
		d = list_first_entry(&pool->free_list, typeof(*d), entry);
		list_del(&d->entry);
	}
	spin_unlock_bh(&pool->lock);

	return d;
}

/**
 * ibtrs_fr_pool_put() - put an FR descriptor back in the free list
 * @pool: Pool the descriptor was allocated from.
 * @desc: Pointer to an array of fast registration descriptor pointers.
 * @n:    Number of descriptors to put back.
 *
 * Note: The caller must already have queued an invalidation request for
 * desc->mr->rkey before calling this function.
 */
static void ibtrs_fr_pool_put(struct ibtrs_fr_pool *pool,
			      struct ibtrs_fr_desc **desc, int n)
{
	int i;

	spin_lock_bh(&pool->lock);
	for (i = 0; i < n; i++)
		list_add(&desc[i]->entry, &pool->free_list);
	spin_unlock_bh(&pool->lock);
}

static void ibtrs_map_desc(struct ibtrs_map_state *state, dma_addr_t dma_addr,
			   u32 dma_len, u32 rkey, u32 max_desc)
{
	struct ibtrs_sg_desc *desc = state->desc;

	pr_debug("dma_addr %llu, key %u, dma_len %u\n",
		 dma_addr, rkey, dma_len);
	desc->addr = cpu_to_le64(dma_addr);
	desc->key  = cpu_to_le32(rkey);
	desc->len  = cpu_to_le32(dma_len);

	state->total_len += dma_len;
	if (state->ndesc < max_desc) {
		state->desc++;
		state->ndesc++;
	} else {
		state->ndesc = INT_MIN;
		pr_err("Could not fit S/G list into buffer descriptor %d.\n",
		       max_desc);
	}
}

static int ibtrs_map_finish_fmr(struct ibtrs_map_state *state,
				struct ibtrs_clt_con *con)
{
	struct ib_pool_fmr *fmr;
	u64 io_addr = 0;
	dma_addr_t dma_addr;

	fmr = ib_fmr_pool_map_phys(con->sess->fmr_pool, state->pages,
				   state->npages, io_addr);
	if (IS_ERR(fmr)) {
		ibtrs_wrn_rl(con->sess, "Failed to map FMR from FMR pool, "
			     "err: %ld\n", PTR_ERR(fmr));
		return PTR_ERR(fmr);
	}

	*state->next_fmr++ = fmr;
	state->nmdesc++;
	dma_addr = state->base_dma_addr & ~con->sess->mr_page_mask;
	pr_debug("ndesc = %d, nmdesc = %d, npages = %d\n",
		 state->ndesc, state->nmdesc, state->npages);
	if (state->dir == DMA_TO_DEVICE)
		ibtrs_map_desc(state, dma_addr, state->dma_len, fmr->fmr->lkey,
			       con->sess->max_desc);
	else
		ibtrs_map_desc(state, dma_addr, state->dma_len, fmr->fmr->rkey,
			       con->sess->max_desc);

	return 0;
}

static void ibtrs_clt_fast_reg_done(struct ib_cq *cq, struct ib_wc *wc)
{
	struct ibtrs_clt_con *con = cq->cq_context;
	struct ibtrs_clt_sess *sess = con->sess;

	if (unlikely(wc->status != IB_WC_SUCCESS)) {
		ibtrs_err(sess, "Failed IB_WR_REG_MR: %s\n",
			  ib_wc_status_msg(wc->status));
		ibtrs_rdma_error_recovery(con);
	}
}

static struct ib_cqe fast_reg_cqe = {
	.done = ibtrs_clt_fast_reg_done
};

/* TODO */
static int ibtrs_map_finish_fr(struct ibtrs_map_state *state,
			       struct ibtrs_clt_con *con, int sg_cnt,
			       unsigned int *sg_offset_p)
{
	struct ib_send_wr *bad_wr;
	struct ib_reg_wr wr;
	struct ibtrs_fr_desc *desc;
	struct ib_pd *pd = con->sess->s.ib_dev->pd;
	u32 rkey;
	int n;

	if (sg_cnt == 1 && (pd->flags & IB_PD_UNSAFE_GLOBAL_RKEY)) {
		unsigned int sg_offset = sg_offset_p ? *sg_offset_p : 0;

		ibtrs_map_desc(state, sg_dma_address(state->sg) + sg_offset,
			       sg_dma_len(state->sg) - sg_offset,
			       pd->unsafe_global_rkey, con->sess->max_desc);
		if (sg_offset_p)
			*sg_offset_p = 0;
		return 1;
	}

	desc = ibtrs_fr_pool_get(con->fr_pool);
	if (!desc) {
		ibtrs_wrn_rl(con->sess, "Failed to get descriptor from FR pool\n");
		return -ENOMEM;
	}

	rkey = ib_inc_rkey(desc->mr->rkey);
	ib_update_fast_reg_key(desc->mr, rkey);

	memset(&wr, 0, sizeof(wr));
	n = ib_map_mr_sg(desc->mr, state->sg, sg_cnt, sg_offset_p,
			 con->sess->mr_page_size);
	if (unlikely(n < 0)) {
		ibtrs_fr_pool_put(con->fr_pool, &desc, 1);
		return n;
	}

	wr.wr.next = NULL;
	wr.wr.opcode = IB_WR_REG_MR;
	wr.wr.wr_cqe = &fast_reg_cqe;
	wr.wr.num_sge = 0;
	wr.wr.send_flags = 0;
	wr.mr = desc->mr;
	wr.key = desc->mr->rkey;
	wr.access = (IB_ACCESS_LOCAL_WRITE | IB_ACCESS_REMOTE_WRITE);

	*state->next_fr++ = desc;
	state->nmdesc++;

	ibtrs_map_desc(state, state->base_dma_addr, state->dma_len,
		       desc->mr->rkey, con->sess->max_desc);

	return ib_post_send(con->c.qp, &wr.wr, &bad_wr);
}

static int ibtrs_finish_fmr_mapping(struct ibtrs_map_state *state,
				    struct ibtrs_clt_con *con)
{
	int ret = 0;
	struct ib_pd *pd = con->sess->s.ib_dev->pd;

	if (state->npages == 0)
		return 0;

	if (state->npages == 1 && (pd->flags & IB_PD_UNSAFE_GLOBAL_RKEY))
		ibtrs_map_desc(state, state->base_dma_addr, state->dma_len,
			       pd->unsafe_global_rkey,
			       con->sess->max_desc);
	else
		ret = ibtrs_map_finish_fmr(state, con);

	if (ret == 0) {
		state->npages = 0;
		state->dma_len = 0;
	}

	return ret;
}

static int ibtrs_map_sg_entry(struct ibtrs_map_state *state,
			      struct ibtrs_clt_con *con, struct scatterlist *sg,
			      int sg_count)
{
	struct ib_device *ibdev = con->sess->s.ib_dev->dev;
	dma_addr_t dma_addr = ib_sg_dma_address(ibdev, sg);
	unsigned int dma_len = ib_sg_dma_len(ibdev, sg);
	unsigned int len;
	int ret;

	if (!dma_len)
		return 0;

	while (dma_len) {
		unsigned offset = dma_addr & ~con->sess->mr_page_mask;

		if (state->npages == con->sess->max_pages_per_mr ||
		    offset != 0) {
			ret = ibtrs_finish_fmr_mapping(state, con);
			if (ret)
				return ret;
		}

		len = min_t(unsigned int, dma_len,
			    con->sess->mr_page_size - offset);

		if (!state->npages)
			state->base_dma_addr = dma_addr;
		state->pages[state->npages++] =
			dma_addr & con->sess->mr_page_mask;
		state->dma_len += len;
		dma_addr += len;
		dma_len -= len;
	}

	/*
	 * If the last entry of the MR wasn't a full page, then we need to
	 * close it out and start a new one -- we can only merge at page
	 * boundaries.
	 */
	ret = 0;
	if (len != con->sess->mr_page_size)
		ret = ibtrs_finish_fmr_mapping(state, con);
	return ret;
}

static int ibtrs_map_fr(struct ibtrs_map_state *state,
			struct ibtrs_clt_con *con,
			struct scatterlist *sg, int sg_count)
{
	unsigned int sg_offset = 0;
	state->sg = sg;

	while (sg_count) {
		int i, n;

		n = ibtrs_map_finish_fr(state, con, sg_count, &sg_offset);
		if (unlikely(n < 0))
			return n;

		sg_count -= n;
		for (i = 0; i < n; i++)
			state->sg = sg_next(state->sg);
	}

	return 0;
}
static int ibtrs_map_fmr(struct ibtrs_map_state *state,
			 struct ibtrs_clt_con *con,
			 struct scatterlist *sg_first_entry,
			 int sg_first_entry_index, int sg_count)
{
	int i, ret;
	struct scatterlist *sg;

	for (i = sg_first_entry_index, sg = sg_first_entry; i < sg_count;
	     i++, sg = sg_next(sg)) {
		ret = ibtrs_map_sg_entry(state, con, sg, sg_count);
		if (ret)
			return ret;
	}
	return 0;
}

static int ibtrs_map_sg(struct ibtrs_map_state *state,
			struct ibtrs_clt_con *con,
			struct rdma_req *req)
{
	int ret = 0;

	state->pages = req->map_page;
	if (con->sess->fast_reg_mode == IBTRS_FAST_MEM_FR) {
		state->next_fr = req->fr_list;
		ret = ibtrs_map_fr(state, con, req->sglist, req->sg_cnt);
		if (ret)
			goto out;
	} else if (con->sess->fast_reg_mode == IBTRS_FAST_MEM_FMR) {
		state->next_fmr = req->fmr_list;
		ret = ibtrs_map_fmr(state, con, req->sglist, 0,
				    req->sg_cnt);
		if (ret)
			goto out;
		ret = ibtrs_finish_fmr_mapping(state, con);
		if (ret)
			goto out;
	}



out:
	req->nmdesc = state->nmdesc;
	return ret;
}

static void ibtrs_clt_inv_rkey_done(struct ib_cq *cq, struct ib_wc *wc)
{
	struct ibtrs_clt_con *con = cq->cq_context;
	struct ibtrs_clt_sess *sess = con->sess;

	if (unlikely(wc->status != IB_WC_SUCCESS)) {
		ibtrs_err(sess, "Failed IB_WR_LOCAL_INV: %s\n",
			  ib_wc_status_msg(wc->status));
		ibtrs_rdma_error_recovery(con);
	}
}

static struct ib_cqe local_inv_cqe = {
	.done = ibtrs_clt_inv_rkey_done
};

static int ibtrs_inv_rkey(struct ibtrs_clt_con *con, u32 rkey)
{
	struct ib_send_wr *bad_wr;
	struct ib_send_wr wr = {
		.opcode		    = IB_WR_LOCAL_INV,
		.wr_cqe		    = &local_inv_cqe,
		.next		    = NULL,
		.num_sge	    = 0,
		.send_flags	    = 0,
		.ex.invalidate_rkey = rkey,
	};

	return ib_post_send(con->c.qp, &wr, &bad_wr);
}

static void ibtrs_unmap_fast_reg_data(struct ibtrs_clt_con *con,
				      struct rdma_req *req)
{
	int i, ret;

	if (con->sess->fast_reg_mode == IBTRS_FAST_MEM_FR) {
		struct ibtrs_fr_desc **pfr;

		for (i = req->nmdesc, pfr = req->fr_list; i > 0; i--, pfr++) {
			ret = ibtrs_inv_rkey(con, (*pfr)->mr->rkey);
			if (ret < 0) {
				ibtrs_err(con->sess,
					  "Invalidating registered RDMA memory for"
					  " rkey %#x failed, err: %d\n",
					  (*pfr)->mr->rkey, ret);
			}
		}
		if (req->nmdesc)
			ibtrs_fr_pool_put(con->fr_pool, req->fr_list,
					  req->nmdesc);
	} else {
		struct ib_pool_fmr **pfmr;

		for (i = req->nmdesc, pfmr = req->fmr_list; i > 0; i--, pfmr++)
			ib_fmr_pool_unmap(*pfmr);
	}
	req->nmdesc = 0;
}

/*
 * We have more scatter/gather entries, so use fast_reg_map
 * trying to merge as many entries as we can.
 */
static int ibtrs_fast_reg_map_data(struct ibtrs_clt_con *con,
				   struct ibtrs_sg_desc *desc,
				   struct rdma_req *req)
{
	struct ibtrs_map_state state;
	int ret;

	memset(&state, 0, sizeof(state));
	state.desc	= desc;
	state.dir	= req->dir;
	ret = ibtrs_map_sg(&state, con, req);

	if (unlikely(ret))
		goto unmap;

	if (unlikely(state.ndesc <= 0)) {
		ibtrs_err(con->sess,
			  "Could not fit S/G list into buffer descriptor %d\n",
			  state.ndesc);
		ret = -EIO;
		goto unmap;
	}

	return state.ndesc;
unmap:
	ibtrs_unmap_fast_reg_data(con, req);
	return ret;
}

static int ibtrs_post_send_rdma(struct ibtrs_clt_con *con, struct rdma_req *req,
				u64 addr, u32 off, u32 imm)
{
	struct ibtrs_clt_sess *sess = con->sess;
	enum ib_send_flags flags;
	struct ib_sge list[1];

	pr_debug("called, imm: %x\n", imm);
	if (unlikely(!req->sg_size)) {
		ibtrs_wrn(con->sess, "Doing RDMA Write failed, no data supplied\n");
		return -EINVAL;
	}

	/* user data and user message in the first list element */
	list[0].addr   = req->iu->dma_addr;
	list[0].length = req->sg_size;
	list[0].lkey   = sess->s.ib_dev->pd->local_dma_lkey;

	/*
	 * From time to time we have to post signalled sends,
	 * or send queue will fill up and only QP reset can help.
	 */
	flags = atomic_inc_return(&con->io_cnt) % sess->queue_depth ?
			0 : IB_SEND_SIGNALED;
	return ibtrs_post_rdma_write_imm(&con->c, req->iu, list, 1,
					 sess->srv_rdma_buf_rkey,
					 addr + off, imm, flags,
					 ibtrs_clt_rdma_done);
}

static void ibtrs_set_sge_with_desc(struct ib_sge *list,
				    struct ibtrs_sg_desc *desc)
{
	list->addr   = le64_to_cpu(desc->addr);
	list->length = le32_to_cpu(desc->len);
	list->lkey   = le32_to_cpu(desc->key);
	pr_debug("dma_addr %llu, key %u, dma_len %u\n",
		 list->addr, list->lkey, list->length);
}

static void ibtrs_set_rdma_desc_last(struct ibtrs_clt_con *con,
				     struct ib_sge *list,
				     struct rdma_req *req,
				     struct ib_rdma_wr *wr, int offset,
				     struct ibtrs_sg_desc *desc, int m,
				     int n, u64 addr, u32 size, u32 imm)
{
	struct ibtrs_clt_sess *sess = con->sess;
	enum ib_send_flags flags;
	int i;

	for (i = m; i < n; i++, desc++)
		ibtrs_set_sge_with_desc(&list[i], desc);

	list[i].addr   = req->iu->dma_addr;
	list[i].length = size;
	list[i].lkey   = sess->s.ib_dev->pd->local_dma_lkey;

	req->iu->cqe.done = ibtrs_clt_rdma_done;

	wr->wr.wr_cqe = &req->iu->cqe;
	wr->wr.sg_list = &list[m];
	wr->wr.num_sge = n - m + 1;
	wr->remote_addr	= addr + offset;
	wr->rkey = sess->srv_rdma_buf_rkey;

	/*
	 * From time to time we have to post signalled sends,
	 * or send queue will fill up and only QP reset can help.
	 */
	flags = atomic_inc_return(&con->io_cnt) % sess->queue_depth ?
			0 : IB_SEND_SIGNALED;

	wr->wr.opcode = IB_WR_RDMA_WRITE_WITH_IMM;
	wr->wr.send_flags  = flags;
	wr->wr.ex.imm_data = cpu_to_be32(imm);
}

static int ibtrs_post_send_rdma_desc_more(struct ibtrs_clt_con *con,
					  struct ib_sge *list,
					  struct rdma_req *req,
					  struct ibtrs_sg_desc *desc, int n,
					  u64 addr, u32 size, u32 imm)
{
	int ret;
	size_t num_sge = 1 + n;
	struct ibtrs_clt_sess *sess = con->sess;
	int max_sge = sess->max_sge;
	int num_wr =  DIV_ROUND_UP(num_sge, max_sge);
	struct ib_send_wr *bad_wr;
	struct ib_rdma_wr *wrs, *wr;
	int j = 0, k, offset = 0, len = 0;
	int m = 0;

	wrs = kcalloc(num_wr, sizeof(*wrs), GFP_ATOMIC);
	if (!wrs)
		return -ENOMEM;

	if (num_wr == 1)
		goto last_one;

	for (; j < num_wr; j++) {
		wr = &wrs[j];
		for (k = 0; k < max_sge; k++, desc++) {
			m = k + j * max_sge;
			ibtrs_set_sge_with_desc(&list[m], desc);
			len += le32_to_cpu(desc->len);
		}
		req->iu->cqe.done = ibtrs_clt_rdma_done;

		wr->wr.wr_cqe = &req->iu->cqe;
		wr->wr.sg_list = &list[m];
		wr->wr.num_sge = max_sge;
		wr->remote_addr	= addr + offset;
		wr->rkey = sess->srv_rdma_buf_rkey;

		offset += len;
		wr->wr.next = &wrs[j + 1].wr;
		wr->wr.opcode = IB_WR_RDMA_WRITE;
	}

last_one:
	wr = &wrs[j];

	ibtrs_set_rdma_desc_last(con, list, req, wr, offset, desc, m, n, addr,
				 size, imm);

	ret = ib_post_send(con->c.qp, &wrs[0].wr, &bad_wr);
	if (unlikely(ret))
		ibtrs_err(sess, "Posting RDMA-Write-Request to QP failed,"
			  " err: %d\n", ret);
	kfree(wrs);
	return ret;
}

static int ibtrs_post_send_rdma_desc(struct ibtrs_clt_con *con,
				     struct rdma_req *req,
				     struct ibtrs_sg_desc *desc, int n,
				     u64 addr, u32 size, u32 imm)
{
	struct ibtrs_clt_sess *sess = con->sess;
	enum ib_send_flags flags;
	struct ib_sge *list;
	size_t num_sge;
	int ret, i;

	num_sge = 1 + n;
	list = kmalloc_array(num_sge, sizeof(*list), GFP_ATOMIC);
	if (!list)
		return -ENOMEM;

	if (num_sge < sess->max_sge) {
		for (i = 0; i < n; i++, desc++)
			ibtrs_set_sge_with_desc(&list[i], desc);
		list[i].addr   = req->iu->dma_addr;
		list[i].length = size;
		list[i].lkey   = sess->s.ib_dev->pd->local_dma_lkey;

		/*
		 * From time to time we have to post signalled sends,
		 * or send queue will fill up and only QP reset can help.
		 */
		flags = atomic_inc_return(&con->io_cnt) % sess->queue_depth ?
				0 : IB_SEND_SIGNALED;
		ret = ibtrs_post_rdma_write_imm(&con->c, req->iu, list, num_sge,
						sess->srv_rdma_buf_rkey,
						addr, imm, flags,
						ibtrs_clt_rdma_done);
	} else
		ret = ibtrs_post_send_rdma_desc_more(con, list, req, desc, n,
						     addr, size, imm);

	kfree(list);
	return ret;
}

static int ibtrs_post_send_rdma_more(struct ibtrs_clt_con *con,
				     struct rdma_req *req,
				     u64 addr, u32 size, u32 imm)
{
	struct ibtrs_clt_sess *sess = con->sess;
	struct ib_device *ibdev = sess->s.ib_dev->dev;
	enum ib_send_flags flags;
	struct scatterlist *sg;
	struct ib_sge *list;
	size_t num_sge;
	int i, ret;

	num_sge = 1 + req->sg_cnt;
	list = kmalloc_array(num_sge, sizeof(*list), GFP_ATOMIC);
	if (!list)
		return -ENOMEM;

	for_each_sg(req->sglist, sg, req->sg_cnt, i) {
		list[i].addr   = ib_sg_dma_address(ibdev, sg);
		list[i].length = ib_sg_dma_len(ibdev, sg);
		list[i].lkey   = sess->s.ib_dev->pd->local_dma_lkey;
	}
	list[i].addr   = req->iu->dma_addr;
	list[i].length = size;
	list[i].lkey   = sess->s.ib_dev->pd->local_dma_lkey;

	/*
	 * From time to time we have to post signalled sends,
	 * or send queue will fill up and only QP reset can help.
	 */
	flags = atomic_inc_return(&con->io_cnt) % sess->queue_depth ?
			0 : IB_SEND_SIGNALED;
	ret = ibtrs_post_rdma_write_imm(&con->c, req->iu, list, num_sge,
					sess->srv_rdma_buf_rkey,
					addr, imm, flags,
					ibtrs_clt_rdma_done);
	kfree(list);

	return ret;
}

static inline int ibtrs_clt_ms_to_id(unsigned long ms)
{
	int id = ms ? ilog2(ms) - MIN_LOG_LATENCY + 1 : 0;

	return clamp(id, 0, MAX_LOG_LATENCY - MIN_LOG_LATENCY + 1);
}

static void ibtrs_clt_update_rdma_lat(struct ibtrs_clt_stats *s, bool read,
				      unsigned long ms)
{
	const int id = ibtrs_clt_ms_to_id(ms);
	const int cpu = raw_smp_processor_id();

	if (read) {
		s->rdma_lat_distr[cpu][id].read++;
		if (s->rdma_lat_max[cpu].read < ms)
			s->rdma_lat_max[cpu].read = ms;
	} else {
		s->rdma_lat_distr[cpu][id].write++;
		if (s->rdma_lat_max[cpu].write < ms)
			s->rdma_lat_max[cpu].write = ms;
	}
}

static inline unsigned long ibtrs_clt_get_raw_ms(void)
{
	struct timespec ts;

	getrawmonotonic(&ts);

	return timespec_to_ns(&ts) / NSEC_PER_MSEC;
}

static inline void ibtrs_clt_decrease_inflight(struct ibtrs_clt_stats *s)
{
	s->rdma_stats[raw_smp_processor_id()].inflight--;
}

static void complete_rdma_req(struct ibtrs_clt_sess *sess,
			      struct rdma_req *req, int errno)
{
	enum dma_data_direction dir;
	void *priv;

	if (WARN_ON(!req->in_use))
		return;
	if (req->sg_cnt > fmr_sg_cnt)
		ibtrs_unmap_fast_reg_data(req->con, req);
	if (req->sg_cnt)
		ib_dma_unmap_sg(sess->s.ib_dev->dev, req->sglist,
				req->sg_cnt, req->dir);
	if (sess->enable_rdma_lat)
		ibtrs_clt_update_rdma_lat(&sess->stats,
					  req->dir == DMA_FROM_DEVICE,
					  ibtrs_clt_get_raw_ms() -
					  req->start_time);
	ibtrs_clt_decrease_inflight(&sess->stats);

	req->in_use = false;
	/* paired with fail_all_outstanding_reqs() */
	smp_wmb();
	req->con = NULL;
	priv = req->priv;
	dir = req->dir;

	sess->ops.rdma_ev(priv, dir == DMA_FROM_DEVICE ?
			  IBTRS_CLT_RDMA_EV_RDMA_REQUEST_WRITE_COMPL :
			  IBTRS_CLT_RDMA_EV_RDMA_WRITE_COMPL, errno);
}

static void process_io_rsp(struct ibtrs_clt_sess *sess, u32 msg_id, s16 errno)
{
	if (WARN_ON(msg_id >= sess->queue_depth))
		return;

	complete_rdma_req(sess, &sess->reqs[msg_id], errno);
}

static void ibtrs_clt_ack_done(struct ib_cq *cq, struct ib_wc *wc)
{
	struct ibtrs_clt_con *con = cq->cq_context;
	struct ibtrs_clt_sess *sess = con->sess;

	if (unlikely(wc->status != IB_WC_SUCCESS)) {
		ibtrs_err(sess, "Failed ACK: %s\n",
			  ib_wc_status_msg(wc->status));
		ibtrs_rdma_error_recovery(con);
	}
}

static struct ib_cqe ack_cqe = {
	.done = ibtrs_clt_ack_done
};

static int ibtrs_send_msg_user_ack(struct ibtrs_clt_con *con)
{
	struct ibtrs_clt_sess *sess = con->sess;
	int err;

	ibtrs_clt_state_lock();
	if (unlikely(sess->state != IBTRS_CLT_CONNECTED)) {
		ibtrs_clt_state_unlock();
		ibtrs_info(sess, "Sending user msg ack failed, disconnected."
			   " Session state is %s\n",
			   ibtrs_clt_state_str(sess->state));
		return -ECOMM;
	}

	err = ibtrs_post_rdma_write_imm_empty(&con->c, &ack_cqe,
					      IBTRS_ACK_IMM,
					      IB_SEND_SIGNALED);
	ibtrs_clt_state_unlock();
	if (unlikely(err)) {
		ibtrs_err_rl(sess, "Sending user msg ack failed, err: %d\n",
			     err);
		return err;
	}

	return 0;
}

static void msg_worker(struct work_struct *work)
{
	struct ibtrs_clt_sess *sess;
	struct ibtrs_msg_user *msg;
	struct ibtrs_clt_con *con;
	struct msg_work *w;
	size_t len;

	w = container_of(work, struct msg_work, work);
	con = w->con;
	msg = w->msg;
	kfree(w);

	len = le16_to_cpu(msg->psize);
	sess = con->sess;

	sess->stats.user_ib_msgs.recv_msg_cnt++;
	sess->stats.user_ib_msgs.recv_size += len;

	sess->ops.recv(sess->ops.priv, msg->payl, len);
	kfree(msg);
}

static int ibtrs_schedule_msg(struct ibtrs_clt_con *con,
			      struct ibtrs_msg_user *msg)
{
	struct msg_work *w;
	size_t len;

	len = le16_to_cpu(msg->psize) + sizeof(*msg);

	/*
	 * FIXME: that is ugly, and better way is to notify API client
	 *        calling cb directly.  We should not care about contexts.
	 */

	w = kmalloc(sizeof(*w), GFP_ATOMIC);
	if (unlikely(!w))
		return -ENOMEM;

	w->con = con;
	w->msg = kmalloc(len, GFP_ATOMIC);
	if (unlikely(!w->msg)) {
		kfree(w);
		return -ENOMEM;
	}
	memcpy(w->msg, msg, len);
	INIT_WORK(&w->work, msg_worker);
	queue_work(ibtrs_wq, &w->work);

	return 0;
}

static void ibtrs_clt_update_wc_stats(struct ibtrs_clt_con *con)
{
	struct ibtrs_clt_sess *sess = con->sess;
	unsigned cpu = con->cpu;

	if (unlikely(con->cpu != cpu)) {
		pr_debug_ratelimited("WC processing is migrated from CPU %d to "
				     "%d, state %s, user: %s\n",
				     con->cpu, cpu,
				     ibtrs_clt_state_str(sess->state),
				     con->cid == 0 ? "true" : "false");
		atomic_inc(&sess->stats.cpu_migr.from[con->cpu]);
		sess->stats.cpu_migr.to[cpu]++;
	}
	sess->stats.wc_comp[cpu].cnt++;
	sess->stats.wc_comp[cpu].total_cnt++;
}

static struct ib_cqe io_comp_cqe = {
	.done = ibtrs_clt_rdma_done
};

static void ibtrs_clt_rdma_done(struct ib_cq *cq, struct ib_wc *wc)
{
	struct ibtrs_clt_con *con = cq->cq_context;
	struct ibtrs_clt_sess *sess = con->sess;
	u32 imm, msg_id;
	int err;

	WARN_ON(!con->cid);

	if (unlikely(wc->status != IB_WC_SUCCESS)) {
		if (wc->status != IB_WC_WR_FLUSH_ERR) {
			ibtrs_err(sess, "RDMA failed: %s\n",
				  ib_wc_status_msg(wc->status));
			ibtrs_rdma_error_recovery(con);
		}
		return;
	}
	ibtrs_clt_update_wc_stats(con);

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
			ibtrs_err(sess, "ibtrs_post_recv_empty(), err: %d\n", err);
			ibtrs_rdma_error_recovery(con);
			break;
		}
		imm = be32_to_cpu(wc->ex.imm_data);
		msg_id = imm >> 16;
		err = (imm << 16) >> 16;
		process_io_rsp(sess, msg_id, err);
		break;
	default:
		WARN(1, "Unknown wc->opcode %d", wc->opcode);
		return;
	}
}

static void ibtrs_clt_usr_send_done(struct ib_cq *cq, struct ib_wc *wc)
{
	struct ibtrs_clt_con *con = cq->cq_context;
	struct ibtrs_clt_sess *sess = con->sess;
	struct ibtrs_iu *iu;

	iu = container_of(wc->wr_cqe, struct ibtrs_iu, cqe);
	ibtrs_usr_msg_return_iu(&sess->s, iu);

	if (unlikely(wc->status != IB_WC_SUCCESS)) {
		ibtrs_err(sess, "User message send failed: %s\n",
			  ib_wc_status_msg(wc->status));
		ibtrs_rdma_error_recovery(con);
		return;
	}
	WARN_ON(wc->opcode != IB_WC_SEND);

	ibtrs_clt_update_wc_stats(con);
}

static void ibtrs_clt_usr_recv_done(struct ib_cq *cq, struct ib_wc *wc);

static int process_usr_msg(struct ibtrs_clt_con *con, struct ib_wc *wc)
{
	struct ibtrs_clt_sess *sess = con->sess;
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
	msg = (struct ibtrs_msg_user *)iu->buf;
	type = le16_to_cpu(msg->type);

	switch (type) {
	case IBTRS_MSG_USER:
		err = ibtrs_schedule_msg(con, msg);
		if (unlikely(err)) {
			ibtrs_err(sess, "ibtrs_schedule_msg(), err: %d\n", err);
			goto out;
		}
		err = ibtrs_post_recv(&con->c, iu, ibtrs_clt_usr_recv_done);
		if (unlikely(err)) {
			ibtrs_err(sess, "ibtrs_post_recv(), err: %d\n", err);
			goto out;
		}
		err = ibtrs_send_msg_user_ack(con);
		if (unlikely(err)) {
			ibtrs_err(sess, "ibtrs_send_msg_user_ack(), err: %d\n",
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

static int process_usr_msg_ack(struct ibtrs_clt_con *con, struct ib_wc *wc)
{
	struct ibtrs_clt_sess *sess = con->sess;
	struct ibtrs_iu *iu;
	int err;
	u32 imm;

	iu = container_of(wc->wr_cqe, struct ibtrs_iu, cqe);
	imm = be32_to_cpu(wc->ex.imm_data);
	if (WARN_ON(imm != IBTRS_ACK_IMM))
		return -ENOENT;

	ibtrs_usr_msg_put(&sess->s);

	err = ibtrs_post_recv(&con->c, iu, ibtrs_clt_usr_recv_done);
	if (unlikely(err))
		ibtrs_err(sess, "ibtrs_post_recv(), err: %d\n", err);

	return err;
}

static void ibtrs_clt_usr_recv_done(struct ib_cq *cq, struct ib_wc *wc)
{
	struct ibtrs_clt_con *con = cq->cq_context;
	struct ibtrs_clt_sess *sess = con->sess;
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
	ibtrs_clt_update_wc_stats(con);

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
	ibtrs_rdma_error_recovery(con);
}

static int post_recv_io(struct ibtrs_clt_con *con)
{
	struct ibtrs_clt_sess *sess = con->sess;
	int err, i;

	for (i = 0; i < sess->queue_depth; i++) {
		err = ibtrs_post_recv_empty(&con->c, &io_comp_cqe);
		if (unlikely(err))
			return err;
	}

	return 0;
}

static int post_recv_usr(struct ibtrs_clt_con *con)
{
	struct ibtrs_clt_sess *sess = con->sess;
	struct ibtrs_iu *iu;
	int err, i;

	for (i = 0; i < USR_CON_BUF_SIZE; i++) {
		iu = sess->s.usr_rx_ring[i];
		err = ibtrs_post_recv(&con->c, iu, ibtrs_clt_usr_recv_done);
		if (unlikely(err))
			return err;
	}

	return 0;
}

static int post_recv(struct ibtrs_clt_con *con)
{
	if (con->cid == 0)
		return post_recv_usr(con);
	return post_recv_io(con);
}

static int post_recv_sess(struct ibtrs_clt_sess *sess)
{
	int err, cid;

	for (cid = 0; cid < CONS_PER_SESSION; cid++) {
		err = post_recv(sess->con[cid]);
		if (unlikely(err)) {
			ibtrs_err(sess, "post_recv(), err: %d\n", err);
			return err;
		}
	}

	return 0;
}

static void fail_all_outstanding_reqs(struct ibtrs_clt_sess *sess)
{
	struct rdma_req *req;
	int i;

	if (WARN_ON(!sess->reqs))
		return;
	/* paired with ibtrs_clt_[request_]rdma_write(),complete_rdma_req() */
	smp_rmb();
	for (i = 0; i < sess->queue_depth; ++i) {
		req = &sess->reqs[i];
		if (req->in_use)
			complete_rdma_req(sess, req, -ECONNABORTED);
	}
}

static void free_sess_reqs(struct ibtrs_clt_sess *sess)
{
	struct rdma_req *req;
	int i;

	for (i = 0; i < sess->queue_depth; ++i) {
		req = &sess->reqs[i];
		if (sess->fast_reg_mode == IBTRS_FAST_MEM_FR)
			kfree(req->fr_list);
		else if (sess->fast_reg_mode == IBTRS_FAST_MEM_FMR)
			kfree(req->fmr_list);
		kfree(req->map_page);
	}
	kfree(sess->reqs);
	sess->reqs = NULL;
}

static int alloc_sess_reqs(struct ibtrs_clt_sess *sess)
{
	struct rdma_req *req;
	void *mr_list;
	int i;

	sess->reqs = kcalloc(sess->queue_depth, sizeof(*sess->reqs),
			     GFP_KERNEL);
	if (unlikely(!sess->reqs))
		return -ENOMEM;

	for (i = 0; i < sess->queue_depth; ++i) {
		req = &sess->reqs[i];
		mr_list = kmalloc_array(sess->max_pages_per_mr,
					sizeof(void *), GFP_KERNEL);
		if (unlikely(!mr_list))
			goto out;
		if (sess->fast_reg_mode == IBTRS_FAST_MEM_FR)
			req->fr_list = mr_list;
		else if (sess->fast_reg_mode == IBTRS_FAST_MEM_FMR)
			req->fmr_list = mr_list;

		req->map_page = kmalloc(sess->max_pages_per_mr *
					sizeof(void *), GFP_KERNEL);
		if (unlikely(!req->map_page))
			goto out;
	}

	return 0;

out:
	free_sess_reqs(sess);

	return -ENOMEM;
}

static void free_sess_tx_bufs(struct ibtrs_clt_sess *sess)
{
	int i;

	if (sess->io_tx_ius) {
		for (i = 0; i < sess->queue_depth; i++)
			if (sess->io_tx_ius[i])
				ibtrs_iu_free(sess->io_tx_ius[i], DMA_TO_DEVICE,
					      sess->s.ib_dev->dev);

		kfree(sess->io_tx_ius);
		sess->io_tx_ius = NULL;
	}
	ibtrs_usr_msg_free_list(&sess->s, sess->s.ib_dev);
}

static int alloc_sess_tx_bufs(struct ibtrs_clt_sess *sess)
{
	u32 max_req_size = sess->max_req_size;
	struct ibtrs_iu *iu;
	int i, err;

	sess->io_tx_ius = kcalloc(sess->queue_depth, sizeof(*sess->io_tx_ius),
				  GFP_KERNEL);
	if (unlikely(!sess->io_tx_ius))
		goto err;

	for (i = 0; i < sess->queue_depth; ++i) {
		iu = ibtrs_iu_alloc(i, max_req_size, GFP_KERNEL,
				    sess->s.ib_dev->dev, DMA_TO_DEVICE);
		if (unlikely(!iu))
			goto err;
		sess->io_tx_ius[i] = iu;
	}
	err = ibtrs_usr_msg_alloc_list(&sess->s, sess->s.ib_dev,
				       max_req_size);
	if (unlikely(err))
		goto err;

	return 0;

err:
	ibtrs_err(sess, "ibtrs_iu_alloc() failed\n");
	free_sess_tx_bufs(sess);

	return -ENOMEM;
}

static int alloc_sess_tags(struct ibtrs_clt_sess *sess)
{
	int err, i;

	sess->tags_map = kzalloc(BITS_TO_LONGS(sess->queue_depth) *
				 sizeof(long), GFP_KERNEL);
	if (!sess->tags_map) {
		ibtrs_err(sess, "Failed to alloc tags bitmap\n");
		err = -ENOMEM;
		goto out_err;
	}

	sess->tags = kcalloc(sess->queue_depth, TAG_SIZE(sess),
			     GFP_KERNEL);
	if (!sess->tags) {
		ibtrs_err(sess, "Failed to alloc memory for tags\n");
		err = -ENOMEM;
		goto err_map;
	}

	for (i = 0; i < sess->queue_depth; i++) {
		struct ibtrs_tag *tag;

		tag = GET_TAG(sess, i);
		tag->mem_id = i;
		tag->mem_id_mask = i << ((IB_IMM_SIZE_BITS - 1) -
					 ilog2(sess->queue_depth - 1));
	}

	return 0;

err_map:
	kfree(sess->tags_map);
	sess->tags_map = NULL;
out_err:
	return err;
}

static void query_fast_reg_mode(struct ibtrs_clt_sess *sess)
{
	struct ib_device_attr *dev_attr;
	struct ib_device *ibdev;
	u64 max_pages_per_mr;
	int mr_page_shift;

	ibdev = sess->s.ib_dev->dev;
	dev_attr = &ibdev->attrs;

	if (ibdev->alloc_fmr && ibdev->dealloc_fmr &&
	    ibdev->map_phys_fmr && ibdev->unmap_fmr) {
		sess->fast_reg_mode = IBTRS_FAST_MEM_FMR;
		ibtrs_info(sess, "Device %s supports FMR\n", ibdev->name);
	}
	if (dev_attr->device_cap_flags & IB_DEVICE_MEM_MGT_EXTENSIONS &&
	    use_fr) {
		sess->fast_reg_mode = IBTRS_FAST_MEM_FR;
		ibtrs_info(sess, "Device %s supports FR\n", ibdev->name);
	}

	/*
	 * Use the smallest page size supported by the HCA, down to a
	 * minimum of 4096 bytes. We're unlikely to build large sglists
	 * out of smaller entries.
	 */
	mr_page_shift      = max(12, ffs(dev_attr->page_size_cap) - 1);
	sess->mr_page_size = 1 << mr_page_shift;
	sess->max_sge      = dev_attr->max_sge;
	sess->mr_page_mask = ~((u64)sess->mr_page_size - 1);
	max_pages_per_mr   = dev_attr->max_mr_size;
	do_div(max_pages_per_mr, sess->mr_page_size);
	sess->max_pages_per_mr = min_t(u64, sess->max_pages_per_mr,
				       max_pages_per_mr);
	if (sess->fast_reg_mode == IBTRS_FAST_MEM_FR) {
		sess->max_pages_per_mr = min_t(u32, sess->max_pages_per_mr,
					  dev_attr->max_fast_reg_page_list_len);
	}
	sess->mr_max_size = sess->mr_page_size * sess->max_pages_per_mr;

	pr_debug("%s: mr_page_shift = %d, dev_attr->max_mr_size = %#llx, "
		 "dev_attr->max_fast_reg_page_list_len = %u, max_pages_per_mr = %d, "
		 "mr_max_size = %#x\n", ibdev->name, mr_page_shift,
		 dev_attr->max_mr_size, dev_attr->max_fast_reg_page_list_len,
		 sess->max_pages_per_mr, sess->mr_max_size);
}

static int alloc_con_fast_pool(struct ibtrs_clt_con *con)
{
	struct ibtrs_clt_sess *sess = con->sess;
	struct ibtrs_fr_pool *fr_pool;
	int err = 0;

	if (sess->fast_reg_mode == IBTRS_FAST_MEM_FR) {
		fr_pool = ibtrs_create_fr_pool(sess->s.ib_dev->dev,
					       sess->s.ib_dev->pd,
					       sess->queue_depth,
					       sess->max_pages_per_mr);
		if (unlikely(IS_ERR(fr_pool))) {
			err = PTR_ERR(fr_pool);
			ibtrs_err(sess, "FR pool allocation failed, err: %d\n",
				  err);
			return err;
		}
		con->fr_pool = fr_pool;
	}

	return err;
}

static void free_con_fast_pool(struct ibtrs_clt_con *con)
{
	if (con->fr_pool) {
		ibtrs_destroy_fr_pool(con->fr_pool);
		con->fr_pool = NULL;
	}
}

static int alloc_sess_fast_pool(struct ibtrs_clt_sess *sess)
{
	struct ib_fmr_pool_param fmr_param;
	struct ib_fmr_pool *fmr_pool;
	int err = 0;

	if (sess->fast_reg_mode == IBTRS_FAST_MEM_FMR) {
		memset(&fmr_param, 0, sizeof(fmr_param));
		fmr_param.pool_size	    = sess->queue_depth *
					      sess->max_pages_per_mr;
		fmr_param.dirty_watermark   = fmr_param.pool_size / 4;
		fmr_param.cache		    = 0;
		fmr_param.max_pages_per_fmr = sess->max_pages_per_mr;
		fmr_param.page_shift	    = ilog2(sess->mr_page_size);
		fmr_param.access	    = (IB_ACCESS_LOCAL_WRITE |
					       IB_ACCESS_REMOTE_WRITE);

		fmr_pool = ib_create_fmr_pool(sess->s.ib_dev->pd, &fmr_param);
		if (unlikely(IS_ERR(fmr_pool))) {
			err = PTR_ERR(fmr_pool);
			ibtrs_err(sess, "FMR pool allocation failed, err: %d\n",
				  err);
			return err;
		}
		sess->fmr_pool = fmr_pool;
	}

	return err;
}

static void free_sess_fast_pool(struct ibtrs_clt_sess *sess)
{
	if (sess->fmr_pool) {
		ib_destroy_fmr_pool(sess->fmr_pool);
		sess->fmr_pool = NULL;
	}
}

int ibtrs_clt_stats_migration_cnt_to_str(struct ibtrs_clt_sess *sess, char *buf,
					 size_t len)
{
	int i;
	size_t used = 0;

	used += scnprintf(buf + used, len - used, "    ");

	for (i = 0; i < num_online_cpus(); i++)
		used += scnprintf(buf + used, len - used, " CPU%u", i);

	used += scnprintf(buf + used, len - used, "\nfrom:");

	for (i = 0; i < num_online_cpus(); i++)
		used += scnprintf(buf + used, len - used, " %d",
				  atomic_read(&sess->stats.cpu_migr.from[i]));

	used += scnprintf(buf + used, len - used, "\n"
			  "to  :");

	for (i = 0; i < num_online_cpus(); i++)
		used += scnprintf(buf + used, len - used, " %d",
				  sess->stats.cpu_migr.to[i]);

	used += scnprintf(buf + used, len - used, "\n");

	return used;
}

int ibtrs_clt_reset_reconnects_stat(struct ibtrs_clt_sess *sess, bool enable)
{
	if (enable) {
		memset(&sess->stats.reconnects, 0,
		       sizeof(sess->stats.reconnects));
		return 0;
	}

	return -EINVAL;
}

int ibtrs_clt_stats_reconnects_to_str(struct ibtrs_clt_sess *sess, char *buf,
				      size_t len)
{
	return scnprintf(buf, len, "%u %u\n",
			 sess->stats.reconnects.successful_cnt,
			 sess->stats.reconnects.fail_cnt);
}

int ibtrs_clt_reset_user_ib_msgs_stats(struct ibtrs_clt_sess *sess, bool enable)
{
	if (enable) {
		memset(&sess->stats.user_ib_msgs, 0,
		       sizeof(sess->stats.user_ib_msgs));
		return 0;
	}

	return -EINVAL;
}

int ibtrs_clt_stats_user_ib_msgs_to_str(struct ibtrs_clt_sess *sess, char *buf,
					size_t len)
{
	return scnprintf(buf, len, "%u %llu %u %llu\n",
			 sess->stats.user_ib_msgs.recv_msg_cnt,
			 sess->stats.user_ib_msgs.recv_size,
			 sess->stats.user_ib_msgs.sent_msg_cnt,
			 sess->stats.user_ib_msgs.sent_size);
}

static u32 ibtrs_clt_stats_get_avg_wc_cnt(struct ibtrs_clt_sess *sess)
{
	int i;
	u32 cnt = 0;
	u64 sum = 0;

	for (i = 0; i < num_online_cpus(); i++) {
		sum += sess->stats.wc_comp[i].total_cnt;
		cnt += sess->stats.wc_comp[i].cnt;
	}

	return cnt ? sum / cnt : 0;
}

int ibtrs_clt_stats_wc_completion_to_str(struct ibtrs_clt_sess *sess, char *buf,
					 size_t len)
{
	return scnprintf(buf, len, "%u\n",
			 ibtrs_clt_stats_get_avg_wc_cnt(sess));
}

int ibtrs_clt_reset_wc_comp_stats(struct ibtrs_clt_sess *sess, bool enable)
{
	if (enable) {
		memset(sess->stats.wc_comp, 0,
		       num_online_cpus() * sizeof(*sess->stats.wc_comp));
		return 0;
	}

	return -EINVAL;
}

static int ibtrs_clt_init_wc_comp_stats(struct ibtrs_clt_sess *sess)
{
	sess->stats.wc_comp = kcalloc(num_online_cpus(),
				      sizeof(*sess->stats.wc_comp),
				      GFP_KERNEL);
	if (unlikely(!sess->stats.wc_comp))
		return -ENOMEM;

	return 0;
}

int ibtrs_clt_reset_cpu_migr_stats(struct ibtrs_clt_sess *sess, bool enable)
{
	if (enable) {
		memset(sess->stats.cpu_migr.from, 0,
		       num_online_cpus() *
		       sizeof(*sess->stats.cpu_migr.from));

		memset(sess->stats.cpu_migr.to, 0,
		       num_online_cpus() * sizeof(*sess->stats.cpu_migr.to));
		return 0;
	}

	return -EINVAL;
}

static int ibtrs_clt_init_cpu_migr_stats(struct ibtrs_clt_sess *sess)
{
	sess->stats.cpu_migr.from = kcalloc(num_online_cpus(),
					    sizeof(*sess->stats.cpu_migr.from),
					    GFP_KERNEL);
	if (unlikely(!sess->stats.cpu_migr.from))
		return -ENOMEM;

	sess->stats.cpu_migr.to = kcalloc(num_online_cpus(),
					  sizeof(*sess->stats.cpu_migr.to),
					  GFP_KERNEL);
	if (unlikely(!sess->stats.cpu_migr.to)) {
		kfree(sess->stats.cpu_migr.from);
		sess->stats.cpu_migr.from = NULL;

		return -ENOMEM;
	}

	return 0;
}

static int ibtrs_clt_init_sg_list_distr_stats(struct ibtrs_clt_sess *sess)
{
	u64 **list_d, *list_t;
	int i;

	list_d = kmalloc_array(num_online_cpus(), sizeof(*list_d), GFP_KERNEL);
	if (unlikely(!list_d))
		return -ENOMEM;

	for (i = 0; i < num_online_cpus(); i++) {
		list_d[i] = kzalloc_node(sizeof(*list_d[0]) * (SG_DISTR_LEN + 1),
					 GFP_KERNEL, cpu_to_node(i));
		if (unlikely(!list_d[i]))
			goto err;
	}
	list_t = kcalloc(num_online_cpus(), sizeof(*list_t), GFP_KERNEL);
	if (unlikely(!list_t))
		goto err;

	sess->stats.sg_list_distr = list_d;
	sess->stats.sg_list_total = list_t;

	return 0;

err:
	while (i--)
		kfree(list_d[i]);

	kfree(list_d);

	return -ENOMEM;
}

int ibtrs_clt_reset_sg_list_distr_stats(struct ibtrs_clt_sess *sess,
					bool enable)
{
	int i;

	if (enable) {
		memset(sess->stats.sg_list_total, 0,
		       num_online_cpus() *
		       sizeof(*sess->stats.sg_list_total));

		for (i = 0; i < num_online_cpus(); i++)
			memset(sess->stats.sg_list_distr[i], 0,
			       sizeof(*sess->stats.sg_list_distr[0]) *
			       (SG_DISTR_LEN + 1));
		return 0;
	}

	return -EINVAL;
}

ssize_t ibtrs_clt_stats_rdma_lat_distr_to_str(struct ibtrs_clt_sess *sess,
					      char *page, size_t len)
{
	ssize_t cnt = 0;
	int i, cpu;
	struct ibtrs_clt_stats *s = &sess->stats;
	struct ibtrs_clt_stats_rdma_lat_entry res[MAX_LOG_LATENCY -
						  MIN_LOG_LATENCY + 2];
	struct ibtrs_clt_stats_rdma_lat_entry max;

	max.write	= 0;
	max.read	= 0;
	for (cpu = 0; cpu < num_online_cpus(); cpu++) {
		if (max.write < s->rdma_lat_max[cpu].write)
			max.write = s->rdma_lat_max[cpu].write;
		if (max.read < s->rdma_lat_max[cpu].read)
			max.read = s->rdma_lat_max[cpu].read;
	}

	for (i = 0; i < ARRAY_SIZE(res); i++) {
		res[i].write	= 0;
		res[i].read	= 0;
		for (cpu = 0; cpu < num_online_cpus(); cpu++) {
			res[i].write += s->rdma_lat_distr[cpu][i].write;
			res[i].read += s->rdma_lat_distr[cpu][i].read;
		}
	}

	for (i = 0; i < ARRAY_SIZE(res) - 1; i++)
		cnt += scnprintf(page + cnt, len - cnt,
				 "< %6d ms: %llu %llu\n",
				 1 << (i + MIN_LOG_LATENCY), res[i].read,
				 res[i].write);
	cnt += scnprintf(page + cnt, len - cnt, ">= %5d ms: %llu %llu\n",
			 1 << (i - 1 + MIN_LOG_LATENCY), res[i].read,
			 res[i].write);
	cnt += scnprintf(page + cnt, len - cnt, " maximum ms: %llu %llu\n",
			 max.read, max.write);

	return cnt;
}

int ibtrs_clt_reset_rdma_lat_distr_stats(struct ibtrs_clt_sess *sess,
					 bool enable)
{
	int i;
	struct ibtrs_clt_stats *s = &sess->stats;

	if (enable) {
		memset(s->rdma_lat_max, 0,
		       num_online_cpus() * sizeof(*s->rdma_lat_max));

		for (i = 0; i < num_online_cpus(); i++)
			memset(s->rdma_lat_distr[i], 0,
			       sizeof(*s->rdma_lat_distr[0]) *
			       (MAX_LOG_LATENCY - MIN_LOG_LATENCY + 2));
	}
	sess->enable_rdma_lat = enable;

	return 0;
}

static int ibtrs_clt_init_rdma_lat_distr_stats(struct ibtrs_clt_sess *sess)
{
	struct ibtrs_clt_stats *s = &sess->stats;
	int i;

	s->rdma_lat_max = kzalloc(num_online_cpus() *
				  sizeof(*s->rdma_lat_max), GFP_KERNEL);
	if (unlikely(!s->rdma_lat_max))
		return -ENOMEM;

	s->rdma_lat_distr = kmalloc_array(num_online_cpus(),
					  sizeof(*s->rdma_lat_distr),
					  GFP_KERNEL);
	if (unlikely(!s->rdma_lat_distr))
		goto err1;

	for (i = 0; i < num_online_cpus(); i++) {
		s->rdma_lat_distr[i] =
			kzalloc_node(sizeof(*s->rdma_lat_distr[0]) *
				     (MAX_LOG_LATENCY - MIN_LOG_LATENCY + 2),
				     GFP_KERNEL, cpu_to_node(i));
		if (unlikely(!s->rdma_lat_distr[i]))
			goto err2;
	}

	return 0;

err2:
	while (i--)
		kfree(s->rdma_lat_distr[i]);

	kfree(s->rdma_lat_distr);
	s->rdma_lat_distr = NULL;
err1:
	kfree(s->rdma_lat_max);
	s->rdma_lat_max = NULL;

	return -ENOMEM;
}

int ibtrs_clt_reset_rdma_stats(struct ibtrs_clt_sess *sess, bool enable)
{
	if (enable) {
		struct ibtrs_clt_stats *s = &sess->stats;

		memset(s->rdma_stats, 0,
		       num_online_cpus() * sizeof(*s->rdma_stats));
		return 0;
	}

	return -EINVAL;
}

static int ibtrs_clt_init_rdma_stats(struct ibtrs_clt_sess *sess)
{
	struct ibtrs_clt_stats *s = &sess->stats;

	s->rdma_stats = kcalloc(num_online_cpus(), sizeof(*s->rdma_stats),
				GFP_KERNEL);
	if (unlikely(!s->rdma_stats))
		return -ENOMEM;

	return 0;
}

ssize_t ibtrs_clt_reset_all_help(struct ibtrs_clt_sess *sess,
				 char *page, size_t len)
{
	return scnprintf(page, len, "echo 1 to reset all statistics\n");
}

int ibtrs_clt_reset_all_stats(struct ibtrs_clt_sess *sess, bool enable)
{
	if (enable) {
		ibtrs_clt_reset_rdma_stats(sess, enable);
		ibtrs_clt_reset_rdma_lat_distr_stats(sess, enable);
		ibtrs_clt_reset_sg_list_distr_stats(sess, enable);
		ibtrs_clt_reset_cpu_migr_stats(sess, enable);
		ibtrs_clt_reset_user_ib_msgs_stats(sess, enable);
		ibtrs_clt_reset_reconnects_stat(sess, enable);
		ibtrs_clt_reset_wc_comp_stats(sess, enable);

		return 0;
	}

	return -EINVAL;
}

static int ibtrs_clt_init_stats(struct ibtrs_clt_sess *sess)
{
	int err;

	err = ibtrs_clt_init_sg_list_distr_stats(sess);
	if (unlikely(err)) {
		ibtrs_err(sess,
			  "Failed to init S/G list distribution stats, err: %d\n",
			  err);
		return err;
	}
	err = ibtrs_clt_init_cpu_migr_stats(sess);
	if (unlikely(err)) {
		ibtrs_err(sess, "Failed to init CPU migration stats, err: %d\n",
			  err);
		goto err_sg_list;
	}
	err = ibtrs_clt_init_rdma_lat_distr_stats(sess);
	if (unlikely(err)) {
		ibtrs_err(sess,
			  "Failed to init RDMA lat distribution stats, err: %d\n",
			  err);
		goto err_migr;
	}
	err = ibtrs_clt_init_wc_comp_stats(sess);
	if (unlikely(err)) {
		ibtrs_err(sess, "Failed to init WC completion stats, err: %d\n",
			  err);
		goto err_rdma_lat;
	}
	err = ibtrs_clt_init_rdma_stats(sess);
	if (unlikely(err)) {
		ibtrs_err(sess, "Failed to init RDMA stats, err: %d\n",
			  err);
		goto err_wc_comp;
	}

	return 0;

err_wc_comp:
	ibtrs_clt_free_wc_comp_stats(sess);
err_rdma_lat:
	ibtrs_clt_free_rdma_lat_stats(sess);
err_migr:
	ibtrs_clt_free_cpu_migr_stats(sess);
err_sg_list:
	ibtrs_clt_free_sg_list_distr_stats(sess);

	return err;
}

static int alloc_sess_io_bufs(struct ibtrs_clt_sess *sess)
{
	int ret;

	ret = alloc_sess_reqs(sess);
	if (unlikely(ret)) {
		ibtrs_err(sess, "alloc_sess_reqs(), err: %d\n", ret);
		return ret;
	}
	ret = alloc_sess_fast_pool(sess);
	if (unlikely(ret)) {
		ibtrs_err(sess, "alloc_sess_fast_pool(), err: %d\n", ret);
		goto free_reqs;
	}
	ret = alloc_sess_tags(sess);
	if (unlikely(ret)) {
		ibtrs_err(sess, "alloc_sess_tags(), err: %d\n", ret);
		goto free_fast_pool;
	}

	return 0;

free_fast_pool:
	free_sess_fast_pool(sess);
free_reqs:
	free_sess_reqs(sess);

	return ret;
}

static void free_sess_io_bufs(struct ibtrs_clt_sess *sess)
{
	free_sess_reqs(sess);
	free_sess_fast_pool(sess);
	kfree(sess->tags_map);
	sess->tags_map = NULL;
	kfree(sess->tags);
	sess->tags = NULL;
}

static bool __ibtrs_clt_change_state(struct ibtrs_clt_sess *sess,
				     enum ibtrs_clt_state new_state)
{
	enum ibtrs_clt_state old_state;
	bool changed = false;

	old_state = sess->state;
	switch (new_state) {
	case IBTRS_CLT_CONNECTING:
		switch (old_state) {
		case IBTRS_CLT_RECONNECTING:
			changed = true;
			/* FALLTHRU */
		default:
			break;
		}
		break;
	case IBTRS_CLT_RECONNECTING:
		switch (old_state) {
		case IBTRS_CLT_CONNECTED:
		case IBTRS_CLT_CONNECTING_ERR:
			changed = true;
			/* FALLTHRU */
		default:
			break;
		}
		break;
	case IBTRS_CLT_CONNECTED:
		switch (old_state) {
		case IBTRS_CLT_CONNECTING:
			changed = true;
			/* FALLTHRU */
		default:
			break;
		}
		break;
	case IBTRS_CLT_CONNECTING_ERR:
		switch (old_state) {
		case IBTRS_CLT_CONNECTING:
			changed = true;
			/* FALLTHRU */
		default:
			break;
		}
		break;
	case IBTRS_CLT_CLOSING:
		switch (old_state) {
		case IBTRS_CLT_CONNECTING:
		case IBTRS_CLT_CONNECTING_ERR:
		case IBTRS_CLT_RECONNECTING:
		case IBTRS_CLT_CONNECTED:
			changed = true;
			/* FALLTHRU */
		default:
			break;
		}
		break;
	case IBTRS_CLT_CLOSED:
		switch (old_state) {
		case IBTRS_CLT_CLOSING:
			changed = true;
			/* FALLTHRU */
		default:
			break;
		}
		break;
	default:
		break;
	}
	if (changed) {
		sess->state = new_state;
		wake_up_locked(&sess->state_wq);
	}

	return changed;
}

static bool ibtrs_clt_change_state_from_to(struct ibtrs_clt_sess *sess,
					   enum ibtrs_clt_state old_state,
					   enum ibtrs_clt_state new_state)
{
	bool changed = false;

	spin_lock_irq(&sess->state_wq.lock);
	if (sess->state == old_state)
		changed = __ibtrs_clt_change_state(sess, new_state);
	spin_unlock_irq(&sess->state_wq.lock);

	return changed;
}

static bool ibtrs_clt_change_state_get_old(struct ibtrs_clt_sess *sess,
					   enum ibtrs_clt_state new_state,
					   enum ibtrs_clt_state *old_state)
{
	bool changed;

	spin_lock_irq(&sess->state_wq.lock);
	*old_state = sess->state;
	changed = __ibtrs_clt_change_state(sess, new_state);
	spin_unlock_irq(&sess->state_wq.lock);

	return changed;
}

static bool ibtrs_clt_change_state(struct ibtrs_clt_sess *sess,
				   enum ibtrs_clt_state new_state)
{
	enum ibtrs_clt_state old_state;

	return ibtrs_clt_change_state_get_old(sess, new_state, &old_state);
}

static enum ibtrs_clt_state ibtrs_clt_state(struct ibtrs_clt_sess *sess)
{
	enum ibtrs_clt_state state;

	spin_lock_irq(&sess->state_wq.lock);
	state = sess->state;
	spin_unlock_irq(&sess->state_wq.lock);

	return state;
}

static void ibtrs_clt_reconnect_work(struct work_struct *work);
static void ibtrs_clt_close_work(struct work_struct *work);

static struct ibtrs_clt_sess *alloc_sess(const struct ibtrs_clt_ops *ops,
					 const struct sockaddr *addr,
					 size_t pdu_sz, u8 reconnect_delay_sec,
					 u16 max_segments,
					 s16 max_reconnect_attempts)
{
	struct ibtrs_clt_sess *sess;
	int err = -ENOMEM;

	sess = kzalloc(sizeof(*sess), GFP_KERNEL);
	if (unlikely(!sess))
		goto err;

	sess->con = kcalloc(CONS_PER_SESSION, sizeof(*sess->con), GFP_KERNEL);
	if (unlikely(!sess->con))
		goto err_free_sess;

	mutex_init(&sess->init_mutex);
	memcpy(&sess->s.addr.sockaddr, addr,
	       rdma_addr_size((struct sockaddr *)addr));
	sess->pdu_sz = pdu_sz;
	sess->ops = *ops;
	sess->reconnect_delay_sec = reconnect_delay_sec;
	sess->max_reconnect_attempts = max_reconnect_attempts;
	sess->max_pages_per_mr = max_segments;
	init_waitqueue_head(&sess->state_wq);
	init_waitqueue_head(&sess->tags_wait);
	sess->state = IBTRS_CLT_CONNECTING;
	INIT_WORK(&sess->close_work, ibtrs_clt_close_work);
	INIT_DELAYED_WORK(&sess->reconnect_dwork, ibtrs_clt_reconnect_work);

	err = ibtrs_clt_init_stats(sess);
	if (unlikely(err)) {
		pr_err("Failed to initialize statistics\n");
		goto err_free_con;
	}

	return sess;

err_free_con:
	kfree(sess->con);
err_free_sess:
	kfree(sess);
err:
	return ERR_PTR(err);
}

static void free_sess(struct ibtrs_clt_sess *sess)
{
	ibtrs_clt_free_stats(sess);
	kfree(sess->con);
	kfree(sess->srv_rdma_addr);
	kfree(sess);
}

static int create_con(struct ibtrs_clt_sess *sess, unsigned cid)
{
	struct ibtrs_clt_con *con;

	con = kzalloc(sizeof(*con), GFP_KERNEL);
	if (unlikely(!con))
		return -ENOMEM;

	/* Map first two connections to the first CPU */
	con->cpu  = (cid ? cid - 1 : 0) % num_online_cpus();
	con->cid = cid;
	con->sess = sess;
	atomic_set(&con->io_cnt, 0);

	sess->con[cid] = con;

	return 0;
}

static void destroy_con(struct ibtrs_clt_con *con)
{
	struct ibtrs_clt_sess *sess = con->sess;

	sess->con[con->cid] = NULL;
	kfree(con);
}

static int create_con_cq_qp(struct ibtrs_clt_con *con)
{
	struct ibtrs_clt_sess *sess = con->sess;
	u16 cq_size, wr_queue_size;
	int err, cq_vector;

	/*
	 * This function can fail, but still destroy_con_cq_qp() should
	 * be called, this is because create_con_cq_qp() is called on cm
	 * event path, thus caller/waiter never knows: have we failed before
	 * create_con_cq_qp() or after.  To solve this dilemma without
	 * creating any additional flags just allow destroy_con_cq_qp() be
	 * called many times.
	 */

	if (con->cid == 0) {
		cq_size	      = USR_CON_BUF_SIZE + 1;
		wr_queue_size = USR_CON_BUF_SIZE + 1;

		/* We must be the first here */
		if (WARN_ON(sess->s.ib_dev))
			return -EINVAL;

		/*
		 * The whole session uses device from user connection.
		 * Be careful not to close user connection before ib dev
		 * is gracefully put.
		 */
		sess->s.ib_dev = ibtrs_ib_dev_find_get(con->c.cm_id);
		if (unlikely(!sess->s.ib_dev)) {
			ibtrs_wrn(sess, "ibtrs_ib_dev_find_get(): no memory\n");
			return -ENOMEM;
		}
		sess->s.ib_dev_ref = 1;
		query_fast_reg_mode(sess);
	} else {
		int num_wr;

		/*
		 * Here we assume that session members are correctly set.
		 * This is always true if user connection (cid == 0) is
		 * established first.
		 */
		if (WARN_ON(!sess->s.ib_dev))
			return -EINVAL;
		if (WARN_ON(!sess->queue_depth))
			return -EINVAL;

		/* Shared between connections */
		sess->s.ib_dev_ref++;

		cq_size = sess->queue_depth;
		num_wr = DIV_ROUND_UP(sess->max_pages_per_mr, sess->max_sge);
		wr_queue_size = sess->s.ib_dev->dev->attrs.max_qp_wr - 1;
		wr_queue_size = min_t(int, wr_queue_size,
				      sess->queue_depth * num_wr *
				      (use_fr ? 3 : 2));
	}
	cq_vector = con->cpu % sess->s.ib_dev->dev->num_comp_vectors;
	err = ibtrs_cq_qp_create(&sess->s, &con->c, sess->max_sge,
				 cq_vector, cq_size, wr_queue_size,
				 IB_POLL_SOFTIRQ);
	/*
	 * In case of error we do not bother to clean previous allocations,
	 * since destroy_con_cq_qp() must be called.
	 */

	if (unlikely(err))
		return err;

	if (con->cid) {
		err = alloc_con_fast_pool(con);
		if (unlikely(err))
			ibtrs_cq_qp_destroy(&con->c);
	}

	return err;
}

static void destroy_con_cq_qp(struct ibtrs_clt_con *con)
{
	struct ibtrs_clt_sess *sess = con->sess;

	/*
	 * Be careful here: destroy_con_cq_qp() can be called even
	 * create_con_cq_qp() failed, see comments there.
	 */

	ibtrs_cq_qp_destroy(&con->c);
	if (con->cid != 0)
		free_con_fast_pool(con);
	if (sess->s.ib_dev_ref && !--sess->s.ib_dev_ref) {
		ibtrs_ib_dev_put(sess->s.ib_dev);
		sess->s.ib_dev = NULL;
	}
}

static void stop_cm(struct ibtrs_clt_con *con)
{
	rdma_disconnect(con->c.cm_id);
	if (con->c.qp)
		ib_drain_qp(con->c.qp);
}

static void destroy_cm(struct ibtrs_clt_con *con)
{
	rdma_destroy_id(con->c.cm_id);
}

static int ibtrs_clt_rdma_cm_handler(struct rdma_cm_id *cm_id,
				     struct rdma_cm_event *ev);

static int create_cm(struct ibtrs_clt_con *con)
{
	struct ibtrs_clt_sess *sess = con->sess;
	struct rdma_cm_id *cm_id;
	int err;

	if (sess->s.addr.sockaddr.ss_family == AF_IB)
		cm_id = rdma_create_id(&init_net,
				       ibtrs_clt_rdma_cm_handler,
				       con, RDMA_PS_IB, IB_QPT_RC);
	else
		cm_id = rdma_create_id(&init_net,
				       ibtrs_clt_rdma_cm_handler,
				       con, RDMA_PS_TCP, IB_QPT_RC);
	if (unlikely(IS_ERR(cm_id))) {
		err = PTR_ERR(cm_id);
		ibtrs_wrn(sess, "Failed to create CM ID, err: %d\n", err);

		return err;
	}
	con->c.cm_id = cm_id;
	con->cm_err = 0;
	err = rdma_resolve_addr(cm_id, NULL,
				(struct sockaddr *)&sess->s.addr.sockaddr,
				IBTRS_CONNECT_TIMEOUT_MS);
	if (unlikely(err)) {
		ibtrs_err(sess, "Failed to resolve address, err: %d\n", err);
		rdma_destroy_id(cm_id);

		return err;
	}
	/*
	 * Combine connection status and session events. This is needed
	 * for waiting two possible cases: cm_err has something meaningful
	 * or session state was really changed to error by device removal.
	 */
	err = wait_event_interruptible_timeout(sess->state_wq,
			con->cm_err || sess->state != IBTRS_CLT_CONNECTING,
			msecs_to_jiffies(IBTRS_CONNECT_TIMEOUT_MS));
	if (unlikely(err == 0 || err == -ERESTARTSYS)) {
		if (err == 0)
			err = -ETIMEDOUT;
		/* Timedout or interrupted */
		goto errr;
	}
	if (unlikely(con->cm_err < 0)) {
		err = con->cm_err;
		goto errr;
	}
	if (unlikely(sess->state != IBTRS_CLT_CONNECTING)) {
		/* Device removal */
		err = -ECONNABORTED;
		goto errr;
	}

	return 0;

errr:
	stop_cm(con);
	/* Is safe to call destroy if cq_qp is not inited */
	destroy_con_cq_qp(con);
	destroy_cm(con);

	return err;
}

static int alloc_sess_all_bufs(struct ibtrs_clt_sess *sess)
{
	int err;

	err = alloc_sess_io_bufs(sess);
	if (unlikely(err))
		return err;

	err = ibtrs_iu_alloc_sess_rx_bufs(&sess->s, sess->max_req_size);
	if (unlikely(err))
		goto free_io_bufs;

	err = alloc_sess_tx_bufs(sess);
	if (unlikely(err))
		goto free_rx_bufs;

	return 0;

free_rx_bufs:
	ibtrs_iu_free_sess_rx_bufs(&sess->s);
free_io_bufs:
	free_sess_io_bufs(sess);

	return err;
}

static void free_sess_all_bufs(struct ibtrs_clt_sess *sess)
{
	free_sess_tx_bufs(sess);
	ibtrs_iu_free_sess_rx_bufs(&sess->s);
	free_sess_io_bufs(sess);
}

static void ibtrs_clt_stop_and_destroy_conns(struct ibtrs_clt_sess *sess)
{
	unsigned cid;

	WARN_ON(sess->state == IBTRS_CLT_CONNECTED);

	/*
	 * Possible race with ibtrs_clt_open(), when DEVICE_REMOVAL comes
	 * exactly in between.  Start destroying after it finishes.
	 */
	mutex_lock(&sess->init_mutex);
	mutex_unlock(&sess->init_mutex);

	/*
	 * All IO paths must observe !CONNECTED state before we
	 * free everything.
	 */
	synchronize_rcu();

	/*
	 * The order it utterly crucial: firstly disconnect and complete all
	 * rdma requests with error (thus set in_use=false for requests),
	 * then fail outstanding requests checking in_use for each, and
	 * eventually notify upper layer about session disconnection.
	 */

	for (cid = 0; cid < CONS_PER_SESSION; cid++)
		stop_cm(sess->con[cid]);
	fail_all_outstanding_reqs(sess);
	sess->ops.sess_ev(sess->ops.priv, IBTRS_CLT_SESS_EV_DISCONNECTED, 0);

	free_sess_all_bufs(sess);
	for (cid = 0; cid < CONS_PER_SESSION; cid++) {
		struct ibtrs_clt_con *con = sess->con[cid];

		destroy_con_cq_qp(con);
		destroy_cm(con);
		destroy_con(con);
	}
}

static void ibtrs_clt_close_work(struct work_struct *work)
{
	struct ibtrs_clt_sess *sess;

	sess = container_of(work, struct ibtrs_clt_sess, close_work);

	cancel_delayed_work_sync(&sess->reconnect_dwork);
	ibtrs_clt_stop_and_destroy_conns(sess);
	/*
	 * Sounds stupid, huh?  No, it is not.  Consider this sequence:
	 *
	 *   #CPU0                              #CPU1
	 *   1.  CONNECTED->RECONNECTING
	 *   2.                                 RECONNECTING->CLOSING
	 *   3.  queue_work(&reconnect_dwork)
	 *   4.                                 queue_work(&close_work);
	 *   5.  reconnect_work();              close_work();
	 *
	 * To avoid that case do cancel twice: before and after.
	 */
	cancel_delayed_work_sync(&sess->reconnect_dwork);
}

static void ibtrs_clt_close_conns(struct ibtrs_clt_sess *sess, bool wait)
{
	if (ibtrs_clt_change_state(sess, IBTRS_CLT_CLOSING))
		queue_work(ibtrs_wq, &sess->close_work);
	if (wait)
		flush_work(&sess->close_work);
}

static int init_conns(struct ibtrs_clt_sess *sess)
{
	unsigned cid;
	int err;

	/* Before connecting generate new session UUID */
	uuid_le_gen(&sess->s.uuid);

	/* Establish all RDMA connections  */
	for (cid = 0; cid < CONS_PER_SESSION; cid++) {
		err = create_con(sess, cid);
		if (unlikely(err))
		    goto destroy;

		err = create_cm(sess->con[cid]);
		if (unlikely(err)) {
			destroy_con(sess->con[cid]);
			goto destroy;
		}
	}
	/* Allocate all session related buffers */
	err = alloc_sess_all_bufs(sess);
	if (unlikely(err))
		goto destroy;

	return 0;

destroy:
	while (cid--) {
		struct ibtrs_clt_con *con = sess->con[cid];

		stop_cm(con);
		destroy_con_cq_qp(con);
		destroy_cm(con);
		destroy_con(con);
	}
	/*
	 * If we've never taken async path and got an error, say,
	 * doing rdma_resolve_addr(), switch to CONNECTION_ERR state
	 * manually to keep reconnecting.
	 */
	ibtrs_clt_change_state(sess, IBTRS_CLT_CONNECTING_ERR);

	return err;
}

static int ibtrs_rdma_addr_resolved(struct ibtrs_clt_con *con)
{
	struct ibtrs_clt_sess *sess = con->sess;
	int err;

	err = create_con_cq_qp(con);
	if (unlikely(err)) {
		ibtrs_err(sess, "create_con_cq_qp(), err: %d\n", err);
		return err;
	}
	err = rdma_resolve_route(con->c.cm_id, IBTRS_CONNECT_TIMEOUT_MS);
	if (unlikely(err)) {
		ibtrs_err(sess, "Resolving route failed, err: %d\n", err);
		destroy_con_cq_qp(con);
	}

	return err;
}

static int ibtrs_rdma_route_resolved(struct ibtrs_clt_con *con)
{
	struct ibtrs_msg_conn_req msg;
	struct rdma_conn_param param;
	struct ibtrs_clt_sess *sess;

	int err;

	sess = con->sess;
	memset(&param, 0, sizeof(param));
	param.retry_count = retry_count;
	param.rnr_retry_count = 7;
	param.private_data = &msg;
	param.private_data_len = sizeof(msg);

	msg.magic = cpu_to_le16(IBTRS_MAGIC);
	msg.version = cpu_to_le16(IBTRS_VERSION);
	msg.cid = cpu_to_le16(con->cid);
	msg.cid_num = cpu_to_le16(CONS_PER_SESSION);
	memcpy(msg.uuid, sess->s.uuid.b, sizeof(msg.uuid));

	err = rdma_connect(con->c.cm_id, &param);
	if (err)
		ibtrs_err(sess, "rdma_connect(): %d\n", err);

	return err;
}

static int ibtrs_rdma_conn_established(struct ibtrs_clt_con *con,
				       struct rdma_cm_event *ev)
{
	const struct ibtrs_msg_conn_rsp *msg;
	struct ibtrs_clt_sess *sess;
	u16 version, queue_depth;
	int errno;
	u8 len;

	sess = con->sess;
	msg = ev->param.conn.private_data;
	len = ev->param.conn.private_data_len;
	if (unlikely(len < sizeof(*msg))) {
		ibtrs_err(sess, "Invalid IBTRS connection response");
		return -ECONNRESET;
	}
	if (unlikely(le16_to_cpu(msg->magic) != IBTRS_MAGIC)) {
		ibtrs_err(sess, "Invalid IBTRS magic");
		return -ECONNRESET;
	}
	version = le16_to_cpu(msg->version);
	if (unlikely(version >> 8 != IBTRS_VER_MAJOR)) {
		ibtrs_err(sess, "Unsupported major IBTRS version: %d",
			  version);
		return -ECONNRESET;
	}
	errno = le16_to_cpu(msg->errno);
	if (unlikely(errno)) {
		ibtrs_err(sess, "Invalid IBTRS message: errno %d",
			  errno);
		return -ECONNRESET;
	}
	if (con->cid == 0) {
		queue_depth = le16_to_cpu(msg->queue_depth);

		if (queue_depth > MAX_SESS_QUEUE_DEPTH) {
			ibtrs_err(sess, "Invalid IBTRS message: queue=%d\n",
				  queue_depth);
			return -ECONNRESET;
		}
		if (!sess->srv_rdma_addr || sess->queue_depth < queue_depth) {
			kfree(sess->srv_rdma_addr);
			sess->srv_rdma_addr = kcalloc(
						queue_depth,
						sizeof(*sess->srv_rdma_addr),
						GFP_KERNEL);
			if (unlikely(!sess->srv_rdma_addr)) {
				ibtrs_err(sess, "Failed to allocate queue_depth=%d\n",
					  queue_depth);
				return -ENOMEM;
			}
		}
		sess->user_queue_depth = queue_depth;
		sess->queue_depth = queue_depth;
		sess->srv_rdma_buf_rkey = le32_to_cpu(msg->rkey);
		sess->max_req_size = le32_to_cpu(msg->max_req_size);
		sess->max_io_size = le32_to_cpu(msg->max_io_size);
		sess->chunk_size = sess->max_io_size + sess->max_req_size;
		sess->max_desc  = sess->max_req_size;
		sess->max_desc -= sizeof(u32) + sizeof(u32) + IO_MSG_SIZE;
		sess->max_desc /= sizeof(struct ibtrs_sg_desc);
	}

	return 0;
}

static int ibtrs_rdma_conn_rejected(struct ibtrs_clt_con *con,
				    struct rdma_cm_event *ev)
{
	const struct ibtrs_msg_conn_rsp *msg;
	const char *rej_msg;
	u8 data_len;
	int status;

	status = ev->status;
	rej_msg = rdma_reject_msg(con->c.cm_id, status);
	msg = rdma_consumer_reject_data(con->c.cm_id, ev, &data_len);

	if (msg && data_len >= sizeof(*msg))
		ibtrs_err(con->sess,
			  "Connect rejected: status %d (%s), ibtrs status %d\n",
			  status, rej_msg, le16_to_cpu(msg->errno));
	else
		ibtrs_err(con->sess,
			  "Connect rejected: status %d (%s)\n",
			  status, rej_msg);

	return -ECONNRESET;
}

static void ibtrs_rdma_error_recovery(struct ibtrs_clt_con *con)
{
	struct ibtrs_clt_sess *sess = con->sess;

	if (ibtrs_clt_change_state_from_to(sess,
				IBTRS_CLT_CONNECTED, IBTRS_CLT_RECONNECTING)) {
		/*
		 * Normal scenario, reconnect if we were successfully connected
		 */
		unsigned delay_ms = sess->reconnect_delay_sec * 1000;

		queue_delayed_work(ibtrs_wq, &sess->reconnect_dwork,
				   msecs_to_jiffies(delay_ms));
	} else
		/*
		 * Error can happen just on establishing new connection,
		 * so notify waiter with error state, waiter is responsible
		 * for cleaning the rest and reconnect if needed.
		 */
		ibtrs_clt_change_state_from_to(sess,
				IBTRS_CLT_CONNECTING, IBTRS_CLT_CONNECTING_ERR);
}

static int ibtrs_clt_rdma_cm_handler(struct rdma_cm_id *cm_id,
				     struct rdma_cm_event *ev)
{
	struct ibtrs_clt_con *con = cm_id->context;
	struct ibtrs_clt_sess *sess = con->sess;
	int cm_err = 0;

	switch (ev->event) {
	case RDMA_CM_EVENT_ADDR_RESOLVED:
		cm_err = ibtrs_rdma_addr_resolved(con);
		break;
	case RDMA_CM_EVENT_ROUTE_RESOLVED:
		cm_err = ibtrs_rdma_route_resolved(con);
		break;
	case RDMA_CM_EVENT_ESTABLISHED:
		con->cm_err = ibtrs_rdma_conn_established(con, ev);
		if (likely(!con->cm_err)) {
			/*
			 * Report success and wake up. Here we abuse state_wq,
			 * i.e. wake up without state change, but we set cm_err.
			 */
			con->cm_err = 1;
			wake_up(&sess->state_wq);
			return 0;
		}
		break;
	case RDMA_CM_EVENT_REJECTED:
		cm_err = ibtrs_rdma_conn_rejected(con, ev);
		break;
	case RDMA_CM_EVENT_ADDR_ERROR:
	case RDMA_CM_EVENT_ROUTE_ERROR:
	case RDMA_CM_EVENT_CONNECT_ERROR:
	case RDMA_CM_EVENT_UNREACHABLE:
		ibtrs_wrn(sess, "CM error event %d\n", ev->event);
		cm_err = -ECONNRESET;
		break;
	case RDMA_CM_EVENT_DISCONNECTED:
	case RDMA_CM_EVENT_ADDR_CHANGE:
	case RDMA_CM_EVENT_TIMEWAIT_EXIT:
		cm_err = -ECONNRESET;
		break;
	case RDMA_CM_EVENT_DEVICE_REMOVAL:
		/*
		 * Device removal is a special case.  Queue close and return 0.
		 */
		ibtrs_clt_close_conns(sess, false);
		return 0;
	default:
		ibtrs_err(sess, "Unexpected RDMA CM event (%d)\n", ev->event);
		cm_err = -ECONNRESET;
		break;
	}

	if (cm_err) {
		/*
		 * cm error makes sense only on connection establishing,
		 * in other cases we rely on normal procedure of reconnecting.
		 */
		con->cm_err = cm_err;
		ibtrs_rdma_error_recovery(con);
	}

	return 0;
}

static void ibtrs_clt_info_req_done(struct ib_cq *cq, struct ib_wc *wc)
{
	struct ibtrs_clt_con *con = cq->cq_context;
	struct ibtrs_clt_sess *sess = con->sess;
	struct ibtrs_iu *iu;

	iu = container_of(wc->wr_cqe, struct ibtrs_iu, cqe);
	ibtrs_iu_free(iu, DMA_TO_DEVICE, sess->s.ib_dev->dev);

	if (unlikely(wc->status != IB_WC_SUCCESS)) {
		ibtrs_err(sess, "Sess info request send failed: %s\n",
			  ib_wc_status_msg(wc->status));
		ibtrs_clt_change_state(sess, IBTRS_CLT_CONNECTING_ERR);
		return;
	}

	ibtrs_clt_update_wc_stats(con);
}

static int process_info_rsp(struct ibtrs_clt_sess *sess,
			    const struct ibtrs_msg_info_rsp *msg)
{
	unsigned addr_num;
	int i;

	addr_num = le16_to_cpu(msg->addr_num);
	/*
	 * Check if IB immediate data size is enough to hold the mem_id and
	 * the offset inside the memory chunk.
	 */
	if (unlikely(ilog2(addr_num - 1) + ilog2(sess->chunk_size - 1) >
		     IB_IMM_SIZE_BITS)) {
		ibtrs_err(sess, "RDMA immediate size (%db) not enough to encode "
			  "%d buffers of size %dB\n", IB_IMM_SIZE_BITS, addr_num,
			  sess->chunk_size);
		return -EINVAL;
	}
	if (unlikely(addr_num > sess->queue_depth)) {
		ibtrs_err(sess, "Incorrect addr_num=%d\n", addr_num);
		return -EINVAL;
	}
	for (i = 0; i < msg->addr_num; i++)
		sess->srv_rdma_addr[i] = le64_to_cpu(msg->addr[i]);

	memcpy(sess->s.addr.hostname, msg->hostname, sizeof(msg->hostname));

	return 0;
}

static void ibtrs_clt_info_rsp_done(struct ib_cq *cq, struct ib_wc *wc)
{
	struct ibtrs_clt_con *con = cq->cq_context;
	struct ibtrs_clt_sess *sess = con->sess;
	struct ibtrs_msg_info_rsp *msg;
	enum ibtrs_clt_state state;
	struct ibtrs_iu *iu;
	size_t rx_sz;
	int err;

	state = IBTRS_CLT_CONNECTING_ERR;

	WARN_ON(con->cid);
	iu = container_of(wc->wr_cqe, struct ibtrs_iu, cqe);
	if (unlikely(wc->status != IB_WC_SUCCESS)) {
		ibtrs_err(sess, "Sess info response recv failed: %s\n",
			  ib_wc_status_msg(wc->status));
		goto out;
	}
	WARN_ON(wc->opcode != IB_WC_RECV);

	if (unlikely(wc->byte_len < sizeof(*msg))) {
		ibtrs_err(sess, "Sess info response is malformed: size %d\n",
			  wc->byte_len);
		goto out;
	}
	msg = iu->buf;
	if (unlikely(le16_to_cpu(msg->type) != IBTRS_MSG_INFO_RSP)) {
		ibtrs_err(sess, "Sess info response is malformed: type %d\n",
			  le32_to_cpu(msg->type));
		goto out;
	}
	rx_sz  = sizeof(*msg);
	rx_sz += sizeof(msg->addr[0]) * le16_to_cpu(msg->addr_num);
	if (unlikely(wc->byte_len < rx_sz)) {
		ibtrs_err(sess, "Sess info response is malformed: size %d\n",
			  wc->byte_len);
		goto out;
	}
	err = process_info_rsp(sess, msg);
	if (unlikely(err))
		goto out;

	err = post_recv_sess(sess);
	if (unlikely(err))
		goto out;

	state = IBTRS_CLT_CONNECTED;

out:
	ibtrs_clt_update_wc_stats(con);
	ibtrs_iu_free(iu, DMA_FROM_DEVICE, sess->s.ib_dev->dev);
	ibtrs_clt_change_state(sess, state);
}

static int ibtrs_send_sess_info(struct ibtrs_clt_sess *sess,
				bool timeout_wait)
{
	struct ibtrs_clt_con *usr_con = sess->con[0];
	struct ibtrs_msg_info_req *msg;
	struct ibtrs_iu *tx_iu, *rx_iu;
	size_t rx_sz;
	int err;

	rx_sz  = sizeof(struct ibtrs_msg_info_rsp);
	rx_sz += sizeof(u64) * MAX_SESS_QUEUE_DEPTH;

	tx_iu = ibtrs_iu_alloc(0, sizeof(struct ibtrs_msg_info_req),
			       GFP_KERNEL, sess->s.ib_dev->dev, DMA_TO_DEVICE);
	rx_iu = ibtrs_iu_alloc(0, rx_sz, GFP_KERNEL,
			       sess->s.ib_dev->dev, DMA_FROM_DEVICE);
	if (unlikely(!tx_iu || !rx_iu)) {
		ibtrs_err(sess, "ibtrs_iu_alloc(): no memory\n");
		err = -ENOMEM;
		goto out;
	}
	/* Prepare for getting info response */
	err = ibtrs_post_recv(&usr_con->c, rx_iu, ibtrs_clt_info_rsp_done);
	if (unlikely(err)) {
		ibtrs_err(sess, "ibtrs_post_recv(), err: %d\n", err);
		goto out;
	}
	rx_iu = NULL;

	msg = tx_iu->buf;
	msg->type = cpu_to_le16(IBTRS_MSG_INFO_REQ);
	memcpy(msg->hostname, hostname, sizeof(msg->hostname));

	/* Send info request */
	err = ibtrs_post_send(&usr_con->c, tx_iu, sizeof(*msg),
			      ibtrs_clt_info_req_done);
	if (unlikely(err)) {
		ibtrs_err(sess, "ibtrs_post_send(), err: %d\n", err);
		goto out;
	}
	tx_iu = NULL;

	/* Wait for state change */
	if (timeout_wait)
		wait_event_interruptible_timeout(sess->state_wq,
			   sess->state != IBTRS_CLT_CONNECTING,
			   msecs_to_jiffies(IBTRS_CONNECT_TIMEOUT_MS));
	else
		wait_event(sess->state_wq,
			   sess->state != IBTRS_CLT_CONNECTING);
	if (unlikely(sess->state != IBTRS_CLT_CONNECTED)) {
		if (sess->state == IBTRS_CLT_CONNECTING_ERR)
			err = -ECONNRESET;
		else
			err = -ETIMEDOUT;
		goto out;
	}

out:
	if (tx_iu)
		ibtrs_iu_free(tx_iu, DMA_TO_DEVICE, sess->s.ib_dev->dev);
	if (rx_iu)
		ibtrs_iu_free(rx_iu, DMA_FROM_DEVICE, sess->s.ib_dev->dev);

	return err;
}

static void ibtrs_clt_reconnect_work(struct work_struct *work)
{
	struct ibtrs_clt_sess *sess;
	unsigned delay_ms;
	int err;

	sess = container_of(to_delayed_work(work), struct ibtrs_clt_sess,
			    reconnect_dwork);

	if (ibtrs_clt_state(sess) == IBTRS_CLT_CLOSING)
		/* User requested closing */
		return;

	/* Stop everything */
	ibtrs_clt_stop_and_destroy_conns(sess);
	ibtrs_clt_change_state(sess, IBTRS_CLT_CONNECTING);

	err = init_conns(sess);
	if (unlikely(err)) {
		ibtrs_err(sess, "Establishing session to server failed,"
			  " failed to init connections, err: %d\n", err);
		goto reconnect_again;
	}
	err = ibtrs_send_sess_info(sess, false);
	if (unlikely(err)) {
		ibtrs_err(sess, "Sending session info failed, err: %d\n", err);
		goto reconnect_again;
	}
	sess->ops.sess_ev(sess->ops.priv, IBTRS_CLT_SESS_EV_RECONNECTED, 0);

	return;

reconnect_again:
	if (ibtrs_clt_change_state(sess, IBTRS_CLT_RECONNECTING)) {
		delay_ms = sess->reconnect_delay_sec * 1000;
		queue_delayed_work(ibtrs_wq, &sess->reconnect_dwork,
				   msecs_to_jiffies(delay_ms));
	}
}

struct ibtrs_clt_sess *ibtrs_clt_open(const struct ibtrs_clt_ops *ops,
				      const struct sockaddr *addr,
				      size_t pdu_sz, u8 reconnect_delay_sec,
				      u16 max_segments,
				      s16 max_reconnect_attempts)
{
	struct ibtrs_clt_sess *sess;
	int err;

	if (unlikely(!clt_ops_are_valid(ops))) {
		pr_err("Callbacks are invalid\n");
		err = -EINVAL;
		goto out;
	}
	sess = alloc_sess(ops, addr, pdu_sz, reconnect_delay_sec,
			  max_segments, max_reconnect_attempts);
	if (unlikely(IS_ERR(sess))) {
		pr_err("Establishing session to server failed, err: %ld\n",
		       PTR_ERR(sess));
		err = PTR_ERR(sess);
		goto out;
	}
	mutex_lock(&sess->init_mutex);
	err = init_conns(sess);
	if (unlikely(err)) {
		ibtrs_err(sess, "Establishing session to server failed,"
			  " failed to init connections, err: %d\n", err);
		err = -EHOSTUNREACH;
		goto close_sess;
	}
	err = ibtrs_send_sess_info(sess, true);
	if (unlikely(err)) {
		ibtrs_err(sess, "Sending session info failed, err: %d\n", err);
		goto close_sess;
	}
	err = ibtrs_clt_create_sess_files(sess);
	if (unlikely(err)) {
		ibtrs_err(sess, "Establishing session to server failed,"
			  " failed to create session sysfs files, err: %d\n",
			  err);
		goto close_sess;
	}
	mutex_unlock(&sess->init_mutex);

	return sess;

close_sess:
	mutex_unlock(&sess->init_mutex);
	ibtrs_clt_close_conns(sess, true);
	free_sess(sess);

out:
	return ERR_PTR(err);
}
EXPORT_SYMBOL(ibtrs_clt_open);

void ibtrs_clt_close(struct ibtrs_clt_sess *sess)
{
	ibtrs_clt_destroy_sess_files(sess);
	ibtrs_clt_close_conns(sess, true);
	free_sess(sess);
}
EXPORT_SYMBOL(ibtrs_clt_close);

int ibtrs_clt_reconnect(struct ibtrs_clt_sess *sess)
{
	if (ibtrs_clt_change_state_from_to(sess,
				IBTRS_CLT_CONNECTED, IBTRS_CLT_RECONNECTING)) {
		unsigned delay_ms = sess->reconnect_delay_sec * 1000;

		queue_delayed_work(ibtrs_wq, &sess->reconnect_dwork,
				   msecs_to_jiffies(delay_ms));
		return 0;
	}

	return -ENOTCONN;
}

void ibtrs_clt_set_max_reconnect_attempts(struct ibtrs_clt_sess *sess, s16 value)
{
	sess->max_reconnect_attempts = value;
}

s16 ibtrs_clt_get_max_reconnect_attempts(const struct ibtrs_clt_sess *sess)
{
	return sess->max_reconnect_attempts;
}

static inline void ibtrs_clt_record_sg_distr(u64 *stat, u64 *total,
					     unsigned int cnt)
{
	int i;

	i = cnt > MAX_LIN_SG ? ilog2(cnt) + MAX_LIN_SG - MIN_LOG_SG + 1 : cnt;
	i = i > SG_DISTR_LEN ? SG_DISTR_LEN : i;

	stat[i]++;
	(*total)++;
}

static int ibtrs_clt_rdma_write_desc(struct ibtrs_clt_con *con,
				     struct rdma_req *req, u64 buf,
				     size_t u_msg_len, u32 imm,
				     struct ibtrs_msg_rdma_write *msg)
{
	struct ibtrs_clt_sess *sess = con->sess;
	struct ibtrs_ib_dev *ibdev = sess->s.ib_dev;
	struct ibtrs_sg_desc *desc;
	int ret;

	desc = kmalloc_array(sess->max_pages_per_mr, sizeof(*desc), GFP_ATOMIC);
	if (!desc) {
		ib_dma_unmap_sg(ibdev->dev, req->sglist,
				req->sg_cnt, req->dir);
		return -ENOMEM;
	}
	ret = ibtrs_fast_reg_map_data(con, desc, req);
	if (unlikely(ret < 0)) {
		ibtrs_err_rl(sess,
			     "RDMA-Write failed, fast reg. data mapping"
			     " failed, err: %d\n", ret);
		ib_dma_unmap_sg(ibdev->dev, req->sglist,
				req->sg_cnt, req->dir);
		kfree(desc);
		return ret;
	}
	ret = ibtrs_post_send_rdma_desc(con, req, desc, ret, buf,
					u_msg_len + sizeof(*msg), imm);
	if (unlikely(ret)) {
		ibtrs_err(sess, "RDMA-Write failed, posting work"
			  " request failed, err: %d\n", ret);
		ibtrs_unmap_fast_reg_data(con, req);
		ib_dma_unmap_sg(ibdev->dev, req->sglist,
				req->sg_cnt, req->dir);
	}
	kfree(desc);
	return ret;
}

static int ibtrs_clt_rdma_write_sg(struct ibtrs_clt_con *con,
				   struct rdma_req *req,
				   const struct kvec *vec,
				   size_t u_msg_len,
				   size_t data_len)
{
	struct ibtrs_clt_sess *sess = con->sess;
	struct ibtrs_msg_rdma_write *msg;
	int count = 0;
	u32 imm;
	int ret;
	int buf_id;
	u64 buf;

	const size_t tsize = sizeof(*msg) + data_len + u_msg_len;

	if (unlikely(tsize > sess->chunk_size)) {
		ibtrs_wrn(sess, "RDMA-Write failed, size too big %zu > %d\n",
			  tsize, sess->chunk_size);
		return -EMSGSIZE;
	}
	if (req->sg_cnt) {
		count = ib_dma_map_sg(sess->s.ib_dev->dev, req->sglist,
				      req->sg_cnt, req->dir);
		if (unlikely(!count)) {
			ibtrs_wrn(sess, "RDMA-Write failed, map failed\n");
			return -EINVAL;
		}
	}
	copy_from_kvec(req->iu->buf, vec, u_msg_len);

	/* put ibtrs msg after sg and user message */
	msg = req->iu->buf + u_msg_len;
	msg->type = cpu_to_le16(IBTRS_MSG_RDMA_WRITE);

	/* ibtrs message on server side will be after user data and message */
	imm = req->tag->mem_id_mask + data_len + u_msg_len;
	buf_id = req->tag->mem_id;
	req->sg_size = tsize;

	buf = sess->srv_rdma_addr[buf_id];
	if (count > fmr_sg_cnt)
		return ibtrs_clt_rdma_write_desc(con, req, buf, u_msg_len, imm,
						 msg);

	ret = ibtrs_post_send_rdma_more(con, req, buf, u_msg_len + sizeof(*msg),
					imm);
	if (unlikely(ret)) {
		ibtrs_err(sess, "RDMA-Write failed, posting work"
			  " request failed, err: %d\n", ret);
		if (count)
			ib_dma_unmap_sg(sess->s.ib_dev->dev, req->sglist,
					req->sg_cnt, req->dir);
	}
	return ret;
}

static void ibtrs_clt_update_rdma_stats(struct ibtrs_clt_stats *s,
					size_t size, bool read)
{
	int cpu = raw_smp_processor_id();

	if (read) {
		s->rdma_stats[cpu].cnt_read++;
		s->rdma_stats[cpu].size_total_read += size;
	} else {
		s->rdma_stats[cpu].cnt_write++;
		s->rdma_stats[cpu].size_total_write += size;
	}

	s->rdma_stats[cpu].inflight++;
}

/**
 * ibtrs_rdma_con_id() - returns RDMA connection id
 *
 * Note:
 *     RDMA connection starts from 1.
 *     0 connection is for user messages.
 */
static inline int ibtrs_rdma_con_id(struct ibtrs_tag *tag)
{
	return (tag->cpu_id % (CONS_PER_SESSION - 1)) + 1;
}

int ibtrs_clt_rdma_write(struct ibtrs_clt_sess *sess, struct ibtrs_tag *tag,
			 void *priv, const struct kvec *vec, size_t nr,
			 size_t data_len, struct scatterlist *sg,
			 unsigned int sg_len)
{
	struct ibtrs_clt_con *con;
	struct rdma_req *req;
	struct ibtrs_iu *iu;
	size_t u_msg_len;
	int con_id;
	int err;

	u_msg_len = kvec_length(vec, nr);
	if (unlikely(u_msg_len > IO_MSG_SIZE)) {
		ibtrs_wrn_rl(sess, "RDMA-Write failed, user message size"
			     " is %zu B big, max size is %d B\n", u_msg_len,
			     IO_MSG_SIZE);
		return -EMSGSIZE;
	}

	con_id = ibtrs_rdma_con_id(tag);
	if (WARN_ON(con_id >= CONS_PER_SESSION))
		return -EINVAL;
	con = sess->con[con_id];
	ibtrs_clt_state_lock();
	if (unlikely(sess->state != IBTRS_CLT_CONNECTED)) {
		ibtrs_clt_state_unlock();
		ibtrs_err_rl(sess, "RDMA-Write failed, not connected"
			     " (connection %d state %s)\n",
			     con_id,
			     ibtrs_clt_state_str(sess->state));
		return -ECOMM;
	}

	iu = sess->io_tx_ius[tag->mem_id];
	req = &sess->reqs[tag->mem_id];
	req->con	= con;
	req->tag	= tag;
	if (sess->enable_rdma_lat)
		req->start_time = ibtrs_clt_get_raw_ms();
	req->in_use	= true;

	req->iu		= iu;
	req->sglist	= sg;
	req->sg_cnt	= sg_len;
	req->priv	= priv;
	req->dir        = DMA_TO_DEVICE;

	err = ibtrs_clt_rdma_write_sg(con, req, vec, u_msg_len, data_len);
	if (unlikely(err))
	    req->in_use = false;
	/* paired with fail_all_outstanding_reqs() */
	smp_wmb();
	ibtrs_clt_state_unlock();
	if (unlikely(err)) {
		ibtrs_err_rl(sess, "RDMA-Write failed, failed to transfer scatter"
			     " gather list, err: %d\n", err);
		return err;
	}

	ibtrs_clt_record_sg_distr(sess->stats.sg_list_distr[tag->cpu_id],
				  &sess->stats.sg_list_total[tag->cpu_id],
				  sg_len);
	ibtrs_clt_update_rdma_stats(&sess->stats, u_msg_len + data_len, false);

	return err;
}
EXPORT_SYMBOL(ibtrs_clt_rdma_write);

static int ibtrs_clt_request_rdma_write_sg(struct ibtrs_clt_con *con,
					   struct rdma_req *req,
					   const struct kvec *vec,
					   size_t u_msg_len,
					   size_t data_len)
{
	struct ibtrs_clt_sess *sess = con->sess;
	struct ibtrs_msg_req_rdma_write *msg;
	struct ibtrs_ib_dev *ibdev;
	struct scatterlist *sg;
	int count, i, ret;
	u32 imm, buf_id;

	const size_t tsize = sizeof(*msg) + data_len + u_msg_len;

	ibdev = sess->s.ib_dev;

	if (unlikely(tsize > sess->chunk_size)) {
		ibtrs_wrn(sess, "Request-RDMA-Write failed, message size is"
			  " %zu, bigger than CHUNK_SIZE %d\n", tsize,
			  sess->chunk_size);
		return -EMSGSIZE;
	}
	count = ib_dma_map_sg(ibdev->dev, req->sglist, req->sg_cnt, req->dir);
	if (unlikely(!count)) {
		ibtrs_wrn(sess, "Request-RDMA-Write failed, dma map failed\n");
		return -EINVAL;
	}

	req->data_len = data_len;
	copy_from_kvec(req->iu->buf, vec, u_msg_len);

	/* put our message into req->buf after user message*/
	msg = req->iu->buf + u_msg_len;
	msg->type = cpu_to_le16(IBTRS_MSG_REQ_RDMA_WRITE);
	msg->sg_cnt = cpu_to_le32(count);

	if (count > fmr_sg_cnt) {
		ret = ibtrs_fast_reg_map_data(con, msg->desc, req);
		if (ret < 0) {
			ibtrs_err_rl(sess,
				     "Request-RDMA-Write failed, failed to map "
				     " fast reg. data, err: %d\n", ret);
			ib_dma_unmap_sg(ibdev->dev, req->sglist, req->sg_cnt,
					req->dir);
			return ret;
		}
		msg->sg_cnt = cpu_to_le32(ret);
	} else {
		for_each_sg(req->sglist, sg, req->sg_cnt, i) {
			msg->desc[i].addr =
				cpu_to_le64(ib_sg_dma_address(ibdev->dev, sg));
			msg->desc[i].key =
				cpu_to_le32(ibdev->mr->rkey);
			msg->desc[i].len =
				cpu_to_le32(ib_sg_dma_len(ibdev->dev, sg));
		}
		req->nmdesc = 0;
	}
	/* ibtrs message will be after the space reserved for disk data and
	 * user message
	 */
	imm = req->tag->mem_id_mask + data_len + u_msg_len;
	buf_id = req->tag->mem_id;

	req->sg_size  = sizeof(*msg);
	req->sg_size += le32_to_cpu(msg->sg_cnt) * sizeof(struct ibtrs_sg_desc);
	req->sg_size += u_msg_len;
	ret = ibtrs_post_send_rdma(con, req, sess->srv_rdma_addr[buf_id],
				   data_len, imm);
	if (unlikely(ret)) {
		ibtrs_err(sess, "Request-RDMA-Write failed,"
			  " posting work request failed, err: %d\n", ret);

		if (unlikely(count > fmr_sg_cnt)) {
			ibtrs_unmap_fast_reg_data(con, req);
			ib_dma_unmap_sg(ibdev->dev, req->sglist,
					req->sg_cnt, req->dir);
		}
	}
	return ret;
}

int ibtrs_clt_request_rdma_write(struct ibtrs_clt_sess *sess,
				 struct ibtrs_tag *tag, void *priv,
				 const struct kvec *vec, size_t nr,
				 size_t data_len,
				 struct scatterlist *recv_sg,
				 unsigned int recv_sg_len)
{
	struct ibtrs_iu *iu;
	struct rdma_req *req;
	int err;
	struct ibtrs_clt_con *con;
	int con_id;
	size_t u_msg_len;

	u_msg_len = kvec_length(vec, nr);
	if (unlikely(u_msg_len > IO_MSG_SIZE ||
		     sizeof(struct ibtrs_msg_req_rdma_write) +
		     recv_sg_len * sizeof(struct ibtrs_sg_desc) >
			     sess->max_req_size)) {
		ibtrs_wrn_rl(sess, "Request-RDMA-Write failed, user message size"
			     " is %zu B big, max size is %d B\n", u_msg_len,
			     IO_MSG_SIZE);
		return -EMSGSIZE;
	}

	con_id = ibtrs_rdma_con_id(tag);
	if (WARN_ON(con_id >= CONS_PER_SESSION))
		return -EINVAL;
	con = sess->con[con_id];
	ibtrs_clt_state_lock();
	if (unlikely(sess->state != IBTRS_CLT_CONNECTED)) {
		ibtrs_clt_state_unlock();
		ibtrs_err_rl(sess, "RDMA-Write failed, not connected"
			     " (connection %d state %s)\n",
			     con_id,
			     ibtrs_clt_state_str(sess->state));
		return -ECOMM;
	}

	iu = sess->io_tx_ius[tag->mem_id];
	req = &sess->reqs[tag->mem_id];
	req->con	= con;
	req->tag	= tag;
	if (sess->enable_rdma_lat)
		req->start_time = ibtrs_clt_get_raw_ms();
	req->in_use	= true;

	req->iu		= iu;
	req->sglist	= recv_sg;
	req->sg_cnt	= recv_sg_len;
	req->priv	= priv;
	req->dir        = DMA_FROM_DEVICE;

	err = ibtrs_clt_request_rdma_write_sg(con, req, vec,
					      u_msg_len, data_len);
	if (unlikely(err))
		req->in_use = false;
	/* paired with fail_all_outstanding_reqs() */
	smp_wmb();
	ibtrs_clt_state_unlock();
	if (unlikely(err)) {
		ibtrs_err_rl(sess, "Request-RDMA-Write failed, failed to transfer"
			     " scatter gather list, err: %d\n", err);
		return err;
	}

	ibtrs_clt_record_sg_distr(sess->stats.sg_list_distr[tag->cpu_id],
				  &sess->stats.sg_list_total[tag->cpu_id],
				  recv_sg_len);
	ibtrs_clt_update_rdma_stats(&sess->stats, u_msg_len + data_len, true);

	return err;
}
EXPORT_SYMBOL(ibtrs_clt_request_rdma_write);

int ibtrs_clt_send(struct ibtrs_clt_sess *sess, const struct kvec *vec,
		   size_t nr)
{
	struct ibtrs_clt_con *usr_con = sess->con[0];
	struct ibtrs_msg_user *msg;
	struct ibtrs_iu *iu;
	size_t len;
	int err;

	len = kvec_length(vec, nr);
	if (unlikely(len > sess->max_req_size - sizeof(*msg))) {
		ibtrs_err(sess, "Message size is too long: %zu\n", len);
		return -EMSGSIZE;
	}
	iu = ibtrs_usr_msg_get(&sess->s);
	if (unlikely(!iu)) {
		/* We are in disconnecting state, just return */
		ibtrs_err_rl(sess, "Sending user message failed, disconnecting");
		return -ECOMM;
	}
	ibtrs_clt_state_lock();
	if (unlikely(sess->state != IBTRS_CLT_CONNECTED)) {
		ibtrs_clt_state_unlock();
		ibtrs_err_rl(sess, "Sending user message failed, not connected."
			     " Session state is %s\n",
			     ibtrs_clt_state_str(sess->state));
		err = -ECOMM;
		goto err_post_send;
	}

	msg = iu->buf;
	msg->type = cpu_to_le16(IBTRS_MSG_USER);
	msg->psize = cpu_to_le16(len);
	copy_from_kvec(msg->payl, vec, len);

	len += sizeof(*msg);

	err = ibtrs_post_send(&usr_con->c, iu, len, ibtrs_clt_usr_send_done);
	ibtrs_clt_state_unlock();
	if (unlikely(err)) {
		ibtrs_err_rl(sess, "Sending user message failed, posting work"
			     " request failed, err: %d\n", err);
		goto err_post_send;
	}

	sess->stats.user_ib_msgs.sent_msg_cnt++;
	sess->stats.user_ib_msgs.sent_size += len;

	return 0;

err_post_send:
	ibtrs_usr_msg_return_iu(&sess->s, iu);
	ibtrs_usr_msg_put(&sess->s);

	return err;
}
EXPORT_SYMBOL(ibtrs_clt_send);

int ibtrs_clt_query(struct ibtrs_clt_sess *sess, struct ibtrs_attrs *attr)
{
	if (unlikely(sess->state != IBTRS_CLT_CONNECTED))
		return -ECOMM;

	attr->queue_depth      = sess->queue_depth;
	attr->mr_page_mask     = sess->mr_page_mask;
	attr->mr_page_size     = sess->mr_page_size;
	attr->mr_max_size      = sess->mr_max_size;
	attr->max_pages_per_mr = sess->max_pages_per_mr;
	attr->max_sge          = sess->max_sge;
	attr->max_io_size      = sess->max_io_size;
	strlcpy(attr->hostname, sess->s.addr.hostname,
		sizeof(attr->hostname));

	return 0;
}
EXPORT_SYMBOL(ibtrs_clt_query);

static int check_module_params(void)
{
	if (fmr_sg_cnt > MAX_SEGMENTS || fmr_sg_cnt < 0) {
		pr_err("invalid fmr_sg_cnt values\n");
		return -EINVAL;
	}
	if (nr_cons_per_session == 0)
		nr_cons_per_session = nr_cpu_ids;
	if (nr_cons_per_session >= U8_MAX)
		/* Protocol header has only 8bits for connection number */
		nr_cons_per_session = U8_MAX - 1;

	return 0;
}

ssize_t ibtrs_clt_stats_rdma_to_str(struct ibtrs_clt_sess *sess,
				    char *page, size_t len)
{
	struct ibtrs_clt_stats_rdma_stats s;
	struct ibtrs_clt_stats_rdma_stats *r = sess->stats.rdma_stats;
	int i;

	memset(&s, 0, sizeof(s));

	for (i = 0; i < num_online_cpus(); i++) {
		s.cnt_read		+= r[i].cnt_read;
		s.size_total_read	+= r[i].size_total_read;
		s.cnt_write		+= r[i].cnt_write;
		s.size_total_write	+= r[i].size_total_write;
		s.inflight		+= r[i].inflight;
	}

	return scnprintf(page, len, "%llu %llu %llu %llu %u\n",
			 s.cnt_read, s.size_total_read, s.cnt_write,
			 s.size_total_write, s.inflight);
}

int ibtrs_clt_stats_sg_list_distr_to_str(struct ibtrs_clt_sess *sess, char *buf,
					 size_t len)
{
	int cnt = 0;
	unsigned p, p_i, p_f;
	u64 *total = sess->stats.sg_list_total;
	u64 **distr = sess->stats.sg_list_distr;
	int i, j;

	cnt += scnprintf(buf + cnt, len - cnt, "n\\cpu:");
	for (j = 0; j < num_online_cpus(); j++)
		cnt += scnprintf(buf + cnt, len - cnt, "%5d", j);

	for (i = 0; i < SG_DISTR_LEN + 1; i++) {
		if (i <= MAX_LIN_SG)
			cnt += scnprintf(buf + cnt, len - cnt, "\n= %3d:", i);
		else if (i < SG_DISTR_LEN)
			cnt += scnprintf(buf + cnt, len - cnt,
					 "\n< %3d:",
					 1 << (i + MIN_LOG_SG - MAX_LIN_SG));
		else
			cnt += scnprintf(buf + cnt, len - cnt,
					 "\n>=%3d:",
					 1 << (i + MIN_LOG_SG - MAX_LIN_SG - 1));

		for (j = 0; j < num_online_cpus(); j++) {
			p = total[j] ? distr[j][i] * 1000 / total[j] : 0;
			p_i = p / 10;
			p_f = p % 10;

			if (distr[j][i])
				cnt += scnprintf(buf + cnt, len - cnt,
						 " %2u.%01u", p_i, p_f);
			else
				cnt += scnprintf(buf + cnt, len - cnt, "    0");
		}
	}

	cnt += scnprintf(buf + cnt, len - cnt, "\ntotal:");
	for (j = 0; j < num_online_cpus(); j++)
		cnt += scnprintf(buf + cnt, len - cnt, " %llu", total[j]);
	cnt += scnprintf(buf + cnt, len - cnt, "\n");

	return cnt;
}

static int __init ibtrs_client_init(void)
{
	int err;

	scnprintf(hostname, sizeof(hostname), "%s", utsname()->nodename);
	pr_info("Loading module %s, version: %s "
		"(use_fr: %d, retry_count: %d, "
		"fmr_sg_cnt: %d, hostname: %s)\n",
		KBUILD_MODNAME, IBTRS_VER_STRING,
		use_fr,	retry_count, fmr_sg_cnt,
		hostname);
	err = check_module_params();
	if (err) {
		pr_err("Failed to load module, invalid module parameters,"
		       " err: %d\n", err);
		return err;
	}
	ibtrs_wq = create_workqueue("ibtrs_client_wq");
	if (!ibtrs_wq) {
		pr_err("Failed to load module, alloc ibtrs_client_wq failed\n");
		return -ENOMEM;
	}
	err = ibtrs_clt_create_sysfs_files();
	if (err) {
		pr_err("Failed to load module, can't create sysfs files,"
		       " err: %d\n", err);
		goto out_ibtrs_wq;
	}

	return 0;

out_ibtrs_wq:
	destroy_workqueue(ibtrs_wq);

	return err;
}

static void __exit ibtrs_client_exit(void)
{
	pr_info("Unloading module\n");

	ibtrs_clt_destroy_sysfs_files();
	destroy_workqueue(ibtrs_wq);

	pr_info("Module unloaded\n");
}

module_init(ibtrs_client_init);
module_exit(ibtrs_client_exit);
