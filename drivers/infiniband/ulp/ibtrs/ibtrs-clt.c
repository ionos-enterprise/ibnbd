/*
 * InfiniBand Transport Layer
 *
 * Copyright (c) 2014 - 2017 ProfitBricks GmbH. All rights reserved.
 * Authors: Fabian Holler <mail@fholler.de>
 *          Jack Wang <jinpu.wang@profitbricks.com>
 *          Kleber Souza <kleber.souza@profitbricks.com>
 *          Danil Kipnis <danil.kipnis@profitbricks.com>
 *          Roman Penyaev <roman.penyaev@profitbricks.com>
 *          Milind Dumbare <Milind.dumbare@gmail.com>
 *
 * Copyright (c) 2017 - 2018 ProfitBricks GmbH. All rights reserved.
 * Authors: Danil Kipnis <danil.kipnis@profitbricks.com>
 *          Roman Penyaev <roman.penyaev@profitbricks.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#undef pr_fmt
#define pr_fmt(fmt) KBUILD_MODNAME " L" __stringify(__LINE__) ": " fmt

#include <linux/module.h>
#include <rdma/ib_fmr_pool.h>

#include "ibtrs-clt.h"
#include "ibtrs-log.h"

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
		 " (default: nr_cpu_ids)");

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

static struct workqueue_struct *ibtrs_wq;

static void ibtrs_rdma_error_recovery(struct ibtrs_clt_con *con);
static void ibtrs_clt_rdma_done(struct ib_cq *cq, struct ib_wc *wc);

static inline void ibtrs_clt_state_lock(void)
{
	rcu_read_lock();
}

static inline void ibtrs_clt_state_unlock(void)
{
	rcu_read_unlock();
}

#define cmpxchg_min(var, new) ({					\
	typeof(var) old;						\
									\
	do {								\
		old = var;						\
		new = (!old ? new : min_t(typeof(var), old, new));	\
	} while (cmpxchg(&var, old, new) != old);			\
})

static void ibtrs_clt_set_min_queue_depth(struct ibtrs_clt *clt, size_t new)
{
	/* Can be updated from different sessions (paths), so cmpxchg */

	cmpxchg_min(clt->queue_depth, new);
}

static void ibtrs_clt_set_min_io_size(struct ibtrs_clt *clt, size_t new)
{
	/* Can be updated from different sessions (paths), so cmpxchg */

	cmpxchg_min(clt->max_io_size, new);
}

bool ibtrs_clt_sess_is_connected(const struct ibtrs_clt_sess *sess)
{
	return sess->state == IBTRS_CLT_CONNECTED;
}

static inline bool ibtrs_clt_is_connected(const struct ibtrs_clt *clt)
{
	struct ibtrs_clt_sess *sess;
	bool connected = false;

	ibtrs_clt_state_lock();
	list_for_each_entry_rcu(sess, &clt->paths_list, s.entry)
		connected |= ibtrs_clt_sess_is_connected(sess);
	ibtrs_clt_state_unlock();

	return connected;
}

/**
 * struct ibtrs_fr_desc - fast registration work request arguments
 * @entry: Entry in ibtrs_fr_pool.free_list.
 * @mr:    Memory region.
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
	spinlock_t		lock; /* protects free_list */
	struct list_head	free_list;
	struct ibtrs_fr_desc	desc[0];
};

/**
 * struct ibtrs_map_state - per-request DMA memory mapping state
 * @desc:	    Pointer to the element of the buffer descriptor array
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

static inline struct ibtrs_tag *
__ibtrs_get_tag(struct ibtrs_clt *clt, enum ibtrs_clt_con_type con_type)
{
	size_t max_depth = clt->queue_depth;
	struct ibtrs_tag *tag;
	int cpu, bit;

	cpu = get_cpu();
	do {
		bit = find_first_zero_bit(clt->tags_map, max_depth);
		if (unlikely(bit >= max_depth)) {
			put_cpu();
			return NULL;
		}

	} while (unlikely(test_and_set_bit_lock(bit, clt->tags_map)));
	put_cpu();

	tag = GET_TAG(clt, bit);
	WARN_ON(tag->mem_id != bit);
	tag->cpu_id = cpu;
	tag->con_type = con_type;

	return tag;
}

static inline void __ibtrs_put_tag(struct ibtrs_clt *clt,
				   struct ibtrs_tag *tag)
{
	clear_bit_unlock(tag->mem_id, clt->tags_map);
}

struct ibtrs_tag *ibtrs_clt_get_tag(struct ibtrs_clt *clt,
				    enum ibtrs_clt_con_type con_type,
				    int can_wait)
{
	struct ibtrs_tag *tag;
	DEFINE_WAIT(wait);

	tag = __ibtrs_get_tag(clt, con_type);
	if (likely(tag) || !can_wait)
		return tag;

	do {
		prepare_to_wait(&clt->tags_wait, &wait, TASK_UNINTERRUPTIBLE);
		tag = __ibtrs_get_tag(clt, con_type);
		if (likely(tag))
			break;

		io_schedule();
	} while (1);

	finish_wait(&clt->tags_wait, &wait);

	return tag;
}
EXPORT_SYMBOL(ibtrs_clt_get_tag);

void ibtrs_clt_put_tag(struct ibtrs_clt *clt, struct ibtrs_tag *tag)
{
	if (WARN_ON(!test_bit(tag->mem_id, clt->tags_map)))
		return;

	__ibtrs_put_tag(clt, tag);

	/*
	 * Putting a tag is a barrier, so we will observe
	 * new entry in the wait list, no worries.
	 */
	if (waitqueue_active(&clt->tags_wait))
		wake_up(&clt->tags_wait);
}
EXPORT_SYMBOL(ibtrs_clt_put_tag);

/**
 * ibtrs_tag_to_clt_con() - returns RDMA connection id by the tag
 *
 * Note:
 *     IO connection starts from 1.
 *     0 connection is for user messages.
 */
static struct ibtrs_clt_con *ibtrs_tag_to_clt_con(struct ibtrs_clt_sess *sess,
						  struct ibtrs_tag *tag)
{
	int id = 0;

	if (likely(tag->con_type == IBTRS_IO_CON))
		id = (tag->cpu_id % (sess->s.con_num - 1)) + 1;

	return to_clt_con(sess->s.con[id]);
}

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
	struct ibtrs_clt_sess *sess = to_clt_sess(con->c.sess);
	struct ib_pool_fmr *fmr;
	dma_addr_t dma_addr;
	u64 io_addr = 0;

	fmr = ib_fmr_pool_map_phys(sess->fmr_pool, state->pages,
				   state->npages, io_addr);
	if (IS_ERR(fmr)) {
		ibtrs_wrn_rl(sess, "Failed to map FMR from FMR pool, "
			     "err: %ld\n", PTR_ERR(fmr));
		return PTR_ERR(fmr);
	}

	*state->next_fmr++ = fmr;
	state->nmdesc++;
	dma_addr = state->base_dma_addr & ~sess->mr_page_mask;
	pr_debug("ndesc = %d, nmdesc = %d, npages = %d\n",
		 state->ndesc, state->nmdesc, state->npages);
	if (state->dir == DMA_TO_DEVICE)
		ibtrs_map_desc(state, dma_addr, state->dma_len, fmr->fmr->lkey,
			       sess->max_desc);
	else
		ibtrs_map_desc(state, dma_addr, state->dma_len, fmr->fmr->rkey,
			       sess->max_desc);

	return 0;
}

static void ibtrs_clt_fast_reg_done(struct ib_cq *cq, struct ib_wc *wc)
{
	struct ibtrs_clt_con *con = cq->cq_context;
	struct ibtrs_clt_sess *sess = to_clt_sess(con->c.sess);

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
	struct ibtrs_clt_sess *sess = to_clt_sess(con->c.sess);
	struct ibtrs_fr_desc *desc;
	struct ib_send_wr *bad_wr;
	struct ib_reg_wr wr;
	struct ib_pd *pd;
	u32 rkey;
	int n;

	pd = sess->s.ib_dev->pd;
	if (sg_cnt == 1 && (pd->flags & IB_PD_UNSAFE_GLOBAL_RKEY)) {
		unsigned int sg_offset = sg_offset_p ? *sg_offset_p : 0;

		ibtrs_map_desc(state, sg_dma_address(state->sg) + sg_offset,
			       sg_dma_len(state->sg) - sg_offset,
			       pd->unsafe_global_rkey, sess->max_desc);
		if (sg_offset_p)
			*sg_offset_p = 0;
		return 1;
	}

	desc = ibtrs_fr_pool_get(con->fr_pool);
	if (!desc) {
		ibtrs_wrn_rl(sess, "Failed to get descriptor from FR pool\n");
		return -ENOMEM;
	}

	rkey = ib_inc_rkey(desc->mr->rkey);
	ib_update_fast_reg_key(desc->mr, rkey);

	memset(&wr, 0, sizeof(wr));
	n = ib_map_mr_sg(desc->mr, state->sg, sg_cnt, sg_offset_p,
			 sess->mr_page_size);
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
		       desc->mr->rkey, sess->max_desc);

	return ib_post_send(con->c.qp, &wr.wr, &bad_wr);
}

static int ibtrs_finish_fmr_mapping(struct ibtrs_map_state *state,
				    struct ibtrs_clt_con *con)
{
	struct ibtrs_clt_sess *sess = to_clt_sess(con->c.sess);
	struct ib_pd *pd = sess->s.ib_dev->pd;
	int ret = 0;

	if (state->npages == 0)
		return 0;

	if (state->npages == 1 && (pd->flags & IB_PD_UNSAFE_GLOBAL_RKEY))
		ibtrs_map_desc(state, state->base_dma_addr, state->dma_len,
			       pd->unsafe_global_rkey,
			       sess->max_desc);
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
	struct ibtrs_clt_sess *sess = to_clt_sess(con->c.sess);
	unsigned int dma_len, len;
	struct ib_device *ibdev;
	dma_addr_t dma_addr;
	int ret;

	ibdev = sess->s.ib_dev->dev;
	dma_addr = ib_sg_dma_address(ibdev, sg);
	dma_len = ib_sg_dma_len(ibdev, sg);
	if (!dma_len)
		return 0;

	while (dma_len) {
		unsigned int offset = dma_addr & ~sess->mr_page_mask;

		if (state->npages == sess->max_pages_per_mr ||
		    offset != 0) {
			ret = ibtrs_finish_fmr_mapping(state, con);
			if (ret)
				return ret;
		}

		len = min_t(unsigned int, dma_len,
			    sess->mr_page_size - offset);

		if (!state->npages)
			state->base_dma_addr = dma_addr;
		state->pages[state->npages++] =
			dma_addr & sess->mr_page_mask;
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
	if (len != sess->mr_page_size)
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
			struct ibtrs_clt_io_req *req)
{
	struct ibtrs_clt_sess *sess = to_clt_sess(con->c.sess);
	int ret = 0;

	state->pages = req->map_page;
	if (sess->fast_reg_mode == IBTRS_FAST_MEM_FR) {
		state->next_fr = req->fr_list;
		ret = ibtrs_map_fr(state, con, req->sglist, req->sg_cnt);
		if (ret)
			goto out;
	} else if (sess->fast_reg_mode == IBTRS_FAST_MEM_FMR) {
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
	struct ibtrs_clt_sess *sess = to_clt_sess(con->c.sess);

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
				      struct ibtrs_clt_io_req *req)
{
	struct ibtrs_clt_sess *sess = to_clt_sess(con->c.sess);
	int i, ret;

	if (sess->fast_reg_mode == IBTRS_FAST_MEM_FR) {
		struct ibtrs_fr_desc **pfr;

		for (i = req->nmdesc, pfr = req->fr_list; i > 0; i--, pfr++) {
			ret = ibtrs_inv_rkey(con, (*pfr)->mr->rkey);
			if (ret < 0) {
				ibtrs_err(sess,
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
				   struct ibtrs_clt_io_req *req)
{
	struct ibtrs_clt_sess *sess = to_clt_sess(con->c.sess);
	struct ibtrs_map_state state;
	int ret;

	memset(&state, 0, sizeof(state));
	state.desc	= desc;
	state.dir	= req->dir;
	ret = ibtrs_map_sg(&state, con, req);

	if (unlikely(ret))
		goto unmap;

	if (unlikely(state.ndesc <= 0)) {
		ibtrs_err(sess,
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

static int ibtrs_post_send_rdma(struct ibtrs_clt_con *con,
				struct ibtrs_clt_io_req *req,
				u64 addr, u32 off, u32 imm)
{
	struct ibtrs_clt_sess *sess = to_clt_sess(con->c.sess);
	enum ib_send_flags flags;
	struct ib_sge list[1];

	if (unlikely(!req->sg_size)) {
		ibtrs_wrn(sess, "Doing RDMA Write failed, no data supplied\n");
		return -EINVAL;
	}

	/* user data and user message in the first list element */
	list[0].addr   = req->iu->dma_addr;
	list[0].length = req->sg_size;
	list[0].lkey   = sess->s.ib_dev->lkey;

	/*
	 * From time to time we have to post signalled sends,
	 * or send queue will fill up and only QP reset can help.
	 */
	flags = atomic_inc_return(&con->io_cnt) % sess->queue_depth ?
			0 : IB_SEND_SIGNALED;
	return ibtrs_iu_post_rdma_write_imm(&con->c, req->iu, list, 1,
					    sess->srv_rdma_buf_rkey,
					    addr + off, imm, flags);
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
				     struct ibtrs_clt_io_req *req,
				     struct ib_rdma_wr *wr, int offset,
				     struct ibtrs_sg_desc *desc, int m,
				     int n, u64 addr, u32 size, u32 imm)
{
	struct ibtrs_clt_sess *sess = to_clt_sess(con->c.sess);
	enum ib_send_flags flags;
	int i;

	for (i = m; i < n; i++, desc++)
		ibtrs_set_sge_with_desc(&list[i], desc);

	list[i].addr   = req->iu->dma_addr;
	list[i].length = size;
	list[i].lkey   = sess->s.ib_dev->lkey;

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
					  struct ibtrs_clt_io_req *req,
					  struct ibtrs_sg_desc *desc, int n,
					  u64 addr, u32 size, u32 imm)
{
	struct ibtrs_clt_sess *sess = to_clt_sess(con->c.sess);
	size_t max_sge, num_sge, num_wr;
	struct ib_send_wr *bad_wr;
	struct ib_rdma_wr *wrs, *wr;
	int j = 0, k, offset = 0, len = 0;
	int m = 0;
	int ret;

	max_sge = sess->max_sge;
	num_sge = 1 + n;
	num_wr = DIV_ROUND_UP(num_sge, max_sge);

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

	ibtrs_set_rdma_desc_last(con, list, req, wr, offset,
				 desc, m, n, addr, size, imm);

	ret = ib_post_send(con->c.qp, &wrs[0].wr, &bad_wr);
	if (unlikely(ret))
		ibtrs_err(sess, "Posting write request to QP failed,"
			  " err: %d\n", ret);
	kfree(wrs);
	return ret;
}

static int ibtrs_post_send_rdma_desc(struct ibtrs_clt_con *con,
				     struct ibtrs_clt_io_req *req,
				     struct ibtrs_sg_desc *desc, int n,
				     u64 addr, u32 size, u32 imm)
{
	struct ibtrs_clt_sess *sess = to_clt_sess(con->c.sess);
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
		list[i].lkey   = sess->s.ib_dev->lkey;

		/*
		 * From time to time we have to post signalled sends,
		 * or send queue will fill up and only QP reset can help.
		 */
		flags = atomic_inc_return(&con->io_cnt) % sess->queue_depth ?
				0 : IB_SEND_SIGNALED;
		ret = ibtrs_iu_post_rdma_write_imm(&con->c, req->iu, list,
						   num_sge,
						   sess->srv_rdma_buf_rkey,
						   addr, imm, flags);
	} else {
		ret = ibtrs_post_send_rdma_desc_more(con, list, req, desc, n,
						     addr, size, imm);
	}

	kfree(list);
	return ret;
}

static int ibtrs_post_send_rdma_more(struct ibtrs_clt_con *con,
				     struct ibtrs_clt_io_req *req,
				     u64 addr, u32 size, u32 imm)
{
	struct ibtrs_clt_sess *sess = to_clt_sess(con->c.sess);
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
		list[i].lkey   = sess->s.ib_dev->lkey;
	}
	list[i].addr   = req->iu->dma_addr;
	list[i].length = size;
	list[i].lkey   = sess->s.ib_dev->lkey;

	/*
	 * From time to time we have to post signalled sends,
	 * or send queue will fill up and only QP reset can help.
	 */
	flags = atomic_inc_return(&con->io_cnt) % sess->queue_depth ?
			0 : IB_SEND_SIGNALED;
	ret = ibtrs_iu_post_rdma_write_imm(&con->c, req->iu, list, num_sge,
					   sess->srv_rdma_buf_rkey,
					   addr, imm, flags);
	kfree(list);

	return ret;
}

static inline unsigned long ibtrs_clt_get_raw_ms(void)
{
	struct timespec ts;

	getrawmonotonic(&ts);

	return timespec_to_ns(&ts) / NSEC_PER_MSEC;
}

static void complete_rdma_req(struct ibtrs_clt_io_req *req,
			      int errno, bool notify)
{
	struct ibtrs_clt_con *con = req->con;
	struct ibtrs_clt_sess *sess;
	enum dma_data_direction dir;
	struct ibtrs_clt *clt;
	void *priv;

	if (WARN_ON(!req->in_use))
		return;
	if (WARN_ON(!req->con))
		return;
	sess = to_clt_sess(con->c.sess);
	clt = sess->clt;

	if (req->sg_cnt > fmr_sg_cnt)
		ibtrs_unmap_fast_reg_data(req->con, req);
	if (req->sg_cnt)
		ib_dma_unmap_sg(sess->s.ib_dev->dev, req->sglist,
				req->sg_cnt, req->dir);
	if (sess->stats.enable_rdma_lat)
		ibtrs_clt_update_rdma_lat(&sess->stats,
					  req->dir == DMA_FROM_DEVICE,
					  ibtrs_clt_get_raw_ms() -
					  req->start_time);
	ibtrs_clt_decrease_inflight(&sess->stats);

	req->in_use = false;
	req->con = NULL;
	priv = req->priv;
	dir = req->dir;

	if (notify)
		req->conf(priv, errno);
}

static void process_io_rsp(struct ibtrs_clt_sess *sess, u32 msg_id, s16 errno)
{
	if (WARN_ON(msg_id >= sess->queue_depth))
		return;

	complete_rdma_req(&sess->reqs[msg_id], errno, true);
}

static struct ib_cqe io_comp_cqe = {
	.done = ibtrs_clt_rdma_done
};

static void ibtrs_clt_rdma_done(struct ib_cq *cq, struct ib_wc *wc)
{
	struct ibtrs_clt_con *con = cq->cq_context;
	struct ibtrs_clt_sess *sess = to_clt_sess(con->c.sess);
	u32 imm_type, imm_payload;
	int err;

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
		 * and hb
		 */
		break;
	case IB_WC_RECV_RDMA_WITH_IMM:
		/*
		 * post_recv() RDMA write completions of IO reqs (read/write)
		 * and hb
		 */
		if (WARN_ON(wc->wr_cqe != &io_comp_cqe))
			return;
		err = ibtrs_post_recv_empty(&con->c, &io_comp_cqe);
		if (unlikely(err)) {
			ibtrs_err(sess, "ibtrs_post_recv_empty(): %d\n", err);
			ibtrs_rdma_error_recovery(con);
			break;
		}
		ibtrs_from_imm(be32_to_cpu(wc->ex.imm_data),
			       &imm_type, &imm_payload);
		if (likely(imm_type == IBTRS_IO_RSP_IMM)) {
			u32 msg_id;

			ibtrs_from_io_rsp_imm(imm_payload, &msg_id, &err);
			process_io_rsp(sess, msg_id, err);
		} else if (imm_type == IBTRS_HB_MSG_IMM) {
			WARN_ON(con->c.cid);
			ibtrs_send_hb_ack(&sess->s);
		} else if (imm_type == IBTRS_HB_ACK_IMM) {
			WARN_ON(con->c.cid);
			sess->s.hb_missed_cnt = 0;
		} else {
			ibtrs_wrn(sess, "Unknown IMM type %u\n", imm_type);
		}
		break;
	default:
		ibtrs_wrn(sess, "Unexpected WC type: %s\n",
			  ib_wc_opcode_str(wc->opcode));
		return;
	}
}

static int post_recv_io(struct ibtrs_clt_con *con)
{
	struct ibtrs_clt_sess *sess = to_clt_sess(con->c.sess);
	int err, i;

	for (i = 0; i < sess->queue_depth; i++) {
		err = ibtrs_post_recv_empty(&con->c, &io_comp_cqe);
		if (unlikely(err))
			return err;
	}

	return 0;
}

static int post_recv_sess(struct ibtrs_clt_sess *sess)
{
	int err, cid;

	for (cid = 0; cid < sess->s.con_num; cid++) {
		err = post_recv_io(to_clt_con(sess->s.con[cid]));
		if (unlikely(err)) {
			ibtrs_err(sess, "post_recv_io(), err: %d\n", err);
			return err;
		}
	}

	return 0;
}

struct path_it {
	int i;
	struct list_head skip_list;
	struct ibtrs_clt *clt;
	struct ibtrs_clt_sess *(*next_path)(struct path_it *);
};

#define do_each_path(path, clt, it) {					\
	path_it_init(it, clt);						\
	ibtrs_clt_state_lock();						\
	for ((it)->i = 0; ((path) = ((it)->next_path)(it)) &&		\
			  (it)->i < (it)->clt->paths_num;		\
	     (it)->i++)

#define while_each_path(it)						\
	path_it_deinit(it);						\
	ibtrs_clt_state_unlock();					\
	}

/**
 * get_next_path_rr() - Returns path in round-robin fashion.
 *
 * Related to @MP_POLICY_RR
 *
 * Locks:
 *    ibtrs_clt_state_lock() must be hold.
 */
static struct ibtrs_clt_sess *get_next_path_rr(struct path_it *it)
{
	struct ibtrs_clt_sess __percpu * __rcu *ppcpu_path, *path;
	struct ibtrs_clt *clt = it->clt;

	ppcpu_path = this_cpu_ptr(clt->pcpu_path);
	path = rcu_dereference(*ppcpu_path);
	if (unlikely(!path))
		path = list_first_or_null_rcu(&clt->paths_list,
					      typeof(*path), s.entry);
	else
		path = list_next_or_null_rcu_rr(path, &clt->paths_list,
						s.entry);
	rcu_assign_pointer(*ppcpu_path, path);

	return path;
}

/**
 * get_next_path_min_inflight() - Returns path with minimal inflight count.
 *
 * Related to @MP_POLICY_MIN_INFLIGHT
 *
 * Locks:
 *    ibtrs_clt_state_lock() must be hold.
 */
static struct ibtrs_clt_sess *get_next_path_min_inflight(struct path_it *it)
{
	struct ibtrs_clt_sess *min_path = NULL;
	struct ibtrs_clt *clt = it->clt;
	struct ibtrs_clt_sess *sess;
	int min_inflight = INT_MAX;
	int inflight;

	list_for_each_entry_rcu(sess, &clt->paths_list, s.entry) {
		if (unlikely(!list_empty(raw_cpu_ptr(sess->mp_skip_entry))))
			continue;

		inflight = atomic_read(&sess->stats.inflight);

		if (inflight < min_inflight) {
			min_inflight = inflight;
			min_path = sess;
		}
	}

	/*
	 * add the path to the skip list, so that next time we can get
	 * a different one
	 */
	if (min_path)
		list_add(raw_cpu_ptr(min_path->mp_skip_entry), &it->skip_list);

	return min_path;
}

static inline void path_it_init(struct path_it *it, struct ibtrs_clt *clt)
{
	INIT_LIST_HEAD(&it->skip_list);
	it->clt = clt;
	it->i = 0;

	if (clt->mp_policy == MP_POLICY_RR)
		it->next_path = get_next_path_rr;
	else
		it->next_path = get_next_path_min_inflight;
}

static inline void path_it_deinit(struct path_it *it)
{
	struct list_head *skip, *tmp;
	/*
	 * The skip_list is used only for the MIN_INFLIGHT policy.
	 * We need to remove paths from it, so that next IO can insert
	 * paths (->mp_skip_entry) into a skip_list again.
	 */
	list_for_each_safe(skip, tmp, &it->skip_list)
		list_del_init(skip);
}

static inline void ibtrs_clt_init_req(struct ibtrs_clt_io_req *req,
				      struct ibtrs_clt_sess *sess,
				      ibtrs_conf_fn *conf,
				      struct ibtrs_tag *tag, void *priv,
				      const struct kvec *vec, size_t usr_len,
				      struct scatterlist *sg, size_t sg_cnt,
				      size_t data_len, int dir)
{
	req->tag = tag;
	req->in_use = true;
	req->usr_len = usr_len;
	req->data_len = data_len;
	req->sglist = sg;
	req->sg_cnt = sg_cnt;
	req->priv = priv;
	req->dir = dir;
	req->con = ibtrs_tag_to_clt_con(sess, tag);
	req->conf = conf;
	copy_from_kvec(req->iu->buf, vec, usr_len);
	if (sess->stats.enable_rdma_lat)
		req->start_time = ibtrs_clt_get_raw_ms();
}

static inline struct ibtrs_clt_io_req *
ibtrs_clt_get_req(struct ibtrs_clt_sess *sess, ibtrs_conf_fn *conf,
		  struct ibtrs_tag *tag, void *priv,
		  const struct kvec *vec, size_t usr_len,
		  struct scatterlist *sg, size_t sg_cnt,
		  size_t data_len, int dir)
{
	struct ibtrs_clt_io_req *req;

	req = &sess->reqs[tag->mem_id];
	ibtrs_clt_init_req(req, sess, conf, tag, priv, vec, usr_len,
			   sg, sg_cnt, data_len, dir);
	return req;
}

static inline struct ibtrs_clt_io_req *
ibtrs_clt_get_copy_req(struct ibtrs_clt_sess *alive_sess,
		       struct ibtrs_clt_io_req *fail_req)
{
	struct ibtrs_clt_io_req *req;
	struct kvec vec = {
		.iov_base = fail_req->iu->buf,
		.iov_len  = fail_req->usr_len
	};

	req = &alive_sess->reqs[fail_req->tag->mem_id];
	ibtrs_clt_init_req(req, alive_sess, fail_req->conf, fail_req->tag,
			   fail_req->priv, &vec, fail_req->usr_len,
			   fail_req->sglist, fail_req->sg_cnt,
			   fail_req->data_len, fail_req->dir);
	return req;
}

static int ibtrs_clt_write_req(struct ibtrs_clt_io_req *req);
static int ibtrs_clt_read_req(struct ibtrs_clt_io_req *req);

static int ibtrs_clt_failover_req(struct ibtrs_clt *clt,
				  struct ibtrs_clt_io_req *fail_req)
{
	struct ibtrs_clt_sess *alive_sess;
	struct ibtrs_clt_io_req *req;
	int err = -ECONNABORTED;
	struct path_it it;

	do_each_path(alive_sess, clt, &it) {
		if (unlikely(alive_sess->state != IBTRS_CLT_CONNECTED))
			continue;
		req = ibtrs_clt_get_copy_req(alive_sess, fail_req);
		if (req->dir == DMA_TO_DEVICE)
			err = ibtrs_clt_write_req(req);
		else
			err = ibtrs_clt_read_req(req);
		if (unlikely(err)) {
			req->in_use = false;
			continue;
		}
		/* Success path */
		ibtrs_clt_inc_failover_cnt(&alive_sess->stats);
		break;
	} while_each_path(&it);

	return err;
}

static void fail_all_outstanding_reqs(struct ibtrs_clt_sess *sess,
				      bool failover)
{
	struct ibtrs_clt *clt = sess->clt;
	struct ibtrs_clt_io_req *req;
	int i;

	if (!sess->reqs)
		return;
	for (i = 0; i < sess->queue_depth; ++i) {
		bool notify;
		int err = 0;

		req = &sess->reqs[i];
		if (!req->in_use)
			continue;

		if (failover)
			err = ibtrs_clt_failover_req(clt, req);

		notify = (!failover || err);
		complete_rdma_req(req, -ECONNABORTED, notify);
	}
}

static void free_sess_reqs(struct ibtrs_clt_sess *sess)
{
	struct ibtrs_clt_io_req *req;
	int i;

	if (!sess->reqs)
		return;
	for (i = 0; i < sess->queue_depth; ++i) {
		req = &sess->reqs[i];
		if (sess->fast_reg_mode == IBTRS_FAST_MEM_FR)
			kfree(req->fr_list);
		else if (sess->fast_reg_mode == IBTRS_FAST_MEM_FMR)
			kfree(req->fmr_list);
		kfree(req->map_page);
		ibtrs_iu_free(req->iu, DMA_TO_DEVICE,
			      sess->s.ib_dev->dev);
	}
	kfree(sess->reqs);
	sess->reqs = NULL;
}

static int alloc_sess_reqs(struct ibtrs_clt_sess *sess)
{
	struct ibtrs_clt_io_req *req;
	void *mr_list;
	int i;

	sess->reqs = kcalloc(sess->queue_depth, sizeof(*sess->reqs),
			     GFP_KERNEL);
	if (unlikely(!sess->reqs))
		return -ENOMEM;

	for (i = 0; i < sess->queue_depth; ++i) {
		req = &sess->reqs[i];
		req->iu = ibtrs_iu_alloc(i, sess->max_req_size, GFP_KERNEL,
					 sess->s.ib_dev->dev, DMA_TO_DEVICE,
					 ibtrs_clt_rdma_done);
		if (unlikely(!req->iu))
			goto out;
		mr_list = kmalloc_array(sess->max_pages_per_mr,
					sizeof(void *), GFP_KERNEL);
		if (unlikely(!mr_list))
			goto out;
		if (sess->fast_reg_mode == IBTRS_FAST_MEM_FR)
			req->fr_list = mr_list;
		else if (sess->fast_reg_mode == IBTRS_FAST_MEM_FMR)
			req->fmr_list = mr_list;

		req->map_page = kmalloc_array(sess->max_pages_per_mr,
					      sizeof(void *), GFP_KERNEL);
		if (unlikely(!req->map_page))
			goto out;
	}

	return 0;

out:
	free_sess_reqs(sess);

	return -ENOMEM;
}

static int alloc_tags(struct ibtrs_clt *clt)
{
	unsigned int chunk_bits;
	int err, i;

	clt->tags_map = kcalloc(BITS_TO_LONGS(clt->queue_depth), sizeof(long),
				GFP_KERNEL);
	if (unlikely(!clt->tags_map)) {
		err = -ENOMEM;
		goto out_err;
	}
	clt->tags = kcalloc(clt->queue_depth, TAG_SIZE(clt), GFP_KERNEL);
	if (unlikely(!clt->tags)) {
		err = -ENOMEM;
		goto err_map;
	}
	chunk_bits = ilog2(clt->queue_depth - 1) + 1;
	for (i = 0; i < clt->queue_depth; i++) {
		struct ibtrs_tag *tag;

		tag = GET_TAG(clt, i);
		tag->mem_id = i;
		tag->mem_off = i << (MAX_IMM_PAYL_BITS - chunk_bits);
	}

	return 0;

err_map:
	kfree(clt->tags_map);
	clt->tags_map = NULL;
out_err:
	return err;
}

static void free_tags(struct ibtrs_clt *clt)
{
	kfree(clt->tags_map);
	clt->tags_map = NULL;
	kfree(clt->tags);
	clt->tags = NULL;
}

static void query_fast_reg_mode(struct ibtrs_clt_sess *sess)
{
	struct ibtrs_ib_dev *ib_dev;
	u64 max_pages_per_mr;
	int mr_page_shift;

	ib_dev = sess->s.ib_dev;
	if (ib_dev->dev->alloc_fmr && ib_dev->dev->dealloc_fmr &&
	    ib_dev->dev->map_phys_fmr && ib_dev->dev->unmap_fmr) {
		sess->fast_reg_mode = IBTRS_FAST_MEM_FMR;
		ibtrs_info(sess, "Device %s supports FMR\n", ib_dev->dev->name);
	}
	if (ib_dev->attrs.device_cap_flags & IB_DEVICE_MEM_MGT_EXTENSIONS &&
	    use_fr) {
		sess->fast_reg_mode = IBTRS_FAST_MEM_FR;
		ibtrs_info(sess, "Device %s supports FR\n", ib_dev->dev->name);
	}

	/*
	 * Use the smallest page size supported by the HCA, down to a
	 * minimum of 4096 bytes. We're unlikely to build large sglists
	 * out of smaller entries.
	 */
	mr_page_shift      = max(12, ffs(ib_dev->attrs.page_size_cap) - 1);
	sess->mr_page_size = 1 << mr_page_shift;
	sess->max_sge      = ib_dev->attrs.max_sge;
	sess->mr_page_mask = ~((u64)sess->mr_page_size - 1);
	max_pages_per_mr   = ib_dev->attrs.max_mr_size;
	do_div(max_pages_per_mr, sess->mr_page_size);
	sess->max_pages_per_mr = min_t(u64, sess->max_pages_per_mr,
				       max_pages_per_mr);
	if (sess->fast_reg_mode == IBTRS_FAST_MEM_FR) {
		sess->max_pages_per_mr =
			min_t(u32, sess->max_pages_per_mr,
			      ib_dev->attrs.max_fast_reg_page_list_len);
	}
	sess->mr_max_size = sess->mr_page_size * sess->max_pages_per_mr;
}

static int alloc_con_fast_pool(struct ibtrs_clt_con *con)
{
	struct ibtrs_clt_sess *sess = to_clt_sess(con->c.sess);
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

	return 0;

free_reqs:
	free_sess_reqs(sess);

	return ret;
}

static void free_sess_io_bufs(struct ibtrs_clt_sess *sess)
{
	free_sess_reqs(sess);
	free_sess_fast_pool(sess);
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
		case IBTRS_CLT_CLOSED:
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
	case IBTRS_CLT_DEAD:
		switch (old_state) {
		case IBTRS_CLT_CLOSED:
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

static void ibtrs_clt_hb_err_handler(struct ibtrs_con *c, int err)
{
	struct ibtrs_clt_con *con;

	(void)err;
	con = container_of(c, typeof(*con), c);
	ibtrs_rdma_error_recovery(con);
}

static void ibtrs_clt_init_hb(struct ibtrs_clt_sess *sess)
{
	ibtrs_init_hb(&sess->s, &io_comp_cqe,
		      IBTRS_HB_INTERVAL_MS,
		      IBTRS_HB_MISSED_MAX,
		      ibtrs_clt_hb_err_handler,
		      ibtrs_wq);
}

static void ibtrs_clt_start_hb(struct ibtrs_clt_sess *sess)
{
	ibtrs_start_hb(&sess->s);
}

static void ibtrs_clt_stop_hb(struct ibtrs_clt_sess *sess)
{
	ibtrs_stop_hb(&sess->s);
}

static void ibtrs_clt_reconnect_work(struct work_struct *work);
static void ibtrs_clt_close_work(struct work_struct *work);

static struct ibtrs_clt_sess *alloc_sess(struct ibtrs_clt *clt,
					 const struct ibtrs_addr *path,
					 size_t con_num, u16 max_segments)
{
	struct ibtrs_clt_sess *sess;
	int err = -ENOMEM;
	int cpu;

	sess = kzalloc(sizeof(*sess), GFP_KERNEL);
	if (unlikely(!sess))
		goto err;

	/* Extra connection for user messages */
	con_num += 1;

	sess->s.con = kcalloc(con_num, sizeof(*sess->s.con), GFP_KERNEL);
	if (unlikely(!sess->s.con))
		goto err_free_sess;

	mutex_init(&sess->init_mutex);
	uuid_gen(&sess->s.uuid);
	memcpy(&sess->s.dst_addr, path->dst,
	       rdma_addr_size((struct sockaddr *)path->dst));

	/*
	 * rdma_resolve_addr() passes src_addr to cma_bind_addr, which
	 * checks the sa_family to be non-zero. If user passed src_addr=NULL
	 * the sess->src_addr will contain only zeros, which is then fine.
	 */
	if (path->src)
		memcpy(&sess->s.src_addr, path->src,
		       rdma_addr_size((struct sockaddr *)path->src));
	strlcpy(sess->s.sessname, clt->sessname, sizeof(sess->s.sessname));
	sess->s.con_num = con_num;
	sess->clt = clt;
	sess->max_pages_per_mr = max_segments;
	init_waitqueue_head(&sess->state_wq);
	sess->state = IBTRS_CLT_CONNECTING;
	atomic_set(&sess->connected_cnt, 0);
	INIT_WORK(&sess->close_work, ibtrs_clt_close_work);
	INIT_DELAYED_WORK(&sess->reconnect_dwork, ibtrs_clt_reconnect_work);
	ibtrs_clt_init_hb(sess);

	sess->mp_skip_entry = alloc_percpu(typeof(*sess->mp_skip_entry));
	if (unlikely(!sess->mp_skip_entry))
		goto err_free_con;

	for_each_possible_cpu(cpu)
		INIT_LIST_HEAD(per_cpu_ptr(sess->mp_skip_entry, cpu));

	err = ibtrs_clt_init_stats(&sess->stats);
	if (unlikely(err))
		goto err_free_percpu;

	return sess;

err_free_percpu:
	free_percpu(sess->mp_skip_entry);
err_free_con:
	kfree(sess->s.con);
err_free_sess:
	kfree(sess);
err:
	return ERR_PTR(err);
}

static void free_sess(struct ibtrs_clt_sess *sess)
{
	ibtrs_clt_free_stats(&sess->stats);
	free_percpu(sess->mp_skip_entry);
	kfree(sess->s.con);
	kfree(sess->srv_rdma_addr);
	kfree(sess);
}

static int create_con(struct ibtrs_clt_sess *sess, unsigned int cid)
{
	struct ibtrs_clt_con *con;

	con = kzalloc(sizeof(*con), GFP_KERNEL);
	if (unlikely(!con))
		return -ENOMEM;

	/* Map first two connections to the first CPU */
	con->cpu  = (cid ? cid - 1 : 0) % nr_cpu_ids;
	con->c.cid = cid;
	con->c.sess = &sess->s;
	atomic_set(&con->io_cnt, 0);

	sess->s.con[cid] = &con->c;

	return 0;
}

static void destroy_con(struct ibtrs_clt_con *con)
{
	struct ibtrs_clt_sess *sess = to_clt_sess(con->c.sess);

	sess->s.con[con->c.cid] = NULL;
	kfree(con);
}

static int create_con_cq_qp(struct ibtrs_clt_con *con)
{
	struct ibtrs_clt_sess *sess = to_clt_sess(con->c.sess);
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

	if (con->c.cid == 0) {
		cq_size = SERVICE_CON_QUEUE_DEPTH;
		/* + 2 for drain and heartbeat */
		wr_queue_size = SERVICE_CON_QUEUE_DEPTH + 2;
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
		wr_queue_size = sess->s.ib_dev->attrs.max_qp_wr;
		wr_queue_size = min_t(int, wr_queue_size,
				      sess->queue_depth * num_wr *
				      (use_fr ? 3 : 2) + 1);
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

	if (con->c.cid) {
		err = alloc_con_fast_pool(con);
		if (unlikely(err))
			ibtrs_cq_qp_destroy(&con->c);
	}

	return err;
}

static void destroy_con_cq_qp(struct ibtrs_clt_con *con)
{
	struct ibtrs_clt_sess *sess = to_clt_sess(con->c.sess);

	/*
	 * Be careful here: destroy_con_cq_qp() can be called even
	 * create_con_cq_qp() failed, see comments there.
	 */

	ibtrs_cq_qp_destroy(&con->c);
	if (con->c.cid != 0)
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
	con->c.cm_id = NULL;
}

static int ibtrs_clt_rdma_cm_handler(struct rdma_cm_id *cm_id,
				     struct rdma_cm_event *ev);

static int create_cm(struct ibtrs_clt_con *con)
{
	struct ibtrs_clt_sess *sess = to_clt_sess(con->c.sess);
	struct rdma_cm_id *cm_id;
	int err;

	cm_id = rdma_create_id(&init_net, ibtrs_clt_rdma_cm_handler, con,
			       sess->s.dst_addr.ss_family == AF_IB ?
			       RDMA_PS_IB : RDMA_PS_TCP, IB_QPT_RC);
	if (unlikely(IS_ERR(cm_id))) {
		err = PTR_ERR(cm_id);
		ibtrs_err(sess, "Failed to create CM ID, err: %d\n", err);

		return err;
	}
	con->c.cm_id = cm_id;
	con->cm_err = 0;
	/* allow the port to be reused */
	err = rdma_set_reuseaddr(cm_id, 1);
	if (err != 0) {
		ibtrs_err(sess, "Set address reuse failed, err: %d\n", err);
		goto destroy_cm;
	}
	err = rdma_resolve_addr(cm_id, (struct sockaddr *)&sess->s.src_addr,
				(struct sockaddr *)&sess->s.dst_addr,
				IBTRS_CONNECT_TIMEOUT_MS);
	if (unlikely(err)) {
		ibtrs_err(sess, "Failed to resolve address, err: %d\n", err);
		goto destroy_cm;
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
destroy_cm:
	destroy_cm(con);

	return err;
}

static void ibtrs_clt_sess_up(struct ibtrs_clt_sess *sess)
{
	struct ibtrs_clt *clt = sess->clt;
	int up;

	/*
	 * We can fire RECONNECTED event only when all paths were
	 * connected on ibtrs_clt_open(), then each was disconnected
	 * and the first one connected again.  That's why this nasty
	 * game with counter value.
	 */

	mutex_lock(&clt->paths_ev_mutex);
	up = ++clt->paths_up;
	/*
	 * Here it is safe to access paths num directly since up counter
	 * is greater than MAX_PATHS_NUM only while ibtrs_clt_open() is
	 * in progress, thus paths removals are impossible.
	 */
	if (up > MAX_PATHS_NUM && up == MAX_PATHS_NUM + clt->paths_num)
		clt->paths_up = clt->paths_num;
	else if (up == 1)
		clt->link_ev(clt->priv, IBTRS_CLT_LINK_EV_RECONNECTED);
	mutex_unlock(&clt->paths_ev_mutex);

	/* Mark session as established */
	sess->established = true;
	sess->reconnect_attempts = 0;
	sess->stats.reconnects.successful_cnt++;
}

static void ibtrs_clt_sess_down(struct ibtrs_clt_sess *sess)
{
	struct ibtrs_clt *clt = sess->clt;

	if (!sess->established)
		return;

	sess->established = false;
	mutex_lock(&clt->paths_ev_mutex);
	WARN_ON(!clt->paths_up);
	if (--clt->paths_up == 0)
		clt->link_ev(clt->priv, IBTRS_CLT_LINK_EV_DISCONNECTED);
	mutex_unlock(&clt->paths_ev_mutex);
}

static void ibtrs_clt_stop_and_destroy_conns(struct ibtrs_clt_sess *sess,
					     bool failover)
{
	struct ibtrs_clt_con *con;
	unsigned int cid;

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

	ibtrs_clt_stop_hb(sess);

	/*
	 * The order it utterly crucial: firstly disconnect and complete all
	 * rdma requests with error (thus set in_use=false for requests),
	 * then fail outstanding requests checking in_use for each, and
	 * eventually notify upper layer about session disconnection.
	 */

	for (cid = 0; cid < sess->s.con_num; cid++) {
		con = to_clt_con(sess->s.con[cid]);
		if (!con)
			break;

		stop_cm(con);
	}
	fail_all_outstanding_reqs(sess, failover);
	free_sess_io_bufs(sess);
	ibtrs_clt_sess_down(sess);

	/*
	 * Wait for graceful shutdown, namely when peer side invokes
	 * rdma_disconnect(). 'connected_cnt' is decremented only on
	 * CM events, thus if other side had crashed and hb has detected
	 * something is wrong, here we will stuck for exactly timeout ms,
	 * since CM does not fire anything.  That is fine, we are not in
	 * hurry.
	 */
	wait_event_timeout(sess->state_wq, !atomic_read(&sess->connected_cnt),
			   msecs_to_jiffies(IBTRS_CONNECT_TIMEOUT_MS));

	for (cid = 0; cid < sess->s.con_num; cid++) {
		con = to_clt_con(sess->s.con[cid]);
		if (!con)
			break;

		destroy_con_cq_qp(con);
		destroy_cm(con);
		destroy_con(con);
	}
}

static void ibtrs_clt_remove_path_from_arr(struct ibtrs_clt_sess *sess)
{
	struct ibtrs_clt *clt = sess->clt;
	struct ibtrs_clt_sess *next;
	int cpu;

	mutex_lock(&clt->paths_mutex);
	list_del_rcu(&sess->s.entry);

	/* Make sure everybody observes path removal. */
	synchronize_rcu();

	/*
	 * Decrement paths number only after grace period, because
	 * caller of do_each_path() must firstly observe list without
	 * path and only then decremented paths number.
	 *
	 * Otherwise there can be the following situation:
	 *    o Two paths exist and IO is coming.
	 *    o One path is removed:
	 *      CPU#0                          CPU#1
	 *      do_each_path():                ibtrs_clt_remove_path_from_arr():
	 *          path = get_next_path()
	 *          ^^^                            list_del_rcu(path)
	 *          [!CONNECTED path]              clt->paths_num--
	 *                                              ^^^^^^^^^
	 *          load clt->paths_num                 from 2 to 1
	 *                    ^^^^^^^^^
	 *                    sees 1
	 *
	 *      path is observed as !CONNECTED, but do_each_path() loop
	 *      ends, because expression i < clt->paths_num is false.
	 */
	clt->paths_num--;

	next = list_next_or_null_rcu_rr(sess, &clt->paths_list, s.entry);

	/*
	 * Pcpu paths can still point to the path which is going to be
	 * removed, so change the pointer manually.
	 */
	for_each_possible_cpu(cpu) {
		struct ibtrs_clt_sess **ppcpu_path;

		ppcpu_path = per_cpu_ptr(clt->pcpu_path, cpu);
		if (*ppcpu_path != sess)
			/*
			 * synchronize_rcu() was called just after deleting
			 * entry from the list, thus IO code path cannot
			 * change pointer back to the pointer which is going
			 * to be removed, we are safe here.
			 */
			continue;

		/*
		 * We race with IO code path, which also changes pointer,
		 * thus we have to be careful not to override it.
		 */
		cmpxchg(ppcpu_path, sess, next);
	}
	mutex_unlock(&clt->paths_mutex);
}

static inline bool __ibtrs_clt_path_exists(struct ibtrs_clt *clt,
					   struct ibtrs_addr *addr)
{
	struct ibtrs_clt_sess *sess;

	list_for_each_entry(sess, &clt->paths_list, s.entry)
		if (!sockaddr_cmp((struct sockaddr *)&sess->s.dst_addr,
				  addr->dst))
			return true;

	return false;
}

static bool ibtrs_clt_path_exists(struct ibtrs_clt *clt,
				  struct ibtrs_addr *addr)
{
	bool res;

	mutex_lock(&clt->paths_mutex);
	res = __ibtrs_clt_path_exists(clt, addr);
	mutex_unlock(&clt->paths_mutex);

	return res;
}

static int ibtrs_clt_add_path_to_arr(struct ibtrs_clt_sess *sess,
				     struct ibtrs_addr *addr)
{
	struct ibtrs_clt *clt = sess->clt;
	int err = 0;

	mutex_lock(&clt->paths_mutex);
	if (!__ibtrs_clt_path_exists(clt, addr)) {
		list_add_tail_rcu(&sess->s.entry, &clt->paths_list);
		clt->paths_num++;
	} else
		err = -EEXIST;
	mutex_unlock(&clt->paths_mutex);

	return err;
}

static void ibtrs_clt_close_work(struct work_struct *work)
{
	struct ibtrs_clt_sess *sess;
	/*
	 * Always try to do a failover, if only single path remains,
	 * all requests will be completed with error.
	 */
	bool failover = true;

	sess = container_of(work, struct ibtrs_clt_sess, close_work);

	cancel_delayed_work_sync(&sess->reconnect_dwork);
	ibtrs_clt_stop_and_destroy_conns(sess, failover);
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
	ibtrs_clt_change_state(sess, IBTRS_CLT_CLOSED);
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
	unsigned int cid;
	int err;

	/*
	 * On every new session connections increase reconnect counter
	 * to avoid clashes with previous sessions not yet closed
	 * sessions on a server side.
	 */
	sess->s.recon_cnt++;

	/* Establish all RDMA connections  */
	for (cid = 0; cid < sess->s.con_num; cid++) {
		err = create_con(sess, cid);
		if (unlikely(err))
			goto destroy;

		err = create_cm(to_clt_con(sess->s.con[cid]));
		if (unlikely(err)) {
			destroy_con(to_clt_con(sess->s.con[cid]));
			goto destroy;
		}
	}
	/* Allocate all session related buffers */
	err = alloc_sess_io_bufs(sess);
	if (unlikely(err))
		goto destroy;

	ibtrs_clt_start_hb(sess);

	return 0;

destroy:
	while (cid--) {
		struct ibtrs_clt_con *con = to_clt_con(sess->s.con[cid]);

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
	struct ibtrs_clt_sess *sess = to_clt_sess(con->c.sess);
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
	struct ibtrs_clt_sess *sess = to_clt_sess(con->c.sess);
	struct ibtrs_clt *clt = sess->clt;
	struct ibtrs_msg_conn_req msg;
	struct rdma_conn_param param;

	int err;

	memset(&param, 0, sizeof(param));
	param.retry_count = retry_count;
	param.rnr_retry_count = 7;
	param.private_data = &msg;
	param.private_data_len = sizeof(msg);

	/*
	 * Those two are the part of struct cma_hdr which is shared
	 * with private_data in case of AF_IB, so put zeroes to avoid
	 * wrong validation inside cma.c on receiver side.
	 */
	msg.__cma_version = 0;
	msg.__ip_version = 0;
	msg.magic = cpu_to_le16(IBTRS_MAGIC);
	msg.version = cpu_to_le16(IBTRS_VERSION);
	msg.cid = cpu_to_le16(con->c.cid);
	msg.cid_num = cpu_to_le16(sess->s.con_num);
	msg.recon_cnt = cpu_to_le16(sess->s.recon_cnt);
	uuid_copy(&msg.sess_uuid, &sess->s.uuid);
	uuid_copy(&msg.paths_uuid, &clt->paths_uuid);

	err = rdma_connect(con->c.cm_id, &param);
	if (err)
		ibtrs_err(sess, "rdma_connect(): %d\n", err);

	return err;
}

static int ibtrs_rdma_conn_established(struct ibtrs_clt_con *con,
				       struct rdma_cm_event *ev)
{
	struct ibtrs_clt_sess *sess = to_clt_sess(con->c.sess);
	const struct ibtrs_msg_conn_rsp *msg;
	u16 version, queue_depth;
	int errno;
	u8 len;

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
	if (con->c.cid == 0) {
		queue_depth = le16_to_cpu(msg->queue_depth);

		if (queue_depth > MAX_SESS_QUEUE_DEPTH) {
			ibtrs_err(sess, "Invalid IBTRS message: queue=%d\n",
				  queue_depth);
			return -ECONNRESET;
		}
		if (!sess->srv_rdma_addr || sess->queue_depth < queue_depth) {
			kfree(sess->srv_rdma_addr);
			sess->srv_rdma_addr =
				kcalloc(queue_depth,
					sizeof(*sess->srv_rdma_addr),
					GFP_KERNEL);
			if (unlikely(!sess->srv_rdma_addr)) {
				ibtrs_err(sess, "Failed to allocate "
					  "queue_depth=%d\n", queue_depth);
				return -ENOMEM;
			}
		}
		sess->queue_depth = queue_depth;
		sess->srv_rdma_buf_rkey = le32_to_cpu(msg->rkey);
		sess->max_req_size = le32_to_cpu(msg->max_req_size);
		sess->max_io_size = le32_to_cpu(msg->max_io_size);
		sess->chunk_size = sess->max_io_size + sess->max_req_size;
		sess->max_desc  = sess->max_req_size;
		sess->max_desc -= sizeof(u32) + sizeof(u32) + IO_MSG_SIZE;
		sess->max_desc /= sizeof(struct ibtrs_sg_desc);

		/*
		 * Global queue depth and is always a minimum.  If while a
		 * reconnection server sends us a value a bit higher -
		 * client does not care and uses cached minimum.
		 */
		ibtrs_clt_set_min_queue_depth(sess->clt, sess->queue_depth);
		ibtrs_clt_set_min_io_size(sess->clt, sess->max_io_size);
	}

	return 0;
}

static int ibtrs_rdma_conn_rejected(struct ibtrs_clt_con *con,
				    struct rdma_cm_event *ev)
{
	struct ibtrs_clt_sess *sess = to_clt_sess(con->c.sess);
	const struct ibtrs_msg_conn_rsp *msg;
	const char *rej_msg;
	int status, errno;
	u8 data_len;

	status = ev->status;
	rej_msg = rdma_reject_msg(con->c.cm_id, status);
	msg = rdma_consumer_reject_data(con->c.cm_id, ev, &data_len);

	if (msg && data_len >= sizeof(*msg)) {
		errno = (int16_t)le16_to_cpu(msg->errno);
		if (errno == -EBUSY)
			ibtrs_err(sess,
				  "Previous session is still exists on the "
				  "server, please reconnect later\n");
		else
			ibtrs_err(sess,
				  "Connect rejected: status %d (%s), ibtrs "
				  "errno %d\n", status, rej_msg, errno);
	} else {
		ibtrs_err(sess,
			  "Connect rejected but with malformed message: "
			  "status %d (%s)\n", status, rej_msg);
	}

	return -ECONNRESET;
}

static void ibtrs_rdma_error_recovery(struct ibtrs_clt_con *con)
{
	struct ibtrs_clt_sess *sess = to_clt_sess(con->c.sess);

	if (ibtrs_clt_change_state_from_to(sess,
					   IBTRS_CLT_CONNECTED,
					   IBTRS_CLT_RECONNECTING)) {
		/*
		 * Normal scenario, reconnect if we were successfully connected
		 */
		queue_delayed_work(ibtrs_wq, &sess->reconnect_dwork, 0);
	} else {
		/*
		 * Error can happen just on establishing new connection,
		 * so notify waiter with error state, waiter is responsible
		 * for cleaning the rest and reconnect if needed.
		 */
		ibtrs_clt_change_state_from_to(sess,
					       IBTRS_CLT_CONNECTING,
					       IBTRS_CLT_CONNECTING_ERR);
	}
}

static inline void flag_success_on_conn(struct ibtrs_clt_con *con)
{
	struct ibtrs_clt_sess *sess = to_clt_sess(con->c.sess);

	atomic_inc(&sess->connected_cnt);
	con->cm_err = 1;
}

static inline void flag_error_on_conn(struct ibtrs_clt_con *con, int cm_err)
{
	if (con->cm_err == 1) {
		struct ibtrs_clt_sess *sess;

		sess = to_clt_sess(con->c.sess);
		if (atomic_dec_and_test(&sess->connected_cnt))
			wake_up(&sess->state_wq);
	}
	con->cm_err = cm_err;
}

static int ibtrs_clt_rdma_cm_handler(struct rdma_cm_id *cm_id,
				     struct rdma_cm_event *ev)
{
	struct ibtrs_clt_con *con = cm_id->context;
	struct ibtrs_clt_sess *sess = to_clt_sess(con->c.sess);
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
			flag_success_on_conn(con);
			wake_up(&sess->state_wq);
			return 0;
		}
		break;
	case RDMA_CM_EVENT_REJECTED:
		cm_err = ibtrs_rdma_conn_rejected(con, ev);
		break;
	case RDMA_CM_EVENT_CONNECT_ERROR:
	case RDMA_CM_EVENT_UNREACHABLE:
		ibtrs_wrn(sess, "CM error event %d\n", ev->event);
		cm_err = -ECONNRESET;
		break;
	case RDMA_CM_EVENT_ADDR_ERROR:
	case RDMA_CM_EVENT_ROUTE_ERROR:
		cm_err = -EHOSTUNREACH;
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
		flag_error_on_conn(con, cm_err);
		ibtrs_rdma_error_recovery(con);
	}

	return 0;
}

static void ibtrs_clt_info_req_done(struct ib_cq *cq, struct ib_wc *wc)
{
	struct ibtrs_clt_con *con = cq->cq_context;
	struct ibtrs_clt_sess *sess = to_clt_sess(con->c.sess);
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
	unsigned int addr_num;
	int i;

	addr_num = le16_to_cpu(msg->addr_num);
	/*
	 * Check if IB immediate data size is enough to hold the mem_id and
	 * the offset inside the memory chunk.
	 */
	if (unlikely(ilog2(addr_num - 1) + ilog2(sess->chunk_size - 1) >
		     MAX_IMM_PAYL_BITS)) {
		ibtrs_err(sess, "RDMA immediate size (%db) not enough to "
			  "encode %d buffers of size %dB\n",  MAX_IMM_PAYL_BITS,
			  addr_num, sess->chunk_size);
		return -EINVAL;
	}
	if (unlikely(addr_num > sess->queue_depth)) {
		ibtrs_err(sess, "Incorrect addr_num=%d\n", addr_num);
		return -EINVAL;
	}
	for (i = 0; i < msg->addr_num; i++)
		sess->srv_rdma_addr[i] = le64_to_cpu(msg->addr[i]);

	return 0;
}

static void ibtrs_clt_info_rsp_done(struct ib_cq *cq, struct ib_wc *wc)
{
	struct ibtrs_clt_con *con = cq->cq_context;
	struct ibtrs_clt_sess *sess = to_clt_sess(con->c.sess);
	struct ibtrs_msg_info_rsp *msg;
	enum ibtrs_clt_state state;
	struct ibtrs_iu *iu;
	size_t rx_sz;
	int err;

	state = IBTRS_CLT_CONNECTING_ERR;

	WARN_ON(con->c.cid);
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

static int ibtrs_send_sess_info(struct ibtrs_clt_sess *sess)
{
	struct ibtrs_clt_con *usr_con = to_clt_con(sess->s.con[0]);
	struct ibtrs_msg_info_req *msg;
	struct ibtrs_iu *tx_iu, *rx_iu;
	size_t rx_sz;
	int err;

	rx_sz  = sizeof(struct ibtrs_msg_info_rsp);
	rx_sz += sizeof(u64) * MAX_SESS_QUEUE_DEPTH;

	tx_iu = ibtrs_iu_alloc(0, sizeof(struct ibtrs_msg_info_req), GFP_KERNEL,
			       sess->s.ib_dev->dev, DMA_TO_DEVICE,
			       ibtrs_clt_info_req_done);
	rx_iu = ibtrs_iu_alloc(0, rx_sz, GFP_KERNEL, sess->s.ib_dev->dev,
			       DMA_FROM_DEVICE, ibtrs_clt_info_rsp_done);
	if (unlikely(!tx_iu || !rx_iu)) {
		ibtrs_err(sess, "ibtrs_iu_alloc(): no memory\n");
		err = -ENOMEM;
		goto out;
	}
	/* Prepare for getting info response */
	err = ibtrs_iu_post_recv(&usr_con->c, rx_iu);
	if (unlikely(err)) {
		ibtrs_err(sess, "ibtrs_iu_post_recv(), err: %d\n", err);
		goto out;
	}
	rx_iu = NULL;

	msg = tx_iu->buf;
	msg->type = cpu_to_le16(IBTRS_MSG_INFO_REQ);
	memcpy(msg->sessname, sess->s.sessname, sizeof(msg->sessname));

	/* Send info request */
	err = ibtrs_iu_post_send(&usr_con->c, tx_iu, sizeof(*msg));
	if (unlikely(err)) {
		ibtrs_err(sess, "ibtrs_iu_post_send(), err: %d\n", err);
		goto out;
	}
	tx_iu = NULL;

	/* Wait for state change */
	wait_event_interruptible_timeout(sess->state_wq,
				sess->state != IBTRS_CLT_CONNECTING,
				msecs_to_jiffies(IBTRS_CONNECT_TIMEOUT_MS));
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
	if (unlikely(err))
		/* If we've never taken async path because of malloc problems */
		ibtrs_clt_change_state(sess, IBTRS_CLT_CONNECTING_ERR);

	return err;
}

/**
 * init_sess() - establishes all session connections and does handshake
 *
 * In case of error full close or reconnect procedure should be taken,
 * because reconnect or close async works can be started.
 */
static int init_sess(struct ibtrs_clt_sess *sess)
{
	int err;

	mutex_lock(&sess->init_mutex);
	err = init_conns(sess);
	if (unlikely(err)) {
		ibtrs_err(sess, "init_conns(), err: %d\n", err);
		goto out;
	}
	err = ibtrs_send_sess_info(sess);
	if (unlikely(err)) {
		ibtrs_err(sess, "ibtrs_send_sess_info(), err: %d\n", err);
		goto out;
	}
	ibtrs_clt_sess_up(sess);
out:
	mutex_unlock(&sess->init_mutex);

	return err;
}

static void ibtrs_clt_reconnect_work(struct work_struct *work)
{
	struct ibtrs_clt_sess *sess;
	struct ibtrs_clt *clt;
	unsigned int delay_ms;
	int err;

	sess = container_of(to_delayed_work(work), struct ibtrs_clt_sess,
			    reconnect_dwork);
	clt = sess->clt;

	if (ibtrs_clt_state(sess) == IBTRS_CLT_CLOSING)
		/* User requested closing */
		return;

	if (sess->reconnect_attempts >= clt->max_reconnect_attempts) {
		/* Close a session completely if max attempts is reached */
		ibtrs_clt_close_conns(sess, false);
		return;
	}
	sess->reconnect_attempts++;

	/* Stop everything */
	ibtrs_clt_stop_and_destroy_conns(sess, true);
	ibtrs_clt_change_state(sess, IBTRS_CLT_CONNECTING);

	err = init_sess(sess);
	if (unlikely(err))
		goto reconnect_again;

	return;

reconnect_again:
	if (ibtrs_clt_change_state(sess, IBTRS_CLT_RECONNECTING)) {
		sess->stats.reconnects.fail_cnt++;
		delay_ms = clt->reconnect_delay_sec * 1000;
		queue_delayed_work(ibtrs_wq, &sess->reconnect_dwork,
				   msecs_to_jiffies(delay_ms));
	}
}

static struct ibtrs_clt *alloc_clt(const char *sessname, size_t paths_num,
				   short port, size_t pdu_sz,
				   void *priv, link_clt_ev_fn *link_ev,
				   unsigned int max_segments,
				   unsigned int reconnect_delay_sec,
				   unsigned int max_reconnect_attempts)
{
	struct ibtrs_clt *clt;
	int err;

	if (unlikely(!paths_num || paths_num > MAX_PATHS_NUM))
		return ERR_PTR(-EINVAL);

	if (unlikely(strlen(sessname) >= sizeof(clt->sessname)))
		return ERR_PTR(-EINVAL);

	clt = kzalloc(sizeof(*clt), GFP_KERNEL);
	if (unlikely(!clt))
		return ERR_PTR(-ENOMEM);

	clt->pcpu_path = alloc_percpu(typeof(*clt->pcpu_path));
	if (unlikely(!clt->pcpu_path)) {
		kfree(clt);
		return ERR_PTR(-ENOMEM);
	}

	uuid_gen(&clt->paths_uuid);
	INIT_LIST_HEAD_RCU(&clt->paths_list);
	clt->paths_num = paths_num;
	clt->paths_up = MAX_PATHS_NUM;
	clt->port = port;
	clt->pdu_sz = pdu_sz;
	clt->max_segments = max_segments;
	clt->reconnect_delay_sec = reconnect_delay_sec;
	clt->max_reconnect_attempts = max_reconnect_attempts;
	clt->priv = priv;
	clt->link_ev = link_ev;
	clt->mp_policy = MP_POLICY_MIN_INFLIGHT;
	strlcpy(clt->sessname, sessname, sizeof(clt->sessname));
	init_waitqueue_head(&clt->tags_wait);
	mutex_init(&clt->paths_ev_mutex);
	mutex_init(&clt->paths_mutex);

	err = ibtrs_clt_create_sysfs_root_folders(clt);
	if (unlikely(err)) {
		free_percpu(clt->pcpu_path);
		kfree(clt);
		return ERR_PTR(err);
	}

	return clt;
}

static void wait_for_inflight_tags(struct ibtrs_clt *clt)
{
	if (clt->tags_map) {
		size_t sz = clt->queue_depth;

		wait_event(clt->tags_wait,
			   find_first_bit(clt->tags_map, sz) >= sz);
	}
}

static void free_clt(struct ibtrs_clt *clt)
{
	ibtrs_clt_destroy_sysfs_root_folders(clt);
	wait_for_inflight_tags(clt);
	free_tags(clt);
	free_percpu(clt->pcpu_path);
	kfree(clt);
}

struct ibtrs_clt *ibtrs_clt_open(void *priv, link_clt_ev_fn *link_ev,
				 const char *sessname,
				 const struct ibtrs_addr *paths,
				 size_t paths_num,
				 short port,
				 size_t pdu_sz, u8 reconnect_delay_sec,
				 u16 max_segments,
				 s16 max_reconnect_attempts)
{
	struct ibtrs_clt_sess *sess, *tmp;
	struct ibtrs_clt *clt;
	int err, i;

	clt = alloc_clt(sessname, paths_num, port, pdu_sz, priv, link_ev,
			max_segments, reconnect_delay_sec,
			max_reconnect_attempts);
	if (unlikely(IS_ERR(clt))) {
		err = PTR_ERR(clt);
		goto out;
	}
	for (i = 0; i < paths_num; i++) {
		struct ibtrs_clt_sess *sess;

		sess = alloc_sess(clt, &paths[i], nr_cons_per_session,
				  max_segments);
		if (unlikely(IS_ERR(sess))) {
			err = PTR_ERR(sess);
			ibtrs_err(clt, "alloc_sess(), err: %d\n", err);
			goto close_all_sess;
		}
		list_add_tail_rcu(&sess->s.entry, &clt->paths_list);

		err = init_sess(sess);
		if (unlikely(err))
			goto close_all_sess;

		err = ibtrs_clt_create_sess_files(sess);
		if (unlikely(err))
			goto close_all_sess;
	}
	err = alloc_tags(clt);
	if (unlikely(err)) {
		ibtrs_err(clt, "alloc_tags(), err: %d\n", err);
		goto close_all_sess;
	}
	err = ibtrs_clt_create_sysfs_root_files(clt);
	if (unlikely(err))
		goto close_all_sess;

	/*
	 * There is a race if someone decides to completely remove just
	 * newly created path using sysfs entry.  To avoid the race we
	 * use simple 'opened' flag, see ibtrs_clt_remove_path_from_sysfs().
	 */
	clt->opened = true;

	/* Do not let module be unloaded if client is alive */
	__module_get(THIS_MODULE);

	return clt;

close_all_sess:
	list_for_each_entry_safe(sess, tmp, &clt->paths_list, s.entry) {
		ibtrs_clt_destroy_sess_files(sess, NULL);
		ibtrs_clt_close_conns(sess, true);
		free_sess(sess);
	}
	free_clt(clt);

out:
	return ERR_PTR(err);
}
EXPORT_SYMBOL(ibtrs_clt_open);

void ibtrs_clt_close(struct ibtrs_clt *clt)
{
	struct ibtrs_clt_sess *sess, *tmp;

	/* Firstly forbid sysfs access */
	ibtrs_clt_destroy_sysfs_root_files(clt);
	ibtrs_clt_destroy_sysfs_root_folders(clt);

	/* Now it is safe to iterate over all paths without locks */
	list_for_each_entry_safe(sess, tmp, &clt->paths_list, s.entry) {
		ibtrs_clt_destroy_sess_files(sess, NULL);
		ibtrs_clt_close_conns(sess, true);
		free_sess(sess);
	}
	free_clt(clt);
	module_put(THIS_MODULE);
}
EXPORT_SYMBOL(ibtrs_clt_close);

int ibtrs_clt_reconnect_from_sysfs(struct ibtrs_clt_sess *sess)
{
	enum ibtrs_clt_state old_state;
	int err = -EBUSY;
	bool changed;

	changed = ibtrs_clt_change_state_get_old(sess, IBTRS_CLT_RECONNECTING,
						 &old_state);
	if (changed) {
		sess->reconnect_attempts = 0;
		queue_delayed_work(ibtrs_wq, &sess->reconnect_dwork, 0);
	}
	if (changed || old_state == IBTRS_CLT_RECONNECTING) {
		/*
		 * flush_delayed_work() queues pending work for immediate
		 * execution, so do the flush if we have queued something
		 * right now or work is pending.
		 */
		flush_delayed_work(&sess->reconnect_dwork);
		err = ibtrs_clt_sess_is_connected(sess) ? 0 : -ENOTCONN;
	}

	return err;
}

int ibtrs_clt_disconnect_from_sysfs(struct ibtrs_clt_sess *sess)
{
	ibtrs_clt_close_conns(sess, true);

	return 0;
}

int ibtrs_clt_remove_path_from_sysfs(struct ibtrs_clt_sess *sess,
				     const struct attribute *sysfs_self)
{
	struct ibtrs_clt *clt = sess->clt;
	enum ibtrs_clt_state old_state;
	bool changed;

	/*
	 * That can happen only when userspace tries to remove path
	 * very early, when ibtrs_clt_open() is not yet finished.
	 */
	if (unlikely(!clt->opened))
		return -EBUSY;

	/*
	 * Continue stopping path till state was changed to DEAD or
	 * state was observed as DEAD:
	 * 1. State was changed to DEAD - we were fast and nobody
	 *    invoked ibtrs_clt_reconnect(), which can again start
	 *    reconnecting.
	 * 2. State was observed as DEAD - we have someone in parallel
	 *    removing the path.
	 */
	do {
		ibtrs_clt_close_conns(sess, true);
	} while (!(changed = ibtrs_clt_change_state_get_old(sess,
							    IBTRS_CLT_DEAD,
							    &old_state)) &&
		   old_state != IBTRS_CLT_DEAD);

	/*
	 * If state was successfully changed to DEAD, commit suicide.
	 */
	if (likely(changed)) {
		ibtrs_clt_destroy_sess_files(sess, sysfs_self);
		ibtrs_clt_remove_path_from_arr(sess);
		free_sess(sess);
	}

	return 0;
}

void ibtrs_clt_set_max_reconnect_attempts(struct ibtrs_clt *clt, int value)
{
	clt->max_reconnect_attempts = (unsigned int)value;
}

int ibtrs_clt_get_max_reconnect_attempts(const struct ibtrs_clt *clt)
{
	return (int)clt->max_reconnect_attempts;
}

static int ibtrs_clt_rdma_write_desc(struct ibtrs_clt_con *con,
				     struct ibtrs_clt_io_req *req, u64 buf,
				     size_t u_msg_len, u32 imm,
				     struct ibtrs_msg_rdma_write *msg)
{
	struct ibtrs_clt_sess *sess = to_clt_sess(con->c.sess);
	struct ibtrs_sg_desc *desc;
	int ret;

	desc = kmalloc_array(sess->max_pages_per_mr, sizeof(*desc), GFP_ATOMIC);
	if (unlikely(!desc))
		return -ENOMEM;

	ret = ibtrs_fast_reg_map_data(con, desc, req);
	if (unlikely(ret < 0)) {
		ibtrs_err_rl(sess,
			     "Write request failed, fast reg. data mapping"
			     " failed, err: %d\n", ret);
		kfree(desc);
		return ret;
	}
	ret = ibtrs_post_send_rdma_desc(con, req, desc, ret, buf,
					u_msg_len + sizeof(*msg), imm);
	if (unlikely(ret)) {
		ibtrs_err(sess, "Write request failed, posting work"
			  " request failed, err: %d\n", ret);
		ibtrs_unmap_fast_reg_data(con, req);
	}
	kfree(desc);
	return ret;
}

static int ibtrs_clt_write_req(struct ibtrs_clt_io_req *req)
{
	struct ibtrs_clt_con *con = req->con;
	struct ibtrs_clt_sess *sess = to_clt_sess(con->c.sess);
	struct ibtrs_msg_rdma_write *msg;

	int ret, count = 0;
	u32 imm, buf_id;
	u64 buf;

	const size_t tsize = sizeof(*msg) + req->data_len + req->usr_len;

	if (unlikely(tsize > sess->chunk_size)) {
		ibtrs_wrn(sess, "Write request failed, size too big %zu > %d\n",
			  tsize, sess->chunk_size);
		return -EMSGSIZE;
	}
	if (req->sg_cnt) {
		count = ib_dma_map_sg(sess->s.ib_dev->dev, req->sglist,
				      req->sg_cnt, req->dir);
		if (unlikely(!count)) {
			ibtrs_wrn(sess, "Write request failed, map failed\n");
			return -EINVAL;
		}
	}
	/* put ibtrs msg after sg and user message */
	msg = req->iu->buf + req->usr_len;
	msg->type = cpu_to_le16(IBTRS_MSG_WRITE);
	msg->usr_len = cpu_to_le16(req->usr_len);

	/* ibtrs message on server side will be after user data and message */
	imm = req->tag->mem_off + req->data_len + req->usr_len;
	imm = ibtrs_to_io_req_imm(imm);
	buf_id = req->tag->mem_id;
	req->sg_size = tsize;
	buf = sess->srv_rdma_addr[buf_id];

	/*
	 * Update stats now, after request is successfully sent it is not
	 * safe anymore to touch it.
	 */
	ibtrs_clt_update_all_stats(req, WRITE);

	if (count > fmr_sg_cnt)
		ret = ibtrs_clt_rdma_write_desc(req->con, req, buf,
						req->usr_len, imm, msg);
	else
		ret = ibtrs_post_send_rdma_more(req->con, req, buf,
						req->usr_len + sizeof(*msg),
						imm);
	if (unlikely(ret)) {
		ibtrs_err(sess, "Write request failed: %d\n", ret);
		ibtrs_clt_decrease_inflight(&sess->stats);
		if (req->sg_cnt)
			ib_dma_unmap_sg(sess->s.ib_dev->dev, req->sglist,
					req->sg_cnt, req->dir);
	}

	return ret;
}

int ibtrs_clt_write(struct ibtrs_clt *clt, ibtrs_conf_fn *conf,
		    struct ibtrs_tag *tag, void *priv, const struct kvec *vec,
		    size_t nr, size_t data_len, struct scatterlist *sg,
		    unsigned int sg_cnt)
{
	struct ibtrs_clt_io_req *req;
	struct ibtrs_clt_sess *sess;

	int err = -ECONNABORTED;
	struct path_it it;
	size_t usr_len;

	usr_len = kvec_length(vec, nr);
	do_each_path(sess, clt, &it) {
		if (unlikely(sess->state != IBTRS_CLT_CONNECTED))
			continue;

		if (unlikely(usr_len > IO_MSG_SIZE)) {
			ibtrs_wrn_rl(sess, "Write request failed, user message"
				     " size is %zu B big, max size is %d B\n",
				     usr_len, IO_MSG_SIZE);
			err = -EMSGSIZE;
			break;
		}
		req = ibtrs_clt_get_req(sess, conf, tag, priv, vec, usr_len,
					sg, sg_cnt, data_len, DMA_TO_DEVICE);
		err = ibtrs_clt_write_req(req);
		if (unlikely(err)) {
			req->in_use = false;
			continue;
		}
		/* Success path */
		break;
	} while_each_path(&it);

	return err;
}

static int ibtrs_clt_read_req(struct ibtrs_clt_io_req *req)
{
	struct ibtrs_clt_con *con = req->con;
	struct ibtrs_clt_sess *sess = to_clt_sess(con->c.sess);
	struct ibtrs_msg_rdma_read *msg;
	struct ibtrs_ib_dev *ibdev;
	struct scatterlist *sg;

	int i, ret, count = 0;
	u32 imm, buf_id;

	const size_t tsize = sizeof(*msg) + req->data_len + req->usr_len;

	ibdev = sess->s.ib_dev;

	if (unlikely(tsize > sess->chunk_size)) {
		ibtrs_wrn(sess, "Read request failed, message size is"
			  " %zu, bigger than CHUNK_SIZE %d\n", tsize,
			  sess->chunk_size);
		return -EMSGSIZE;
	}

	if (req->sg_cnt) {
		count = ib_dma_map_sg(ibdev->dev, req->sglist, req->sg_cnt,
				      req->dir);
		if (unlikely(!count)) {
			ibtrs_wrn(sess, "Read request failed, "
				  "dma map failed\n");
			return -EINVAL;
		}
	}
	/* put our message into req->buf after user message*/
	msg = req->iu->buf + req->usr_len;
	msg->type = cpu_to_le16(IBTRS_MSG_READ);
	msg->sg_cnt = cpu_to_le32(count);
	msg->usr_len = cpu_to_le16(req->usr_len);

	if (count > fmr_sg_cnt) {
		ret = ibtrs_fast_reg_map_data(req->con, msg->desc, req);
		if (ret < 0) {
			ibtrs_err_rl(sess,
				     "Read request failed, failed to map "
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
				cpu_to_le32(ibdev->rkey);
			msg->desc[i].len =
				cpu_to_le32(ib_sg_dma_len(ibdev->dev, sg));
		}
		req->nmdesc = 0;
	}
	/*
	 * ibtrs message will be after the space reserved for disk data and
	 * user message
	 */
	imm = req->tag->mem_off + req->data_len + req->usr_len;
	imm = ibtrs_to_io_req_imm(imm);
	buf_id = req->tag->mem_id;

	req->sg_size  = sizeof(*msg);
	req->sg_size += le32_to_cpu(msg->sg_cnt) * sizeof(struct ibtrs_sg_desc);
	req->sg_size += req->usr_len;

	/*
	 * Update stats now, after request is successfully sent it is not
	 * safe anymore to touch it.
	 */
	ibtrs_clt_update_all_stats(req, READ);

	ret = ibtrs_post_send_rdma(req->con, req, sess->srv_rdma_addr[buf_id],
				   req->data_len, imm);
	if (unlikely(ret)) {
		ibtrs_err(sess, "Read request failed: %d\n", ret);
		ibtrs_clt_decrease_inflight(&sess->stats);
		if (unlikely(count > fmr_sg_cnt))
			ibtrs_unmap_fast_reg_data(req->con, req);
		if (req->sg_cnt)
			ib_dma_unmap_sg(ibdev->dev, req->sglist,
					req->sg_cnt, req->dir);
	}

	return ret;
}

int ibtrs_clt_read(struct ibtrs_clt *clt, ibtrs_conf_fn *conf,
		   struct ibtrs_tag *tag, void *priv, const struct kvec *vec,
		   size_t nr, size_t data_len, struct scatterlist *sg,
		   unsigned int sg_cnt)
{
	struct ibtrs_clt_io_req *req;
	struct ibtrs_clt_sess *sess;

	int err = -ECONNABORTED;
	struct path_it it;
	size_t usr_len;

	usr_len = kvec_length(vec, nr);
	do_each_path(sess, clt, &it) {
		if (unlikely(sess->state != IBTRS_CLT_CONNECTED))
			continue;

		if (unlikely(usr_len > IO_MSG_SIZE ||
			     sizeof(struct ibtrs_msg_rdma_read) +
			     sg_cnt * sizeof(struct ibtrs_sg_desc) >
			     sess->max_req_size)) {
			ibtrs_wrn_rl(sess, "Read request failed, user message"
				     " size is %zu B big, max size is %d B\n",
				     usr_len, IO_MSG_SIZE);
			err = -EMSGSIZE;
			break;
		}
		req = ibtrs_clt_get_req(sess, conf, tag, priv, vec, usr_len,
					sg, sg_cnt, data_len, DMA_FROM_DEVICE);
		err = ibtrs_clt_read_req(req);
		if (unlikely(err)) {
			req->in_use = false;
			continue;
		}
		/* Success path */
		break;
	} while_each_path(&it);

	return err;
}

int ibtrs_clt_request(int dir, ibtrs_conf_fn *conf, struct ibtrs_clt *clt,
		      struct ibtrs_tag *tag, void *priv, const struct kvec *vec,
		      size_t nr, size_t len, struct scatterlist *sg,
		      unsigned int sg_len)
{
	if (dir == READ)
		return ibtrs_clt_read(clt, conf, tag, priv, vec, nr, len, sg,
				      sg_len);
	else
		return ibtrs_clt_write(clt, conf, tag, priv, vec, nr, len, sg,
				       sg_len);
}
EXPORT_SYMBOL(ibtrs_clt_request);

int ibtrs_clt_query(struct ibtrs_clt *clt, struct ibtrs_attrs *attr)
{
	if (unlikely(!ibtrs_clt_is_connected(clt)))
		return -ECOMM;

	attr->queue_depth      = clt->queue_depth;
	attr->max_io_size      = clt->max_io_size;
	strlcpy(attr->sessname, clt->sessname, sizeof(attr->sessname));

	return 0;
}
EXPORT_SYMBOL(ibtrs_clt_query);

int ibtrs_clt_create_path_from_sysfs(struct ibtrs_clt *clt,
				     struct ibtrs_addr *addr)
{
	struct ibtrs_clt_sess *sess;
	int err;

	if (ibtrs_clt_path_exists(clt, addr))
		return -EEXIST;

	sess = alloc_sess(clt, addr, nr_cons_per_session, clt->max_segments);
	if (unlikely(IS_ERR(sess)))
		return PTR_ERR(sess);

	/*
	 * It is totally safe to add path in CONNECTING state: coming
	 * IO will never grab it.  Also it is very important to add
	 * path before init, since init fires LINK_CONNECTED event.
	 */
	err = ibtrs_clt_add_path_to_arr(sess, addr);
	if (unlikely(err))
		goto free_sess;

	err = init_sess(sess);
	if (unlikely(err))
		goto close_sess;

	err = ibtrs_clt_create_sess_files(sess);
	if (unlikely(err))
		goto close_sess;

	return 0;

close_sess:
	ibtrs_clt_remove_path_from_arr(sess);
	ibtrs_clt_close_conns(sess, true);
free_sess:
	free_sess(sess);

	return err;
}

static int check_module_params(void)
{
	if (fmr_sg_cnt > MAX_SEGMENTS || fmr_sg_cnt < 0) {
		pr_err("invalid fmr_sg_cnt values\n");
		return -EINVAL;
	}
	if (nr_cons_per_session == 0)
		nr_cons_per_session = min_t(unsigned int, nr_cpu_ids, U16_MAX);

	return 0;
}

static int __init ibtrs_client_init(void)
{
	int err;

	pr_info("Loading module %s, version: %s "
		"(use_fr: %d, retry_count: %d, "
		"fmr_sg_cnt: %d)\n",
		KBUILD_MODNAME, IBTRS_VER_STRING,
		use_fr,	retry_count, fmr_sg_cnt);
	err = check_module_params();
	if (err) {
		pr_err("Failed to load module, invalid module parameters,"
		       " err: %d\n", err);
		return err;
	}
	ibtrs_wq = alloc_workqueue("ibtrs_client_wq", WQ_MEM_RECLAIM, 0);
	if (!ibtrs_wq) {
		pr_err("Failed to load module, alloc ibtrs_client_wq failed\n");
		return -ENOMEM;
	}
	err = ibtrs_clt_create_sysfs_module_files();
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
	ibtrs_clt_destroy_sysfs_module_files();
	destroy_workqueue(ibtrs_wq);
}

module_init(ibtrs_client_init);
module_exit(ibtrs_client_exit);
