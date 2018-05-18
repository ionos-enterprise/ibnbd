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
 *          Swapnil Ingle <swapnil.ingle@profitbricks.com>
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
#include <linux/rculist.h>

#include "ibtrs-clt.h"
#include "ibtrs-log.h"

#define MAX_SEGMENTS 31
#define IBTRS_CONNECT_TIMEOUT_MS 5000

MODULE_AUTHOR("ibnbd@profitbricks.com");
MODULE_DESCRIPTION("IBTRS Client");
MODULE_VERSION(IBTRS_VER_STRING);
MODULE_LICENSE("GPL");

static ushort nr_cons_per_session;
module_param(nr_cons_per_session, ushort, 0444);
MODULE_PARM_DESC(nr_cons_per_session, "Number of connections per session."
		 " (default: nr_cpu_ids)");

static int retry_cnt = 7;
module_param_named(retry_cnt, retry_cnt, int, 0644);
MODULE_PARM_DESC(retry_cnt, "Number of times to send the message if the"
		 " remote side didn't respond with Ack or Nack (default: 7,"
		 " min: " __stringify(MIN_RTR_CNT) ", max: "
		 __stringify(MAX_RTR_CNT) ")");

static int __read_mostly noreg_cnt = 0;
module_param_named(noreg_cnt, noreg_cnt, int, 0444);
MODULE_PARM_DESC(noreg_cnt, "Max number of SG entries when MR registration "
		 "does not happen (default: 0)");

static const struct ibtrs_ib_dev_pool_ops dev_pool_ops;
static struct ibtrs_ib_dev_pool dev_pool = {
	.ops = &dev_pool_ops
};
static struct workqueue_struct *ibtrs_wq;
static struct class *ibtrs_dev_class;

static void ibtrs_rdma_error_recovery(struct ibtrs_clt_con *con);
static int ibtrs_clt_rdma_cm_handler(struct rdma_cm_id *cm_id,
				     struct rdma_cm_event *ev);
static void ibtrs_clt_rdma_done(struct ib_cq *cq, struct ib_wc *wc);
static void complete_rdma_req(struct ibtrs_clt_io_req *req, int errno,
			      bool notify, bool can_wait);
static int ibtrs_clt_write_req(struct ibtrs_clt_io_req *req);
static int ibtrs_clt_read_req(struct ibtrs_clt_io_req *req);

bool ibtrs_clt_sess_is_connected(const struct ibtrs_clt_sess *sess)
{
	return sess->state == IBTRS_CLT_CONNECTED;
}

static inline bool ibtrs_clt_is_connected(const struct ibtrs_clt *clt)
{
	struct ibtrs_clt_sess *sess;
	bool connected = false;

	rcu_read_lock();
	list_for_each_entry_rcu(sess, &clt->paths_list, s.entry)
		connected |= ibtrs_clt_sess_is_connected(sess);
	rcu_read_unlock();

	return connected;
}

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

struct ibtrs_tag *ibtrs_tag_from_pdu(void *pdu)
{
	return pdu - sizeof(struct ibtrs_tag);
}
EXPORT_SYMBOL(ibtrs_tag_from_pdu);

void *ibtrs_tag_to_pdu(struct ibtrs_tag *tag)
{
	return tag + 1;
}
EXPORT_SYMBOL(ibtrs_tag_to_pdu);

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

static void ibtrs_clt_inv_rkey_done(struct ib_cq *cq, struct ib_wc *wc)
{
	struct ibtrs_clt_io_req *req =
		container_of(wc->wr_cqe, typeof(*req), inv_cqe);
	struct ibtrs_clt_con *con = cq->cq_context;
	struct ibtrs_clt_sess *sess = to_clt_sess(con->c.sess);

	if (unlikely(wc->status != IB_WC_SUCCESS)) {
		ibtrs_err(sess, "Failed IB_WR_LOCAL_INV: %s\n",
			  ib_wc_status_msg(wc->status));
		ibtrs_rdma_error_recovery(con);
	}
	req->need_inv = false;
	if (likely(req->need_inv_comp))
		complete(&req->inv_comp);
	else
		/* Complete request from INV callback */
		complete_rdma_req(req, req->inv_errno, true, false);
}

static int ibtrs_inv_rkey(struct ibtrs_clt_io_req *req)
{
	struct ibtrs_clt_con *con = req->con;
	struct ib_send_wr *bad_wr;
	struct ib_send_wr wr = {
		.opcode		    = IB_WR_LOCAL_INV,
		.wr_cqe		    = &req->inv_cqe,
		.next		    = NULL,
		.num_sge	    = 0,
		.send_flags	    = IB_SEND_SIGNALED,
		.ex.invalidate_rkey = req->mr->rkey,
	};
	req->inv_cqe.done = ibtrs_clt_inv_rkey_done;

	return ib_post_send(con->c.qp, &wr, &bad_wr);
}

static int ibtrs_post_send_rdma(struct ibtrs_clt_con *con,
				struct ibtrs_clt_io_req *req,
				struct ibtrs_rbuf *rbuf, u32 off,
				u32 imm, struct ib_send_wr *wr)
{
	struct ibtrs_clt_sess *sess = to_clt_sess(con->c.sess);
	enum ib_send_flags flags;
	struct ib_sge sge;

	if (unlikely(!req->sg_size)) {
		ibtrs_wrn(sess, "Doing RDMA Write failed, no data supplied\n");
		return -EINVAL;
	}

	/* user data and user message in the first list element */
	sge.addr   = req->iu->dma_addr;
	sge.length = req->sg_size;
	sge.lkey   = sess->s.dev->ib_pd->local_dma_lkey;

	/*
	 * From time to time we have to post signalled sends,
	 * or send queue will fill up and only QP reset can help.
	 */
	flags = atomic_inc_return(&con->io_cnt) % sess->queue_depth ?
			0 : IB_SEND_SIGNALED;

	ib_dma_sync_single_for_device(sess->s.dev->ib_dev, req->iu->dma_addr,
				      req->sg_size, DMA_TO_DEVICE);

	return ibtrs_iu_post_rdma_write_imm(&con->c, req->iu, &sge, 1,
					    rbuf->rkey, rbuf->addr + off,
					    imm, flags, wr);
}

static void complete_rdma_req(struct ibtrs_clt_io_req *req, int errno,
			      bool notify, bool can_wait)
{
	struct ibtrs_clt_con *con = req->con;
	struct ibtrs_clt_sess *sess;
	struct ibtrs_clt *clt;
	int err;

	if (WARN_ON(!req->in_use))
		return;
	if (WARN_ON(!req->con))
		return;
	sess = to_clt_sess(con->c.sess);
	clt = sess->clt;

	if (req->sg_cnt) {
		if (unlikely(req->dir == DMA_FROM_DEVICE && req->need_inv)) {
			/*
			 * We are here to invalidate RDMA read requests
			 * ourselves.  In normal scenario server should
			 * send INV for all requested RDMA reads, but
			 * we are here, thus two things could happen:
			 *
			 *    1.  this is failover, when errno != 0
			 *        and can_wait == 1,
			 *
			 *    2.  something totally bad happened and
			 *        server forgot to send INV, so we
			 *        should do that ourselves.
			 */

			if (likely(can_wait))
				req->need_inv_comp = true;
			else {
				/* This should be IO path, so always notify */
				WARN_ON(!notify);
				/* Save errno for INV callback */
				req->inv_errno = errno;
			}

			err = ibtrs_inv_rkey(req);
			if (unlikely(err))
				ibtrs_err(sess, "Send INV WR key=%#x: %d\n",
					  req->mr->rkey, err);
			else if (likely(can_wait))
				wait_for_completion(&req->inv_comp);
			else {
				/*
				 * Something went wrong, so request will be
				 * completed from INV callback.
				 */
				WARN_ON_ONCE(1);

				return;
			}
		}
		ib_dma_unmap_sg(sess->s.dev->ib_dev, req->sglist,
				req->sg_cnt, req->dir);
	}
	if (sess->stats.enable_rdma_lat)
		ibtrs_clt_update_rdma_lat(&sess->stats,
				req->dir == DMA_FROM_DEVICE,
				jiffies_to_msecs(jiffies - req->start_jiffies));
	ibtrs_clt_decrease_inflight(&sess->stats);

	req->in_use = false;
	req->con = NULL;

	if (notify)
		req->conf(req->priv, errno);
}

static void process_io_rsp(struct ibtrs_clt_sess *sess, u32 msg_id,
			   s16 errno, bool w_inval)
{
	struct ibtrs_clt_io_req *req;

	if (WARN_ON(msg_id >= sess->queue_depth))
		return;

	req = &sess->reqs[msg_id];
	/* Drop need_inv if server responsed with invalidation */
	req->need_inv &= !w_inval;
	complete_rdma_req(req, errno, true, false);
}

static struct ib_cqe io_comp_cqe = {
	.done = ibtrs_clt_rdma_done
};

static void ibtrs_clt_rdma_done(struct ib_cq *cq, struct ib_wc *wc)
{
	struct ibtrs_clt_con *con = cq->cq_context;
	struct ibtrs_clt_sess *sess = to_clt_sess(con->c.sess);
	u32 imm_type, imm_payload;
	bool w_inval = false;
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
	case IB_WC_RECV:
		/*
		 * Key invalidations from server side
		 */
		WARN_ON(!(wc->wc_flags & IB_WC_WITH_INVALIDATE));
		WARN_ON(wc->wr_cqe != &io_comp_cqe);
		break;

	case IB_WC_RECV_RDMA_WITH_IMM:
		/*
		 * post_recv() RDMA write completions of IO reqs (read/write)
		 * and hb
		 */
		if (WARN_ON(wc->wr_cqe != &io_comp_cqe))
			return;

		ibtrs_from_imm(be32_to_cpu(wc->ex.imm_data),
			       &imm_type, &imm_payload);
		if (likely(imm_type == IBTRS_IO_RSP_IMM ||
			   imm_type == IBTRS_IO_RSP_W_INV_IMM)) {
			u32 msg_id;

			w_inval = (imm_type == IBTRS_IO_RSP_W_INV_IMM);
			ibtrs_from_io_rsp_imm(imm_payload, &msg_id, &err);
			process_io_rsp(sess, msg_id, err, w_inval);
		} else if (imm_type == IBTRS_HB_MSG_IMM) {
			WARN_ON(con->c.cid);
			ibtrs_send_hb_ack(&sess->s);
		} else if (imm_type == IBTRS_HB_ACK_IMM) {
			WARN_ON(con->c.cid);
			sess->s.hb_missed_cnt = 0;
		} else {
			ibtrs_wrn(sess, "Unknown IMM type %u\n", imm_type);
		}
		if (w_inval)
			/*
			 * Post x2 empty WRs: first is for this RDMA with IMM,
			 * second is for RECV with INV, which happened earlier.
			 */
			err = ibtrs_post_recv_empty_x2(&con->c, &io_comp_cqe);
		else
			err = ibtrs_post_recv_empty(&con->c, &io_comp_cqe);
		if (unlikely(err)) {
			ibtrs_err(sess, "ibtrs_post_recv_empty(): %d\n", err);
			ibtrs_rdma_error_recovery(con);
			break;
		}
		break;
	default:
		ibtrs_wrn(sess, "Unexpected WC type: %d\n", wc->opcode);
		return;
	}
}

static int post_recv_io(struct ibtrs_clt_con *con, size_t q_size)
{
	int err, i;

	for (i = 0; i < q_size; i++) {
		err = ibtrs_post_recv_empty(&con->c, &io_comp_cqe);
		if (unlikely(err))
			return err;
	}

	return 0;
}

static int post_recv_sess(struct ibtrs_clt_sess *sess)
{
	size_t q_size;
	int err, cid;

	for (cid = 0; cid < sess->s.con_num; cid++) {
		if (cid == 0)
			q_size = SERVICE_CON_QUEUE_DEPTH;
		else
			q_size = sess->queue_depth;

		/*
		 * x2 for RDMA read responses + FR key invalidations,
		 * RDMA writes do not require any FR registrations.
		 */
		q_size *= 2;

		err = post_recv_io(to_clt_con(sess->s.con[cid]), q_size);
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
	rcu_read_lock();						\
	for ((it)->i = 0; ((path) = ((it)->next_path)(it)) &&		\
			  (it)->i < (it)->clt->paths_num;		\
	     (it)->i++)

#define while_each_path(it)						\
	path_it_deinit(it);						\
	rcu_read_unlock();						\
	}

/**
 * get_next_path_rr() - Returns path in round-robin fashion.
 *
 * Related to @MP_POLICY_RR
 *
 * Locks:
 *    rcu_read_lock() must be hold.
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
		path = list_next_or_null_rr_rcu(&clt->paths_list,
						&path->s.entry,
						typeof(*path),
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
 *    rcu_read_lock() must be hold.
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
	struct iov_iter iter;
	size_t len;

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
	req->need_inv = false;
	req->need_inv_comp = false;
	req->inv_errno = 0;

	iov_iter_kvec(&iter, ITER_KVEC, vec, 1, usr_len);
	len = _copy_from_iter(req->iu->buf, usr_len, &iter);
	WARN_ON(len != usr_len);

	reinit_completion(&req->inv_comp);
	if (sess->stats.enable_rdma_lat)
		req->start_jiffies = jiffies;
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

static void fail_all_outstanding_reqs(struct ibtrs_clt_sess *sess)
{
	struct ibtrs_clt *clt = sess->clt;
	struct ibtrs_clt_io_req *req;
	int i, err;

	if (!sess->reqs)
		return;
	for (i = 0; i < sess->queue_depth; ++i) {
		req = &sess->reqs[i];
		if (!req->in_use)
			continue;

		/*
		 * Safely (without notification) complete failed request.
		 * After completion this request is still usebale and can
		 * be failovered to another path.
		 */
		complete_rdma_req(req, -ECONNABORTED, false, true);

		err = ibtrs_clt_failover_req(clt, req);
		if (unlikely(err))
			/* Failover failed, notify anyway */
			req->conf(req->priv, err);
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
		if (req->mr)
			ib_dereg_mr(req->mr);
		kfree(req->sge);
		ibtrs_iu_free(req->iu, DMA_TO_DEVICE,
			      sess->s.dev->ib_dev);
	}
	kfree(sess->reqs);
	sess->reqs = NULL;
}

static int alloc_sess_reqs(struct ibtrs_clt_sess *sess)
{
	struct ibtrs_clt_io_req *req;
	struct ibtrs_clt *clt = sess->clt;
	int i, err = -ENOMEM;

	sess->reqs = kcalloc(sess->queue_depth, sizeof(*sess->reqs),
			     GFP_KERNEL);
	if (unlikely(!sess->reqs))
		return -ENOMEM;

	for (i = 0; i < sess->queue_depth; ++i) {
		req = &sess->reqs[i];
		req->iu = ibtrs_iu_alloc(i, sess->max_hdr_size, GFP_KERNEL,
					 sess->s.dev->ib_dev, DMA_TO_DEVICE,
					 ibtrs_clt_rdma_done);
		if (unlikely(!req->iu))
			goto out;

		req->sge = kmalloc_array(clt->max_segments + 1,
					 sizeof(*req->sge), GFP_KERNEL);
		if (unlikely(!req->sge))
			goto out;

		req->mr = ib_alloc_mr(sess->s.dev->ib_pd, IB_MR_TYPE_MEM_REG,
				      clt->max_segments + 1);
		if (unlikely(IS_ERR(req->mr))) {
			err = PTR_ERR(req->mr);
			req->mr = NULL;
			goto out;
		}

		init_completion(&req->inv_comp);
	}

	return 0;

out:
	free_sess_reqs(sess);

	return err;
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
	struct ib_device *ib_dev;
	u64 max_pages_per_mr;
	int mr_page_shift;

	ib_dev = sess->s.dev->ib_dev;

	/*
	 * Use the smallest page size supported by the HCA, down to a
	 * minimum of 4096 bytes. We're unlikely to build large sglists
	 * out of smaller entries.
	 */
	mr_page_shift      = max(12, ffs(ib_dev->attrs.page_size_cap) - 1);
	max_pages_per_mr   = ib_dev->attrs.max_mr_size;
	do_div(max_pages_per_mr, (1ull << mr_page_shift));
	sess->max_pages_per_mr =
		min3(sess->max_pages_per_mr, (u32)max_pages_per_mr,
		     ib_dev->attrs.max_fast_reg_page_list_len);
	sess->max_sge = ib_dev->attrs.max_sge;
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
	kfree(sess->rbufs);
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
		/*
		 * One completion for each receive and two for each send
		 * (send request + registration)
		 * + 2 for drain and heartbeat
		 * in case qp gets into error state
		 */
		cq_size = wr_queue_size = SERVICE_CON_QUEUE_DEPTH * 3 + 2;
		/* We must be the first here */
		if (WARN_ON(sess->s.dev))
			return -EINVAL;

		/*
		 * The whole session uses device from user connection.
		 * Be careful not to close user connection before ib dev
		 * is gracefully put.
		 */
		sess->s.dev = ibtrs_ib_dev_find_or_add(
			con->c.cm_id->device, &dev_pool);
		if (unlikely(!sess->s.dev)) {
			ibtrs_wrn(sess, "ibtrs_ib_dev_find_get_or_add(): no memory\n");
			return -ENOMEM;
		}
		sess->s.dev_ref = 1;
		query_fast_reg_mode(sess);
	} else {
		/*
		 * Here we assume that session members are correctly set.
		 * This is always true if user connection (cid == 0) is
		 * established first.
		 */
		if (WARN_ON(!sess->s.dev))
			return -EINVAL;
		if (WARN_ON(!sess->queue_depth))
			return -EINVAL;

		/* Shared between connections */
		sess->s.dev_ref++;
		cq_size = wr_queue_size =
			min_t(int, sess->s.dev->ib_dev->attrs.max_qp_wr,
			      /* QD * (REQ + RSP + FR REGS or INVS) + drain */
			      sess->queue_depth * 3 + 1);
	}
	cq_vector = con->cpu % sess->s.dev->ib_dev->num_comp_vectors;
	err = ibtrs_cq_qp_create(&sess->s, &con->c, sess->max_sge,
				 cq_vector, cq_size, wr_queue_size,
				 IB_POLL_SOFTIRQ);
	/*
	 * In case of error we do not bother to clean previous allocations,
	 * since destroy_con_cq_qp() must be called.
	 */

	if (unlikely(err))
		return err;

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
	if (sess->s.dev_ref && !--sess->s.dev_ref) {
		ibtrs_ib_dev_put(sess->s.dev);
		sess->s.dev = NULL;
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

static void ibtrs_clt_stop_and_destroy_conns(struct ibtrs_clt_sess *sess)
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
		if (!sess->s.con[cid])
			break;
		con = to_clt_con(sess->s.con[cid]);
		stop_cm(con);
	}
	fail_all_outstanding_reqs(sess);
	free_sess_reqs(sess);
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
		if (!sess->s.con[cid])
			break;
		con = to_clt_con(sess->s.con[cid]);
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

	next = list_next_or_null_rr_rcu(&clt->paths_list, &sess->s.entry,
					typeof(*next), s.entry);

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
				  (struct sockaddr *)addr->dst))
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

		clt->paths_num++;

		/*
		 * Firstly increase paths_num, wait for GP and then
		 * add path to the list.  Why?  Since we add path with
		 * !CONNECTED state explanation is similar to what has
		 * been written in ibtrs_clt_remove_path_from_arr().
		 */
		synchronize_rcu();

		list_add_tail_rcu(&sess->s.entry, &clt->paths_list);
	} else
		err = -EEXIST;
	mutex_unlock(&clt->paths_mutex);

	return err;
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
	err = alloc_sess_reqs(sess);
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
	param.retry_count = clamp(retry_cnt, MIN_RTR_CNT, MAX_RTR_CNT);
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
	msg.version = cpu_to_le16(IBTRS_PROTO_VER);
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
	struct ibtrs_clt *clt = sess->clt;
	const struct ibtrs_msg_conn_rsp *msg;
	u16 version, queue_depth;
	int errno;
	u8 len;

	msg = ev->param.conn.private_data;
	len = ev->param.conn.private_data_len;
	if (unlikely(len < sizeof(*msg))) {
		ibtrs_err(sess, "Invalid IBTRS connection response\n");
		return -ECONNRESET;
	}
	if (unlikely(le16_to_cpu(msg->magic) != IBTRS_MAGIC)) {
		ibtrs_err(sess, "Invalid IBTRS magic\n");
		return -ECONNRESET;
	}
	version = le16_to_cpu(msg->version);
	if (unlikely(version >> 8 != IBTRS_PROTO_VER_MAJOR)) {
		ibtrs_err(sess, "Unsupported major IBTRS version: %d, expected %d\n",
			  version >> 8, IBTRS_PROTO_VER_MAJOR);
		return -ECONNRESET;
	}
	errno = le16_to_cpu(msg->errno);
	if (unlikely(errno)) {
		ibtrs_err(sess, "Invalid IBTRS message: errno %d\n",
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
		if (!sess->rbufs || sess->queue_depth < queue_depth) {
			kfree(sess->rbufs);
			sess->rbufs = kcalloc(queue_depth, sizeof(*sess->rbufs),
					      GFP_KERNEL);
			if (unlikely(!sess->rbufs)) {
				ibtrs_err(sess, "Failed to allocate "
					  "queue_depth=%d\n", queue_depth);
				return -ENOMEM;
			}
		}
		sess->queue_depth = queue_depth;
		sess->max_hdr_size = le32_to_cpu(msg->max_hdr_size);
		sess->max_io_size = le32_to_cpu(msg->max_io_size);
		sess->chunk_size = sess->max_io_size + sess->max_hdr_size;

		/*
		 * Global queue depth and IO size is always a minimum.
		 * If while a reconnection server sends us a value a bit
		 * higher - client does not care and uses cached minimum.
		 *
		 * Since we can have several sessions (paths) restablishing
		 * connections in parallel, use lock.
		 */
		mutex_lock(&clt->paths_mutex);
		clt->queue_depth = min_not_zero(sess->queue_depth,
						clt->queue_depth);
		clt->max_io_size = min_not_zero(sess->max_io_size,
						clt->max_io_size);
		mutex_unlock(&clt->paths_mutex);

		/*
		 * Cache the hca_port and hca_name for sysfs
		 */
		sess->hca_port = con->c.cm_id->port_num;
		scnprintf(sess->hca_name, sizeof(sess->hca_name),
			  sess->s.dev->ib_dev->name);
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
	ibtrs_iu_free(iu, DMA_TO_DEVICE, sess->s.dev->ib_dev);

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
	unsigned int sg_cnt, total_len;
	int i, sgi;

	sg_cnt = le16_to_cpu(msg->sg_cnt);
	if (unlikely(!sg_cnt))
		return -EINVAL;
	/*
	 * Check if IB immediate data size is enough to hold the mem_id and
	 * the offset inside the memory chunk.
	 */
	if (unlikely((ilog2(sg_cnt-1)+1) + (ilog2(sess->chunk_size-1)+1) >
		     MAX_IMM_PAYL_BITS)) {
		ibtrs_err(sess, "RDMA immediate size (%db) not enough to "
			  "encode %d buffers of size %dB\n",  MAX_IMM_PAYL_BITS,
			  sg_cnt, sess->chunk_size);
		return -EINVAL;
	}
	if (unlikely(!sg_cnt || (sess->queue_depth % sg_cnt))) {
		ibtrs_err(sess, "Incorrect sg_cnt %d, is not multiple\n",
			  sg_cnt);
		return -EINVAL;
	}
	total_len = 0;
	for (sgi = 0, i = 0; sgi < sg_cnt && i < sess->queue_depth; sgi++) {
		const struct ibtrs_sg_desc *desc = &msg->desc[sgi];
		u32 len, rkey;
		u64 addr;

		addr = le64_to_cpu(desc->addr);
		rkey = le32_to_cpu(desc->key);
		len  = le32_to_cpu(desc->len);

		total_len += len;

		if (unlikely(!len || (len % sess->chunk_size))) {
			ibtrs_err(sess, "Incorrect [%d].len %d\n", sgi, len);
			return -EINVAL;
		}
		for ( ; len && i < sess->queue_depth; i++) {
			sess->rbufs[i].addr = addr;
			sess->rbufs[i].rkey = rkey;

			len  -= sess->chunk_size;
			addr += sess->chunk_size;
		}
	}
	/* Sanity check */
	if (unlikely(sgi != sg_cnt || i != sess->queue_depth)) {
		ibtrs_err(sess, "Incorrect sg vector, not fully mapped\n");
		return -EINVAL;
	}
	if (unlikely(total_len != sess->chunk_size * sess->queue_depth)) {
		ibtrs_err(sess, "Incorrect total_len %d\n", total_len);
		return -EINVAL;
	}

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
	ib_dma_sync_single_for_cpu(sess->s.dev->ib_dev, iu->dma_addr,
				   iu->size, DMA_FROM_DEVICE);
	msg = iu->buf;
	if (unlikely(le16_to_cpu(msg->type) != IBTRS_MSG_INFO_RSP)) {
		ibtrs_err(sess, "Sess info response is malformed: type %d\n",
			  le32_to_cpu(msg->type));
		goto out;
	}
	rx_sz  = sizeof(*msg);
	rx_sz += sizeof(msg->desc[0]) * le16_to_cpu(msg->sg_cnt);
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
	ibtrs_iu_free(iu, DMA_FROM_DEVICE, sess->s.dev->ib_dev);
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
			       sess->s.dev->ib_dev, DMA_TO_DEVICE,
			       ibtrs_clt_info_req_done);
	rx_iu = ibtrs_iu_alloc(0, rx_sz, GFP_KERNEL, sess->s.dev->ib_dev,
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

	ib_dma_sync_single_for_device(sess->s.dev->ib_dev, tx_iu->dma_addr,
				      tx_iu->size, DMA_TO_DEVICE);

	/* Send info request */
	err = ibtrs_iu_post_send(&usr_con->c, tx_iu, sizeof(*msg), NULL);
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
		ibtrs_iu_free(tx_iu, DMA_TO_DEVICE, sess->s.dev->ib_dev);
	if (rx_iu)
		ibtrs_iu_free(rx_iu, DMA_FROM_DEVICE, sess->s.dev->ib_dev);
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
	ibtrs_clt_stop_and_destroy_conns(sess);
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

static void ibtrs_clt_dev_release(struct device *dev)
{
	/* Nobody plays with device references, so nop */
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

	clt->dev.class = ibtrs_dev_class;
	clt->dev.release = ibtrs_clt_dev_release;
	dev_set_name(&clt->dev, "%s", sessname);

	err = device_register(&clt->dev);
	if (unlikely(err))
		goto percpu_free;

	err = ibtrs_clt_create_sysfs_root_folders(clt);
	if (unlikely(err))
		goto dev_unregister;

	return clt;

dev_unregister:
	/* Nobody plays with dev refs, so dev.release() is nop */
	device_unregister(&clt->dev);
percpu_free:
	free_percpu(clt->pcpu_path);
	kfree(clt);

	return ERR_PTR(err);
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
	/* Nobody plays with dev refs, so dev.release() is nop */
	device_unregister(&clt->dev);
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

static int ibtrs_post_rdma_write_sg(struct ibtrs_clt_con *con,
				    struct ibtrs_clt_io_req *req,
				    struct ibtrs_rbuf *rbuf,
				    u32 size, u32 imm)
{
	struct ibtrs_clt_sess *sess = to_clt_sess(con->c.sess);
	struct ib_sge *sge = req->sge;
	enum ib_send_flags flags;
	struct scatterlist *sg;
	size_t num_sge;
	int i;

	for_each_sg(req->sglist, sg, req->sg_cnt, i) {
		sge[i].addr   = sg_dma_address(sg);
		sge[i].length = sg_dma_len(sg);
		sge[i].lkey   = sess->s.dev->ib_pd->local_dma_lkey;
	}
	sge[i].addr   = req->iu->dma_addr;
	sge[i].length = size;
	sge[i].lkey   = sess->s.dev->ib_pd->local_dma_lkey;

	num_sge = 1 + req->sg_cnt;

	/*
	 * From time to time we have to post signalled sends,
	 * or send queue will fill up and only QP reset can help.
	 */
	flags = atomic_inc_return(&con->io_cnt) % sess->queue_depth ?
			0 : IB_SEND_SIGNALED;

	ib_dma_sync_single_for_device(sess->s.dev->ib_dev, req->iu->dma_addr,
				      size, DMA_TO_DEVICE);

	return ibtrs_iu_post_rdma_write_imm(&con->c, req->iu, sge, num_sge,
					    rbuf->rkey, rbuf->addr, imm,
					    flags, NULL);
}

static int ibtrs_clt_write_req(struct ibtrs_clt_io_req *req)
{
	struct ibtrs_clt_con *con = req->con;
	struct ibtrs_clt_sess *sess = to_clt_sess(con->c.sess);
	struct ibtrs_msg_rdma_write *msg;

	struct ibtrs_rbuf *rbuf;
	int ret, count = 0;
	u32 imm, buf_id;

	const size_t tsize = sizeof(*msg) + req->data_len + req->usr_len;

	if (unlikely(tsize > sess->chunk_size)) {
		ibtrs_wrn(sess, "Write request failed, size too big %zu > %d\n",
			  tsize, sess->chunk_size);
		return -EMSGSIZE;
	}
	if (req->sg_cnt) {
		count = ib_dma_map_sg(sess->s.dev->ib_dev, req->sglist,
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
	rbuf = &sess->rbufs[buf_id];

	/*
	 * Update stats now, after request is successfully sent it is not
	 * safe anymore to touch it.
	 */
	ibtrs_clt_update_all_stats(req, WRITE);

	ret = ibtrs_post_rdma_write_sg(req->con, req, rbuf,
				       req->usr_len + sizeof(*msg),
				       imm);
	if (unlikely(ret)) {
		ibtrs_err(sess, "Write request failed: %d\n", ret);
		ibtrs_clt_decrease_inflight(&sess->stats);
		if (req->sg_cnt)
			ib_dma_unmap_sg(sess->s.dev->ib_dev, req->sglist,
					req->sg_cnt, req->dir);
	}

	return ret;
}

static int ibtrs_map_sg_fr(struct ibtrs_clt_io_req *req, size_t count)
{
	int nr;

	/* Align the MR to a 4K page size to match the block virt boundary */
	nr = ib_map_mr_sg(req->mr, req->sglist, count, NULL, SZ_4K);
	if (unlikely(nr < req->sg_cnt)) {
		if (nr < 0)
			return nr;
		return -EINVAL;
	}
	ib_update_fast_reg_key(req->mr, ib_inc_rkey(req->mr->rkey));

	return nr;
}

static int ibtrs_clt_read_req(struct ibtrs_clt_io_req *req)
{
	struct ibtrs_clt_con *con = req->con;
	struct ibtrs_clt_sess *sess = to_clt_sess(con->c.sess);
	struct ibtrs_msg_rdma_read *msg;
	struct ibtrs_ib_dev *dev;
	struct scatterlist *sg;

	struct ib_reg_wr rwr;
	struct ib_send_wr *wr = NULL;

	int i, ret, count = 0;
	u32 imm, buf_id;

	const size_t tsize = sizeof(*msg) + req->data_len + req->usr_len;

	dev = sess->s.dev;

	if (unlikely(tsize > sess->chunk_size)) {
		ibtrs_wrn(sess, "Read request failed, message size is"
			  " %zu, bigger than CHUNK_SIZE %d\n", tsize,
			  sess->chunk_size);
		return -EMSGSIZE;
	}

	if (req->sg_cnt) {
		count = ib_dma_map_sg(dev->ib_dev, req->sglist, req->sg_cnt,
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
	msg->usr_len = cpu_to_le16(req->usr_len);

	if (count > noreg_cnt) {
		ret = ibtrs_map_sg_fr(req, count);
		if (ret < 0) {
			ibtrs_err_rl(sess,
				     "Read request failed, failed to map "
				     " fast reg. data, err: %d\n", ret);
			ib_dma_unmap_sg(dev->ib_dev, req->sglist, req->sg_cnt,
					req->dir);
			return ret;
		}
		memset(&rwr, 0, sizeof(rwr));
		rwr.wr.next = NULL;
		rwr.wr.opcode = IB_WR_REG_MR;
		rwr.wr.wr_cqe = &fast_reg_cqe;
		rwr.wr.num_sge = 0;
		rwr.mr = req->mr;
		rwr.key = req->mr->rkey;
		rwr.access = (IB_ACCESS_LOCAL_WRITE |
			      IB_ACCESS_REMOTE_WRITE);
		wr = &rwr.wr;

		msg->sg_cnt = cpu_to_le16(1);
		msg->flags = cpu_to_le16(ibtrs_invalidate_flag());

		msg->desc[0].addr = cpu_to_le64(req->mr->iova);
		msg->desc[0].key = cpu_to_le32(req->mr->rkey);
		msg->desc[0].len = cpu_to_le32(req->mr->length);

		/* Further invalidation is required */
		req->need_inv = !!ibtrs_invalidate_flag();

	} else {
		msg->sg_cnt = cpu_to_le16(count);
		msg->flags = 0;

		for_each_sg(req->sglist, sg, req->sg_cnt, i) {
			msg->desc[i].addr = cpu_to_le64(sg_dma_address(sg));
			msg->desc[i].key = cpu_to_le32(dev->ib_pd->unsafe_global_rkey);
			msg->desc[i].len = cpu_to_le32(sg_dma_len(sg));
		}
	}
	/*
	 * ibtrs message will be after the space reserved for disk data and
	 * user message
	 */
	imm = req->tag->mem_off + req->data_len + req->usr_len;
	imm = ibtrs_to_io_req_imm(imm);
	buf_id = req->tag->mem_id;

	req->sg_size  = sizeof(*msg);
	req->sg_size += le16_to_cpu(msg->sg_cnt) * sizeof(struct ibtrs_sg_desc);
	req->sg_size += req->usr_len;

	/*
	 * Update stats now, after request is successfully sent it is not
	 * safe anymore to touch it.
	 */
	ibtrs_clt_update_all_stats(req, READ);

	ret = ibtrs_post_send_rdma(req->con, req, &sess->rbufs[buf_id],
				   req->data_len, imm, wr);
	if (unlikely(ret)) {
		ibtrs_err(sess, "Read request failed: %d\n", ret);
		ibtrs_clt_decrease_inflight(&sess->stats);
		req->need_inv = false;
		if (req->sg_cnt)
			ib_dma_unmap_sg(dev->ib_dev, req->sglist,
					req->sg_cnt, req->dir);
	}

	return ret;
}

int ibtrs_clt_request(int dir, ibtrs_conf_fn *conf, struct ibtrs_clt *clt,
		      struct ibtrs_tag *tag, void *priv, const struct kvec *vec,
		      size_t nr, size_t data_len, struct scatterlist *sg,
		      unsigned int sg_cnt)
{
	struct ibtrs_clt_io_req *req;
	struct ibtrs_clt_sess *sess;

	enum dma_data_direction dma_dir;
	int err = -ECONNABORTED, i;
	size_t usr_len, hdr_len;
	struct path_it it;

	/* Get kvec length */
	for (i = 0, usr_len = 0; i < nr; i++)
		usr_len += vec[i].iov_len;

	if (dir == READ) {
		hdr_len = sizeof(struct ibtrs_msg_rdma_read) +
			  sg_cnt * sizeof(struct ibtrs_sg_desc);
		dma_dir = DMA_FROM_DEVICE;
	} else {
		hdr_len = sizeof(struct ibtrs_msg_rdma_write);
		dma_dir = DMA_TO_DEVICE;
	}

	do_each_path(sess, clt, &it) {
		if (unlikely(sess->state != IBTRS_CLT_CONNECTED))
			continue;

		if (unlikely(usr_len + hdr_len > sess->max_hdr_size)) {
			ibtrs_wrn_rl(sess, "%s request failed, user message "
				     "size is %zu and header length %zu, but "
				     "max size is %u\n",
				     dir == READ ? "Read" : "Write",
				     usr_len, hdr_len, sess->max_hdr_size);
			err = -EMSGSIZE;
			break;
		}
		req = ibtrs_clt_get_req(sess, conf, tag, priv, vec, usr_len,
					sg, sg_cnt, data_len, dma_dir);
		if (dir == READ)
			err = ibtrs_clt_read_req(req);
		else
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
	if (nr_cons_per_session == 0)
		nr_cons_per_session = min_t(unsigned int, nr_cpu_ids, U16_MAX);

	return 0;
}

static int ibtrs_clt_ib_dev_init(struct ibtrs_ib_dev *dev)
{
	if (!(dev->ib_dev->attrs.device_cap_flags &
	      IB_DEVICE_MEM_MGT_EXTENSIONS)) {
		pr_err("Memory registrations not supported.\n");
		return -ENOTSUPP;
	}

	return 0;
}

static const struct ibtrs_ib_dev_pool_ops dev_pool_ops = {
	.init = ibtrs_clt_ib_dev_init
};

static int __init ibtrs_client_init(void)
{
	int err;

	pr_info("Loading module %s, version %s, proto %s: "
		"(retry_cnt: %d, noreg_cnt: %d)\n",
		KBUILD_MODNAME, IBTRS_VER_STRING, IBTRS_PROTO_VER_STRING,
		retry_cnt, noreg_cnt);

	ibtrs_ib_dev_pool_init(noreg_cnt ? IB_PD_UNSAFE_GLOBAL_RKEY : 0,
			       &dev_pool);

	err = check_module_params();
	if (unlikely(err)) {
		pr_err("Failed to load module, invalid module parameters,"
		       " err: %d\n", err);
		return err;
	}
	ibtrs_dev_class = class_create(THIS_MODULE, "ibtrs-client");
	if (unlikely(IS_ERR(ibtrs_dev_class))) {
		pr_err("Failed to create ibtrs-client dev class\n");
		return PTR_ERR(ibtrs_dev_class);
	}
	ibtrs_wq = alloc_workqueue("ibtrs_client_wq", WQ_MEM_RECLAIM, 0);
	if (unlikely(!ibtrs_wq)) {
		pr_err("Failed to load module, alloc ibtrs_client_wq failed\n");
		class_destroy(ibtrs_dev_class);
		return -ENOMEM;
	}

	return 0;
}

static void __exit ibtrs_client_exit(void)
{
	destroy_workqueue(ibtrs_wq);
	class_destroy(ibtrs_dev_class);
	ibtrs_ib_dev_pool_deinit(&dev_pool);
}

module_init(ibtrs_client_init);
module_exit(ibtrs_client_exit);
