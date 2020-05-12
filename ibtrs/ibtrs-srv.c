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
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions, and the following disclaimer,
 *    without modification.
 * 2. Redistributions in binary form must reproduce at minimum a disclaimer
 *    substantially similar to the "NO WARRANTY" disclaimer below
 *    ("Disclaimer") and any redistribution must be conditioned upon
 *    including a substantially similar Disclaimer requirement for further
 *    binary redistribution.
 * 3. Neither the names of the above-listed copyright holders nor the names
 *    of any contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * Alternatively, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") version 2 as published by the Free
 * Software Foundation.
 *
 * NO WARRANTY
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDERS OR CONTRIBUTORS BE LIABLE FOR SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGES.
 */

#undef pr_fmt
#define pr_fmt(fmt) KBUILD_MODNAME " L" __stringify(__LINE__) ": " fmt

#include <linux/module.h>
#include <linux/mempool.h>
#include <rdma/rdma_cm.h>

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

/* We guarantee to serve 10 paths at least */
#define CHUNK_POOL_SIZE (DEFAULT_SESS_QUEUE_DEPTH * 10)
static mempool_t *chunk_pool;

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

static struct workqueue_struct *ibtrs_wq;

static void close_sess(struct ibtrs_srv_sess *sess);

static inline struct ibtrs_srv_con *to_srv_con(struct ibtrs_con *c)
{
	if (unlikely(!c))
		return NULL;

	return container_of(c, struct ibtrs_srv_con, c);
}

static inline struct ibtrs_srv_sess *to_srv_sess(struct ibtrs_sess *s)
{
	if (unlikely(!s))
		return NULL;

	return container_of(s, struct ibtrs_srv_sess, s);
}

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
	struct ibtrs_srv_con *usr_con = to_srv_con(sess->s.con[0]);
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
	struct ibtrs_srv_con *usr_con = to_srv_con(sess->s.con[0]);

	if (usr_con)
		return sess->s.ib_dev->dev->name;

	return "n/a";
}

static void free_id(struct ibtrs_srv_op *id)
{
	if (!id)
		return;
	kfree(id->tx_wr);
	kfree(id->tx_sg);
	kfree(id);
}

static void ibtrs_srv_free_ops_ids(struct ibtrs_srv_sess *sess)
{
	struct ibtrs_srv *srv = sess->srv;
	int i;

	WARN_ON(atomic_read(&sess->ids_inflight));
	if (sess->ops_ids) {
		for (i = 0; i < srv->queue_depth; i++)
			free_id(sess->ops_ids[i]);
		kfree(sess->ops_ids);
		sess->ops_ids = NULL;
	}
}

static int ibtrs_srv_alloc_ops_ids(struct ibtrs_srv_sess *sess)
{
	struct ibtrs_srv *srv = sess->srv;
	struct ibtrs_srv_op *id;
	int i;

	sess->ops_ids = kcalloc(srv->queue_depth, sizeof(*sess->ops_ids),
				GFP_KERNEL);
	if (unlikely(!sess->ops_ids)) {
		ibtrs_err(sess, "Allocation failed\n");
		goto err;
	}
	for (i = 0; i < srv->queue_depth; ++i) {
		id = kzalloc(sizeof(*id), GFP_KERNEL);
		if (unlikely(!id)) {
			ibtrs_err(sess, "Allocation failed\n");
			goto err;
		}
		sess->ops_ids[i] = id;
	}
	init_waitqueue_head(&sess->ids_waitq);
	atomic_set(&sess->ids_inflight, 0);

	return 0;

err:
	ibtrs_srv_free_ops_ids(sess);
	return -ENOMEM;
}

static void ibtrs_srv_get_ops_ids(struct ibtrs_srv_sess *sess)
{
	atomic_inc(&sess->ids_inflight);
}

static void ibtrs_srv_put_ops_ids(struct ibtrs_srv_sess *sess)
{
	if (atomic_dec_and_test(&sess->ids_inflight))
		wake_up(&sess->ids_waitq);
}

static void ibtrs_srv_wait_ops_ids(struct ibtrs_srv_sess *sess)
{
	wait_event(sess->ids_waitq, !atomic_read(&sess->ids_inflight));
}

static void ibtrs_srv_rdma_done(struct ib_cq *cq, struct ib_wc *wc);

static struct ib_cqe io_comp_cqe = {
	.done = ibtrs_srv_rdma_done
};

static int rdma_write_sg(struct ibtrs_srv_op *id)
{
	struct ibtrs_srv_sess *sess = to_srv_sess(id->con->c.sess);
	struct ibtrs_srv *srv = sess->srv;
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

		list->lkey = sess->s.ib_dev->lkey;
		offset += list->length;

		wr->wr.wr_cqe	= &io_comp_cqe;
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
	flags = atomic_inc_return(&id->con->wr_cnt) % srv->queue_depth ?
			0 : IB_SEND_SIGNALED;

	wr->wr.wr_cqe = &io_comp_cqe;
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

static int send_io_resp_imm(struct ibtrs_srv_con *con, int msg_id, s16 errno)
{
	struct ibtrs_srv_sess *sess = to_srv_sess(con->c.sess);
	struct ibtrs_srv *srv = sess->srv;
	enum ib_send_flags flags;
	u32 imm;
	int err;

	/*
	 * From time to time we have to post signalled sends,
	 * or send queue will fill up and only QP reset can help.
	 */
	flags = atomic_inc_return(&con->wr_cnt) % srv->queue_depth ?
			0 : IB_SEND_SIGNALED;
	imm = (msg_id << 16) | (u16)errno;
	err = ibtrs_post_rdma_write_imm_empty(&con->c, &io_comp_cqe,
					      imm, flags);
	if (unlikely(err))
		ibtrs_err_rl(sess, "ib_post_send(), err: %d\n", err);

	return err;
}

/*
 * ibtrs_srv_resp_rdma() - sends response to the client.
 *
 * Context: any
 */
void ibtrs_srv_resp_rdma(struct ibtrs_srv_op *id, int status)
{
	struct ibtrs_srv_con *con = id->con;
	struct ibtrs_srv_sess *sess = to_srv_sess(con->c.sess);
	int err;

	if (WARN_ON(!id))
		return;

	if (unlikely(sess->state != IBTRS_SRV_CONNECTED)) {
		ibtrs_err_rl(sess, "Sending I/O response failed, "
			     " session is disconnected, sess state %s\n",
			     ibtrs_srv_state_str(sess->state));
		goto out;
	}
	if (status || id->dir == WRITE || !id->req->sg_cnt)
		err = send_io_resp_imm(con, id->msg_id, status);
	else
		err = rdma_write_sg(id);
	if (unlikely(err)) {
		ibtrs_err_rl(sess, "IO response failed: %d\n", err);
		close_sess(sess);
	}
out:
	ibtrs_srv_put_ops_ids(sess);

	return;
}
EXPORT_SYMBOL(ibtrs_srv_resp_rdma);

void ibtrs_srv_set_sess_priv(struct ibtrs_srv *srv, void *priv)
{
	srv->priv = priv;
}
EXPORT_SYMBOL(ibtrs_srv_set_sess_priv);

static void unmap_cont_bufs(struct ibtrs_srv_sess *sess)
{
	struct ibtrs_srv *srv = sess->srv;
	int i;

	for (i = 0; i < srv->queue_depth; i++)
		ib_dma_unmap_page(sess->s.ib_dev->dev, sess->rdma_addr[i],
				  rcv_buf_size, DMA_BIDIRECTIONAL);
}

static int map_cont_bufs(struct ibtrs_srv_sess *sess)
{
	struct ibtrs_srv *srv = sess->srv;
	dma_addr_t addr;
	int i, err;

	for (i = 0; i < srv->queue_depth; i++) {
		addr = ib_dma_map_page(sess->s.ib_dev->dev, srv->chunks[i],
				       0, rcv_buf_size, DMA_BIDIRECTIONAL);
		if (unlikely(ib_dma_mapping_error(sess->s.ib_dev->dev, addr))) {
			ibtrs_err(sess, "ib_dma_map_page() failed\n");
			err = -EIO;
			goto err_map;
		}
		sess->rdma_addr[i] = addr;
	}
	sess->off_len = 31 - ilog2(srv->queue_depth - 1);
	sess->off_mask = (1 << sess->off_len) - 1;

	return 0;

err_map:
	while (i--)
		ib_dma_unmap_page(sess->s.ib_dev->dev, sess->rdma_addr[i],
				  rcv_buf_size, DMA_BIDIRECTIONAL);

	return err;
}

static void ibtrs_srv_hb_err_handler(struct ibtrs_con *c, int err)
{
	(void)err;
	close_sess(to_srv_sess(c->sess));
}

static void ibtrs_srv_init_hb(struct ibtrs_srv_sess *sess)
{
	ibtrs_init_hb(&sess->s, &io_comp_cqe,
		      IBTRS_HB_INTERVAL_MS,
		      IBTRS_HB_MISSED_MAX,
		      ibtrs_srv_hb_err_handler,
		      ibtrs_wq);
}

static void ibtrs_srv_start_hb(struct ibtrs_srv_sess *sess)
{
	ibtrs_start_hb(&sess->s);
}

static void ibtrs_srv_stop_hb(struct ibtrs_srv_sess *sess)
{
	ibtrs_stop_hb(&sess->s);
}

static void ibtrs_srv_info_rsp_done(struct ib_cq *cq, struct ib_wc *wc)
{
	struct ibtrs_srv_con *con = cq->cq_context;
	struct ibtrs_srv_sess *sess = to_srv_sess(con->c.sess);
	struct ibtrs_iu *iu;

	iu = container_of(wc->wr_cqe, struct ibtrs_iu, cqe);
	ibtrs_iu_free(iu, DMA_TO_DEVICE, sess->s.ib_dev->dev);

	if (unlikely(wc->status != IB_WC_SUCCESS)) {
		ibtrs_err(sess, "Sess info response send failed: %s\n",
			  ib_wc_status_msg(wc->status));
		close_sess(sess);
		return;
	}
	WARN_ON(wc->opcode != IB_WC_SEND);
	ibtrs_srv_update_wc_stats(&sess->stats);
}

static void ibtrs_srv_sess_up(struct ibtrs_srv_sess *sess)
{
	struct ibtrs_srv *srv = sess->srv;
	struct ibtrs_srv_ctx *ctx = srv->ctx;
	int up;

	mutex_lock(&srv->paths_ev_mutex);
	up = ++srv->paths_up;
	if (up == 1)
		ctx->link_ev(srv, IBTRS_SRV_LINK_EV_CONNECTED, NULL);
	mutex_unlock(&srv->paths_ev_mutex);

	/* Mark session as established */
	sess->established = true;
}

static void ibtrs_srv_sess_down(struct ibtrs_srv_sess *sess)
{
	struct ibtrs_srv *srv = sess->srv;
	struct ibtrs_srv_ctx *ctx = srv->ctx;

	if (!sess->established)
		return;

	sess->established = false;
	mutex_lock(&srv->paths_ev_mutex);
	WARN_ON(!srv->paths_up);
	if (--srv->paths_up == 0)
		ctx->link_ev(srv, IBTRS_SRV_LINK_EV_DISCONNECTED, srv->priv);
	mutex_unlock(&srv->paths_ev_mutex);
}

static int post_recv_sess(struct ibtrs_srv_sess *sess);

static int process_info_req(struct ibtrs_srv_con *con,
			    struct ibtrs_msg_info_req *msg)
{
	struct ibtrs_srv_sess *sess = to_srv_sess(con->c.sess);
	struct ibtrs_srv *srv = sess->srv;
	struct ibtrs_msg_info_rsp *rsp;
	struct ibtrs_iu *tx_iu;
	size_t tx_sz;
	int i, err;

	err = post_recv_sess(sess);
	if (unlikely(err)) {
		ibtrs_err(sess, "post_recv_sess(), err: %d\n", err);
		return err;
	}
	memcpy(sess->s.sessname, msg->sessname, sizeof(sess->s.sessname));

	tx_sz  = sizeof(struct ibtrs_msg_info_rsp);
	tx_sz += sizeof(u64) * srv->queue_depth;
	tx_iu = ibtrs_iu_alloc(0, tx_sz, GFP_KERNEL, sess->s.ib_dev->dev,
			       DMA_TO_DEVICE, ibtrs_srv_info_rsp_done);
	if (unlikely(!tx_iu)) {
		ibtrs_err(sess, "ibtrs_iu_alloc(), err: %d\n", -ENOMEM);
		return -ENOMEM;
	}

	rsp = tx_iu->buf;
	rsp->type = cpu_to_le16(IBTRS_MSG_INFO_RSP);
	rsp->addr_num = cpu_to_le16(srv->queue_depth);
	for (i = 0; i < srv->queue_depth; i++)
		rsp->addr[i] = cpu_to_le64(sess->rdma_addr[i]);

	err = ibtrs_srv_create_once_sysfs_root_folders(srv, sess->s.sessname);
	if (unlikely(err))
		goto iu_free;

	err = ibtrs_srv_create_sess_files(sess);
	if (unlikely(err))
		goto iu_free;

	ibtrs_srv_change_state(sess, IBTRS_SRV_CONNECTED);
	ibtrs_srv_start_hb(sess);

	/*
	 * We do not account number of established connections at the current
	 * moment, we rely on the client, which should send info request when
	 * all connections are successfully established.  Thus, simply notify
	 * listener with a proper event if we are the first path.
	 */
	ibtrs_srv_sess_up(sess);

	/* Send info response */
	err = ibtrs_iu_post_send(&con->c, tx_iu, tx_sz);
	if (unlikely(err)) {
		ibtrs_err(sess, "ibtrs_iu_post_send(), err: %d\n", err);
iu_free:
		ibtrs_iu_free(tx_iu, DMA_TO_DEVICE, sess->s.ib_dev->dev);
	}

	return err;
}

static void ibtrs_srv_info_req_done(struct ib_cq *cq, struct ib_wc *wc)
{
	struct ibtrs_srv_con *con = cq->cq_context;
	struct ibtrs_srv_sess *sess = to_srv_sess(con->c.sess);
	struct ibtrs_msg_info_req *msg;
	struct ibtrs_iu *iu;
	int err;

	WARN_ON(con->c.cid);

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
	struct ibtrs_srv_sess *sess = to_srv_sess(con->c.sess);
	struct ibtrs_iu *rx_iu;
	int err;

	rx_iu = ibtrs_iu_alloc(0, sizeof(struct ibtrs_msg_info_req),
			       GFP_KERNEL, sess->s.ib_dev->dev,
			       DMA_FROM_DEVICE, ibtrs_srv_info_req_done);
	if (unlikely(!rx_iu)) {
		ibtrs_err(sess, "ibtrs_iu_alloc(): no memory\n");
		return -ENOMEM;
	}
	/* Prepare for getting info response */
	err = ibtrs_iu_post_recv(&con->c, rx_iu);
	if (unlikely(err)) {
		ibtrs_err(sess, "ibtrs_iu_post_recv(), err: %d\n", err);
		ibtrs_iu_free(rx_iu, DMA_FROM_DEVICE, sess->s.ib_dev->dev);
		return err;
	}

	return 0;
}

static int post_recv_io(struct ibtrs_srv_con *con)
{
	struct ibtrs_srv_sess *sess = to_srv_sess(con->c.sess);
	struct ibtrs_srv *srv = sess->srv;
	int i, err;

	for (i = 0; i < srv->queue_depth; i++) {
		err = ibtrs_post_recv_empty(&con->c, &io_comp_cqe);
		if (unlikely(err))
			return err;
	}

	return 0;
}

static int post_recv_sess(struct ibtrs_srv_sess *sess)
{
	int err, cid;

	for (cid = 0; cid < sess->s.con_num; cid++) {
		err = post_recv_io(to_srv_con(sess->s.con[cid]));
		if (unlikely(err)) {
			ibtrs_err(sess, "post_recv_io(), err: %d\n", err);
			return err;
		}
	}

	return 0;
}

static void process_read(struct ibtrs_srv_con *con,
			 struct ibtrs_msg_req_rdma_write *req,
			 u32 buf_id, u32 off)
{
	struct ibtrs_srv_sess *sess = to_srv_sess(con->c.sess);
	struct ibtrs_srv *srv = sess->srv;
	struct ibtrs_srv_ctx *ctx = srv->ctx;
	struct ibtrs_srv_op *id;

	size_t usr_len, data_len, sg_cnt;
	void *data;
	int ret;

	if (unlikely(sess->state != IBTRS_SRV_CONNECTED)) {
		ibtrs_err_rl(sess, "Processing read request failed, "
			     " session is disconnected, sess state %s\n",
			     ibtrs_srv_state_str(sess->state));
		return;
	}
	sg_cnt = le32_to_cpu(req->sg_cnt);
	ibtrs_srv_get_ops_ids(sess);
	ibtrs_srv_update_rdma_stats(&sess->stats, off, READ);
	id = sess->ops_ids[buf_id];
	kfree(id->tx_wr);
	kfree(id->tx_sg);
	id->tx_wr	= NULL;
	id->tx_sg	= NULL;
	id->con		= con;
	id->dir		= READ;
	id->msg_id	= buf_id;
	id->req		= req;
	if (sg_cnt) {
		id->tx_wr	= kcalloc(sg_cnt, sizeof(*id->tx_wr), GFP_KERNEL);
		id->tx_sg	= kcalloc(sg_cnt, sizeof(*id->tx_sg), GFP_KERNEL);
		if (!id->tx_wr || !id->tx_sg) {
			ibtrs_err_rl(sess, "Processing read request failed, work request "
				     "or scatter gather allocation failed for msg_id %d\n",
				     buf_id);
			ret = -ENOMEM;
			goto send_err_msg;
		}
	}
	usr_len = le16_to_cpu(req->usr_len);
	data_len = off - usr_len;
	data = page_address(srv->chunks[buf_id]);
	id->data_dma_addr = sess->rdma_addr[buf_id];
	ret = ctx->rdma_ev(srv, srv->priv, id, READ, data, data_len,
			   data + data_len, usr_len);

	if (unlikely(ret)) {
		ibtrs_err_rl(sess, "Processing read request failed, user "
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
	ibtrs_srv_put_ops_ids(sess);
}

static void process_write(struct ibtrs_srv_con *con,
			  struct ibtrs_msg_rdma_write *req,
			  u32 buf_id, u32 off)
{
	struct ibtrs_srv_sess *sess = to_srv_sess(con->c.sess);
	struct ibtrs_srv *srv = sess->srv;
	struct ibtrs_srv_ctx *ctx = srv->ctx;
	struct ibtrs_srv_op *id;

	size_t data_len, usr_len;
	void *data;
	int ret;

	if (unlikely(sess->state != IBTRS_SRV_CONNECTED)) {
		ibtrs_err_rl(sess, "Processing write request failed, "
			     " session is disconnected, sess state %s\n",
			     ibtrs_srv_state_str(sess->state));
		return;
	}
	ibtrs_srv_get_ops_ids(sess);
	ibtrs_srv_update_rdma_stats(&sess->stats, off, WRITE);
	id = sess->ops_ids[buf_id];
	id->con    = con;
	id->dir    = WRITE;
	id->msg_id = buf_id;

	usr_len = le16_to_cpu(req->usr_len);
	data_len = off - usr_len;
	data = page_address(srv->chunks[buf_id]);
	ret = ctx->rdma_ev(srv, srv->priv, id, WRITE, data, data_len,
			   data + data_len, usr_len);
	if (unlikely(ret)) {
		ibtrs_err_rl(sess, "Processing write request failed, user module"
			     " callback reports err: %d\n", ret);
		goto send_err_msg;
	}

	return;

send_err_msg:
	ret = send_io_resp_imm(con, buf_id, ret);
	if (ret < 0) {
		ibtrs_err_rl(sess, "Processing write request failed, sending I/O"
			     " response failed, msg_id %d, err: %d\n",
			     buf_id, ret);
		close_sess(sess);
	}
	ibtrs_srv_put_ops_ids(sess);
}

static void process_io_req(struct ibtrs_srv_con *con, void *msg,
			   u32 id, u32 off)
{
	struct ibtrs_srv_sess *sess = to_srv_sess(con->c.sess);
	unsigned type;

	type = le16_to_cpu(le16_to_cpu(*(__le16 *)msg));

	switch (type) {
	case IBTRS_MSG_WRITE:
		process_write(con, msg, id, off);
		break;
	case IBTRS_MSG_READ:
		process_read(con, msg, id, off);
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
	struct ibtrs_srv_sess *sess = to_srv_sess(con->c.sess);
	struct ibtrs_srv *srv = sess->srv;
	u32 imm, msg_id, off;
	void *data;
	int err;

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
	ibtrs_srv_update_wc_stats(&sess->stats);

	switch (wc->opcode) {
	case IB_WC_RDMA_WRITE:
		/*
		 * post_send() RDMA write completions of IO reqs (read/write) and hb
		 */
		break;
	case IB_WC_RECV_RDMA_WITH_IMM:
		/*
		 * post_recv() RDMA write completions of IO reqs (read/write) and hb
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
		if (imm == IBTRS_HB_IMM) {
			WARN_ON(con->c.cid);
			ibtrs_send_hb_ack(&sess->s);
			break;
		} else if (imm == IBTRS_HB_ACK_IMM) {
			WARN_ON(con->c.cid);
			sess->s.hb_missed_cnt = 0;
			break;
		}

		msg_id = imm >> sess->off_len;
		off = imm & sess->off_mask;

		if (unlikely(msg_id > srv->queue_depth ||
			     off > rcv_buf_size)) {
			ibtrs_err(sess, "Processing I/O failed, contiguous "
				  "buf addr is out of reserved area\n");
			close_sess(sess);
			return;
		}
		data = page_address(srv->chunks[msg_id]) + off;
		process_io_req(con, data, msg_id, off);
		break;
	default:
		ibtrs_wrn(sess, "Unexpected WC type: %s\n",
			  ib_wc_opcode_str(wc->opcode));
		return;
	}
}

int ibtrs_srv_get_sess_name(struct ibtrs_srv *srv, char *sessname, size_t len)
{
	struct ibtrs_srv_sess *sess;
	int err = -ENOTCONN;

	mutex_lock(&srv->paths_mutex);
	list_for_each_entry(sess, &srv->paths_list, s.entry) {
		if (sess->state != IBTRS_SRV_CONNECTED)
			continue;
		memcpy(sessname, sess->s.sessname,
		       min_t(size_t, sizeof(sess->s.sessname), len));
		err = 0;
		break;
	}
	mutex_unlock(&srv->paths_mutex);

	return err;
}
EXPORT_SYMBOL(ibtrs_srv_get_sess_name);

int ibtrs_srv_get_queue_depth(struct ibtrs_srv *srv)
{
	return srv->queue_depth;
}
EXPORT_SYMBOL(ibtrs_srv_get_queue_depth);

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

static struct ibtrs_srv *__alloc_srv(struct ibtrs_srv_ctx *ctx,
				     const uuid_t *paths_uuid)
{
	struct ibtrs_srv *srv;
	int i;

	srv = kzalloc(sizeof(*srv), GFP_KERNEL);
	if  (unlikely(!srv))
		return NULL;

	refcount_set(&srv->refcount, 1);
	INIT_LIST_HEAD(&srv->paths_list);
	mutex_init(&srv->paths_mutex);
	mutex_init(&srv->paths_ev_mutex);
	uuid_copy(&srv->paths_uuid, paths_uuid);
	srv->queue_depth = sess_queue_depth;
	srv->ctx = ctx;

	srv->chunks = kcalloc(srv->queue_depth, sizeof(*srv->chunks),
			      GFP_KERNEL);
	if (unlikely(!srv->chunks))
		goto err_free_srv;

	for (i = 0; i < srv->queue_depth; i++) {
		srv->chunks[i] = mempool_alloc(chunk_pool, GFP_KERNEL);
		if (unlikely(!srv->chunks[i])) {
			pr_err("mempool_alloc() failed\n");
			goto err_free_chunks;
		}
	}
	list_add(&srv->ctx_list, &ctx->srv_list);

	return srv;

err_free_chunks:
	while (i--)
		mempool_free(srv->chunks[i], chunk_pool);
	kfree(srv->chunks);

err_free_srv:
	kfree(srv);

	return NULL;
}

static void free_srv(struct ibtrs_srv *srv)
{
	int i;

	WARN_ON(refcount_read(&srv->refcount));
	for (i = 0; i < srv->queue_depth; i++)
		mempool_free(srv->chunks[i], chunk_pool);
	kfree(srv->chunks);
	kfree(srv);
}

static inline struct ibtrs_srv *__find_srv_and_get(struct ibtrs_srv_ctx *ctx,
						   const uuid_t *paths_uuid)
{
	struct ibtrs_srv *srv;

	list_for_each_entry(srv, &ctx->srv_list, ctx_list) {
		if (uuid_equal(&srv->paths_uuid, paths_uuid) &&
		    refcount_inc_not_zero(&srv->refcount))
			return srv;
	}

	return NULL;
}

static struct ibtrs_srv *get_or_create_srv(struct ibtrs_srv_ctx *ctx,
					   const uuid_t *paths_uuid)
{
	struct ibtrs_srv *srv;

	mutex_lock(&ctx->srv_mutex);
	srv = __find_srv_and_get(ctx, paths_uuid);
	if (!srv)
		srv = __alloc_srv(ctx, paths_uuid);
	mutex_unlock(&ctx->srv_mutex);

	return srv;
}

static void put_srv(struct ibtrs_srv *srv)
{
	if (refcount_dec_and_test(&srv->refcount)) {
		struct ibtrs_srv_ctx *ctx = srv->ctx;

		mutex_lock(&ctx->srv_mutex);
		ibtrs_srv_destroy_sysfs_root_folders(srv);
		list_del(&srv->ctx_list);
		mutex_unlock(&ctx->srv_mutex);
		free_srv(srv);
	}
}

static void __add_path_to_srv(struct ibtrs_srv *srv,
			      struct ibtrs_srv_sess *sess)
{
	list_add_tail(&sess->s.entry, &srv->paths_list);
	srv->paths_num++;
	WARN_ON(srv->paths_num >= MAX_PATHS_NUM);
}

static void del_path_from_srv(struct ibtrs_srv_sess *sess)
{
	struct ibtrs_srv* srv = sess->srv;

	if (WARN_ON(!srv))
		return;

	mutex_lock(&srv->paths_mutex);
	list_del(&sess->s.entry);
	WARN_ON(!srv->paths_num);
	srv->paths_num--;
	mutex_unlock(&srv->paths_mutex);
}

static void ibtrs_srv_close_work(struct work_struct *work)
{
	struct ibtrs_srv_sess *sess;
	struct ibtrs_srv_ctx *ctx;
	struct ibtrs_srv_con *con;
	int i;

	sess = container_of(work, typeof(*sess), close_work);
	ctx = sess->srv->ctx;

	ibtrs_srv_destroy_sess_files(sess);
	ibtrs_srv_stop_hb(sess);

	for (i = 0; i < sess->s.con_num; i++) {
		con = to_srv_con(sess->s.con[i]);
		if (!con)
			continue;

		rdma_disconnect(con->c.cm_id);
		ib_drain_qp(con->c.qp);
	}
	/* Wait for all inflights */
	ibtrs_srv_wait_ops_ids(sess);

	/* Notify upper layer if we are the last path */
	ibtrs_srv_sess_down(sess);

	unmap_cont_bufs(sess);
	ibtrs_srv_free_ops_ids(sess);

	for (i = 0; i < sess->s.con_num; i++) {
		con = to_srv_con(sess->s.con[i]);
		if (!con)
			continue;

		ibtrs_cq_qp_destroy(&con->c);
		rdma_destroy_id(con->c.cm_id);
		kfree(con);
	}
	ibtrs_ib_dev_put(sess->s.ib_dev);

	del_path_from_srv(sess);
	put_srv(sess->srv);
	sess->srv = NULL;
	ibtrs_srv_change_state(sess, IBTRS_SRV_CLOSED);

	kfree(sess->rdma_addr);
	kfree(sess->s.con);
	kfree(sess);
}

static int ibtrs_rdma_do_accept(struct ibtrs_srv_sess *sess,
				struct rdma_cm_id *cm_id)
{
	struct ibtrs_srv *srv = sess->srv;
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
	msg.queue_depth = cpu_to_le16(srv->queue_depth);
	msg.rkey = cpu_to_le32(sess->s.ib_dev->rkey);
	msg.max_io_size = cpu_to_le32(max_io_size);
	msg.max_req_size = cpu_to_le32(MAX_REQ_SIZE);
	uuid_copy(&msg.uuid, &sess->s.uuid);

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

	/* Bounce errno back */
	return errno;
}

static struct ibtrs_srv_sess *
__find_sess(struct ibtrs_srv *srv, const uuid_t *sess_uuid)
{
	struct ibtrs_srv_sess *sess;

	list_for_each_entry(sess, &srv->paths_list, s.entry) {
		if (uuid_equal(&sess->s.uuid, sess_uuid))
			return sess;
	}

	return NULL;
}

static int create_con(struct ibtrs_srv_sess *sess,
		      struct rdma_cm_id *cm_id,
		      unsigned cid)
{
	struct ibtrs_srv *srv = sess->srv;
	struct ibtrs_srv_con *con;

	u16 cq_size, wr_queue_size;
	int err, cq_vector;

	con = kzalloc(sizeof(*con), GFP_KERNEL);
	if (unlikely(!con)) {
		ibtrs_err(sess, "kzalloc() failed\n");
		err = -ENOMEM;
		goto err;
	}

	con->c.cm_id = cm_id;
	con->c.sess = &sess->s;
	con->c.cid = cid;
	atomic_set(&con->wr_cnt, 0);

	if (con->c.cid == 0) {
		cq_size       = SERVICE_CON_QUEUE_DEPTH;
		/* + 2 for drain and heartbeat */
		wr_queue_size = SERVICE_CON_QUEUE_DEPTH + 2;
	} else {
		cq_size       = srv->queue_depth;
		wr_queue_size = sess->s.ib_dev->attrs.max_qp_wr;
	}

	cq_vector = ibtrs_srv_get_next_cq_vector(sess);

	/* TODO: SOFTIRQ can be faster, but be careful with softirq context */
	err = ibtrs_cq_qp_create(&sess->s, &con->c, 1, cq_vector, cq_size,
				 wr_queue_size, IB_POLL_WORKQUEUE);
	if (unlikely(err)) {
		ibtrs_err(sess, "ibtrs_cq_qp_create(), err: %d\n", err);
		goto free_con;
	}
	if (con->c.cid == 0) {
		err = post_recv_info_req(con);
		if (unlikely(err))
			goto free_cqqp;
	}
	WARN_ON(sess->s.con[cid]);
	sess->s.con[cid] = &con->c;

	/*
	 * Change context from server to current connection.  The other
	 * way is to use cm_id->qp->qp_context, which does not work on OFED.
	 */
	cm_id->context = &con->c;

	return 0;

free_cqqp:
	ibtrs_cq_qp_destroy(&con->c);
free_con:
	kfree(con);

err:
	return err;
}

static struct ibtrs_srv_sess *__alloc_sess(struct ibtrs_srv *srv,
					   struct rdma_cm_id *cm_id,
					   unsigned con_num, unsigned recon_cnt,
					   const uuid_t *uuid)
{
	struct ibtrs_srv_sess *sess;
	int err = -ENOMEM;

	if (unlikely(srv->paths_num >= MAX_PATHS_NUM)) {
		err = -ECONNRESET;
		goto err;
	}
	sess = kzalloc(sizeof(*sess), GFP_KERNEL);
	if (unlikely(!sess))
		goto err;

	sess->rdma_addr = kcalloc(srv->queue_depth, sizeof(*sess->rdma_addr),
				  GFP_KERNEL);
	if (unlikely(!sess->rdma_addr))
		goto err_free_sess;

	sess->s.con = kcalloc(con_num, sizeof(*sess->s.con), GFP_KERNEL);
	if (unlikely(!sess->s.con))
		goto err_free_rdma_addr;

	sess->state = IBTRS_SRV_CONNECTING;
	sess->srv = srv;
	sess->cur_cq_vector = -1;
	sess->s.dst_addr = cm_id->route.addr.dst_addr;
	sess->s.con_num = con_num;
	sess->s.recon_cnt = recon_cnt;
	uuid_copy(&sess->s.uuid, uuid);
	spin_lock_init(&sess->state_lock);
	INIT_WORK(&sess->close_work, ibtrs_srv_close_work);
	ibtrs_srv_init_hb(sess);

	sess->s.ib_dev = ibtrs_ib_dev_find_get(cm_id);
	if (unlikely(!sess->s.ib_dev)) {
		err = -ENOMEM;
		ibtrs_wrn(sess, "Failed to alloc ibtrs_device\n");
		goto err_free_con;
	}
	err = map_cont_bufs(sess);
	if (unlikely(err))
		goto err_put_dev;

	err = ibtrs_srv_alloc_ops_ids(sess);
	if (unlikely(err))
		goto err_unmap_bufs;

	__add_path_to_srv(srv, sess);

	return sess;

err_unmap_bufs:
	unmap_cont_bufs(sess);
err_put_dev:
	ibtrs_ib_dev_put(sess->s.ib_dev);
err_free_con:
	kfree(sess->s.con);
err_free_rdma_addr:
	kfree(sess->rdma_addr);
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
	struct ibtrs_srv *srv;

	u16 version, con_num, cid;
	u16 recon_cnt;
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
	con_num = le16_to_cpu(msg->cid_num);
	if (unlikely(con_num > 4096)) {
		/* Sanity check */
		pr_err("Too many connections requested: %d\n", con_num);
		goto reject_w_econnreset;
	}
	cid = le16_to_cpu(msg->cid);
	if (unlikely(cid >= con_num)) {
		/* Sanity check */
		pr_err("Incorrect cid: %d >= %d\n", cid, con_num);
		goto reject_w_econnreset;
	}
	recon_cnt = le16_to_cpu(msg->recon_cnt);
	srv = get_or_create_srv(ctx, &msg->paths_uuid);
	if (unlikely(!srv)) {
		err = -ENOMEM;
		goto reject_w_err;
	}
	mutex_lock(&srv->paths_mutex);
	sess = __find_sess(srv, &msg->sess_uuid);
	if (sess) {
		/* Session already holds a reference */
		put_srv(srv);

		if (unlikely(sess->s.recon_cnt != recon_cnt)) {
			ibtrs_err(sess, "Reconnect detected %d != %d, but "
				  "previous session is still alive, reconnect "
				  "later\n", sess->s.recon_cnt, recon_cnt);
			mutex_unlock(&srv->paths_mutex);
			goto reject_w_ebusy;
		}
		if (unlikely(sess->state != IBTRS_SRV_CONNECTING)) {
			ibtrs_err(sess, "Session in wrong state: %s\n",
				  ibtrs_srv_state_str(sess->state));
			mutex_unlock(&srv->paths_mutex);
			goto reject_w_econnreset;
		}
		/*
		 * Sanity checks
		 */
		if (unlikely(con_num != sess->s.con_num ||
			     cid >= sess->s.con_num)) {
			ibtrs_err(sess, "Incorrect request: %d, %d\n",
				  cid, con_num);
			mutex_unlock(&srv->paths_mutex);
			goto reject_w_econnreset;
		}
		if (unlikely(sess->s.con[cid])) {
			ibtrs_err(sess, "Connection already exists: %d\n",
				  cid);
			mutex_unlock(&srv->paths_mutex);
			goto reject_w_econnreset;
		}
	} else {
		sess = __alloc_sess(srv, cm_id, con_num, recon_cnt,
				    &msg->sess_uuid);
		if (unlikely(IS_ERR(sess))) {
			mutex_unlock(&srv->paths_mutex);
			put_srv(srv);
			err = PTR_ERR(sess);
			goto reject_w_err;
		}
	}
	err = create_con(sess, cm_id, cid);
	if (unlikely(err)) {
		(void)ibtrs_rdma_do_reject(cm_id, err);
		/*
		 * Since session has other connections we follow normal way
		 * thru worqueue, but still return an error to tell cma.c
		 * to call rdma_destroy_id() for current connection.
		 */
		goto close_and_return_err;
	}
	err = ibtrs_rdma_do_accept(sess, cm_id);
	if (unlikely(err)) {
		(void)ibtrs_rdma_do_reject(cm_id, err);
		/*
		 * Since current connection was successfully added to the
		 * session we follow normal way thru workqueue to close the
		 * session, thus return 0 to tell cma.c we call
		 * rdma_destroy_id() ourselves.
		 */
		err = 0;
		goto close_and_return_err;
	}
	mutex_unlock(&srv->paths_mutex);

	return 0;

reject_w_err:
	return ibtrs_rdma_do_reject(cm_id, err);

reject_w_econnreset:
	return ibtrs_rdma_do_reject(cm_id, -ECONNRESET);

reject_w_ebusy:
	return ibtrs_rdma_do_reject(cm_id, -EBUSY);

close_and_return_err:
	close_sess(sess);
	mutex_unlock(&srv->paths_mutex);

	return err;
}

static int ibtrs_srv_rdma_cm_handler(struct rdma_cm_id *cm_id,
				     struct rdma_cm_event *ev)
{
	struct ibtrs_srv_sess *sess = NULL;

	if (ev->event != RDMA_CM_EVENT_CONNECT_REQUEST) {
		struct ibtrs_con *c = cm_id->context;

		sess = to_srv_sess(c->sess);
	}

	switch (ev->event) {
	case RDMA_CM_EVENT_CONNECT_REQUEST:
		/*
		 * In case of error cma.c will destroy cm_id,
		 * see cma_process_remove()
		 */
		return ibtrs_rdma_connect(cm_id, ev->param.conn.private_data,
					  ev->param.conn.private_data_len);
	case RDMA_CM_EVENT_ESTABLISHED:
		/* Nothing here */
		break;
	case RDMA_CM_EVENT_REJECTED:
	case RDMA_CM_EVENT_CONNECT_ERROR:
	case RDMA_CM_EVENT_UNREACHABLE:
		ibtrs_err(sess, "CM error (CM event: %s, err: %d)\n",
			  rdma_event_msg(ev->event), ev->status);
		close_sess(sess);
		break;
	case RDMA_CM_EVENT_DISCONNECTED:
	case RDMA_CM_EVENT_ADDR_CHANGE:
	case RDMA_CM_EVENT_TIMEWAIT_EXIT:
		close_sess(sess);
		break;
	case RDMA_CM_EVENT_DEVICE_REMOVAL:
		close_sess(sess);
		break;
	default:
		pr_err("Ignoring unexpected CM event %s, err %d\n",
		       rdma_event_msg(ev->event), ev->status);
		break;
	}

	return 0;
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
	int ret;

	/*
	 * We accept both IPoIB and IB connections, so we need to keep
	 * two cm id's, one for each socket type and port space.
	 * If the cm initialization of one of the id's fails, we abort
	 * everything.
	 */

	cm_ip = ibtrs_srv_cm_init(ctx, (struct sockaddr *)&sin, RDMA_PS_TCP);
	if (unlikely(IS_ERR(cm_ip)))
	    return PTR_ERR(cm_ip);

	cm_ib = ibtrs_srv_cm_init(ctx, (struct sockaddr *)&sib, RDMA_PS_IB);
	if (unlikely(IS_ERR(cm_ib))) {
		ret = PTR_ERR(cm_ib);
		goto free_cm_ip;
	}

	ctx->cm_id_ip = cm_ip;
	ctx->cm_id_ib = cm_ib;

	return 0;

free_cm_ip:
	rdma_destroy_id(cm_ip);

	return ret;
}

static struct ibtrs_srv_ctx *alloc_srv_ctx(rdma_ev_fn *rdma_ev,
					   link_ev_fn *link_ev)
{
	struct ibtrs_srv_ctx *ctx;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return NULL;

	ctx->rdma_ev = rdma_ev;
	ctx->link_ev = link_ev;
	mutex_init(&ctx->srv_mutex);
	INIT_LIST_HEAD(&ctx->srv_list);

	return ctx;
}

static void free_srv_ctx(struct ibtrs_srv_ctx *ctx)
{
	WARN_ON(!list_empty(&ctx->srv_list));
	kfree(ctx);
}

struct ibtrs_srv_ctx *ibtrs_srv_open(rdma_ev_fn *rdma_ev, link_ev_fn *link_ev,
				     unsigned int port)
{
	struct ibtrs_srv_ctx *ctx;
	int err;

	ctx = alloc_srv_ctx(rdma_ev, link_ev);
	if (unlikely(!ctx))
		return ERR_PTR(-ENOMEM);

	err = ibtrs_srv_rdma_init(ctx, port);
	if (unlikely(err)) {
		free_srv_ctx(ctx);
		return ERR_PTR(err);
	}
	/* Do not let module be unloaded if server context is alive */
	__module_get(THIS_MODULE);

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
					   &old_state))
		queue_work(ibtrs_wq, &sess->close_work);
	WARN_ON(sess->state != IBTRS_SRV_CLOSING);
}

static void close_sessions(struct ibtrs_srv *srv)
{
	struct ibtrs_srv_sess *sess;

	mutex_lock(&srv->paths_mutex);
	list_for_each_entry(sess, &srv->paths_list, s.entry)
		close_sess(sess);
	mutex_unlock(&srv->paths_mutex);
}

static void close_ctx(struct ibtrs_srv_ctx *ctx)
{
	struct ibtrs_srv *srv;

	mutex_lock(&ctx->srv_mutex);
	list_for_each_entry(srv, &ctx->srv_list, ctx_list)
		close_sessions(srv);
	mutex_unlock(&ctx->srv_mutex);
	flush_workqueue(ibtrs_wq);
}

void ibtrs_srv_close(struct ibtrs_srv_ctx *ctx)
{
	rdma_destroy_id(ctx->cm_id_ip);
	rdma_destroy_id(ctx->cm_id_ib);
	close_ctx(ctx);
	free_srv_ctx(ctx);
	module_put(THIS_MODULE);
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

	return 0;
}

static int __init ibtrs_server_init(void)
{
	int err;

	if (!strlen(cq_affinity_list))
		init_cq_affinity();

	pr_info("Loading module %s, version: %s "
		"(retry_count: %d, cq_affinity_list: %s, "
		"max_io_size: %d, sess_queue_depth: %d)\n",
		KBUILD_MODNAME, IBTRS_VER_STRING, retry_count,
		cq_affinity_list, max_io_size, sess_queue_depth);

	err = check_module_params();
	if (err) {
		pr_err("Failed to load module, invalid module parameters,"
		       " err: %d\n", err);
		return err;
	}
	chunk_pool = mempool_create_page_pool(CHUNK_POOL_SIZE,
					      get_order(rcv_buf_size));
	if (unlikely(!chunk_pool)) {
		pr_err("Failed preallocate pool of chunks\n");
		return -ENOMEM;
	}
	ibtrs_wq = alloc_workqueue("ibtrs_server_wq", WQ_MEM_RECLAIM, 0);
	if (!ibtrs_wq) {
		pr_err("Failed to load module, alloc ibtrs_server_wq failed\n");
		goto out_chunk_pool;
	}
	err = ibtrs_srv_create_sysfs_module_files();
	if (err) {
		pr_err("Failed to load module, can't create sysfs files,"
		       " err: %d\n", err);
		goto out_ibtrs_wq;
	}

	return 0;

out_ibtrs_wq:
	destroy_workqueue(ibtrs_wq);
out_chunk_pool:
	mempool_destroy(chunk_pool);

	return err;
}

static void __exit ibtrs_server_exit(void)
{
	ibtrs_srv_destroy_sysfs_module_files();
	destroy_workqueue(ibtrs_wq);
	mempool_destroy(chunk_pool);
}

module_init(ibtrs_server_init);
module_exit(ibtrs_server_exit);
