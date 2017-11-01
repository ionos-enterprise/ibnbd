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
#include <rdma/ibtrs.h>
#include "ibtrs-pri.h"
#include "ibtrs-log.h"

MODULE_AUTHOR("ibnbd@profitbricks.com");
MODULE_DESCRIPTION("IBTRS Core");
MODULE_VERSION(IBTRS_VER_STRING);
MODULE_LICENSE("GPL");

static LIST_HEAD(device_list);
static DEFINE_MUTEX(device_list_mutex);

int ibtrs_iu_post_recv(struct ibtrs_con *con, struct ibtrs_iu *iu)
{
	struct ibtrs_sess *sess = con->sess;
	struct ib_recv_wr wr, *bad_wr;
	struct ib_sge list;

	list.addr   = iu->dma_addr;
	list.length = iu->size;
	list.lkey   = sess->ib_dev->pd->local_dma_lkey;

	if (WARN_ON(list.length == 0)) {
		ibtrs_wrn(con, "Posting receive work request failed,"
			  " sg list is empty\n");
		return -EINVAL;
	}

	wr.next    = NULL;
	wr.wr_cqe  = &iu->cqe;
	wr.sg_list = &list;
	wr.num_sge = 1;

	return ib_post_recv(con->qp, &wr, &bad_wr);
}
EXPORT_SYMBOL_GPL(ibtrs_iu_post_recv);

int ibtrs_post_recv_empty(struct ibtrs_con *con, struct ib_cqe *cqe)
{
	struct ib_recv_wr wr, *bad_wr;

	wr.next    = NULL;
	wr.wr_cqe  = cqe;
	wr.sg_list = NULL;
	wr.num_sge = 0;

	return ib_post_recv(con->qp, &wr, &bad_wr);
}
EXPORT_SYMBOL_GPL(ibtrs_post_recv_empty);

int ibtrs_iu_post_send(struct ibtrs_con *con, struct ibtrs_iu *iu, size_t size)
{
	struct ibtrs_sess *sess = con->sess;
	struct ib_send_wr wr, *bad_wr;
	struct ib_sge list;

	if ((WARN_ON(size == 0)))
		return -EINVAL;

	list.addr   = iu->dma_addr;
	list.length = size;
	list.lkey   = sess->ib_dev->mr->lkey;

	memset(&wr, 0, sizeof(wr));
	wr.next       = NULL;
	wr.wr_cqe     = &iu->cqe;
	wr.sg_list    = &list;
	wr.num_sge    = 1;
	wr.opcode     = IB_WR_SEND;
	wr.send_flags = IB_SEND_SIGNALED;

	return ib_post_send(con->qp, &wr, &bad_wr);
}
EXPORT_SYMBOL_GPL(ibtrs_iu_post_send);

int ibtrs_iu_post_rdma_write_imm(struct ibtrs_con *con, struct ibtrs_iu *iu,
				 struct ib_sge *sge, unsigned int num_sge,
				 u32 rkey, u64 rdma_addr, u32 imm_data,
				 enum ib_send_flags flags)
{
	struct ib_send_wr *bad_wr;
	struct ib_rdma_wr wr;
	int i;

	wr.wr.next	  = NULL;
	wr.wr.wr_cqe	  = &iu->cqe;
	wr.wr.sg_list	  = sge;
	wr.wr.num_sge	  = num_sge;
	wr.rkey		  = rkey;
	wr.remote_addr	  = rdma_addr;
	wr.wr.opcode	  = IB_WR_RDMA_WRITE_WITH_IMM;
	wr.wr.ex.imm_data = cpu_to_be32(imm_data);
	wr.wr.send_flags  = flags;

	/*
	 * If one of the sges has 0 size, the operation will fail with an
	 * length error
	 */
	for (i = 0; i < num_sge; i++)
		if (WARN_ON(sge[i].length == 0))
			return -EINVAL;

	return ib_post_send(con->qp, &wr.wr, &bad_wr);
}
EXPORT_SYMBOL_GPL(ibtrs_iu_post_rdma_write_imm);

int ibtrs_post_rdma_write_imm_empty(struct ibtrs_con *con, struct ib_cqe *cqe,
				    u32 imm_data, enum ib_send_flags flags)
{
	struct ib_send_wr wr, *bad_wr;

	memset(&wr, 0, sizeof(wr));
	wr.wr_cqe	= cqe;
	wr.send_flags	= flags;
	wr.opcode	= IB_WR_RDMA_WRITE_WITH_IMM;
	wr.ex.imm_data	= cpu_to_be32(imm_data);

	return ib_post_send(con->qp, &wr, &bad_wr);
}
EXPORT_SYMBOL_GPL(ibtrs_post_rdma_write_imm_empty);

static void qp_event_handler(struct ib_event *ev, void *ctx)
{
	struct ibtrs_con *con = ctx;

	switch (ev->event) {
	case IB_EVENT_COMM_EST:
		ibtrs_info(con, "QP event %s (%d) received\n",
			   ib_event_msg(ev->event), ev->event);
		rdma_notify(con->cm_id, IB_EVENT_COMM_EST);
		break;
	default:
		ibtrs_info(con, "Unhandled QP event %s (%d) received\n",
			   ib_event_msg(ev->event), ev->event);
		break;
	}
}

static int ibtrs_ib_dev_init(struct ibtrs_ib_dev *d, struct ib_device *dev)
{
	d->pd = ib_alloc_pd(dev, IB_PD_UNSAFE_GLOBAL_RKEY);
	if (IS_ERR(d->pd))
		return PTR_ERR(d->pd);
	d->mr = d->pd->__internal_mr;
	d->dev = dev;

	return 0;
}

static void ibtrs_ib_dev_destroy(struct ibtrs_ib_dev *d)
{
	if (d->pd) {
		ib_dealloc_pd(d->pd);
		d->mr = NULL;
		d->pd = NULL;
		d->dev = NULL;
	}
}

struct ibtrs_ib_dev *ibtrs_ib_dev_find_get(struct rdma_cm_id *cm_id)
{
	struct ibtrs_ib_dev *dev;
	int err;

	mutex_lock(&device_list_mutex);
	list_for_each_entry(dev, &device_list, entry) {
		if (dev->dev->node_guid == cm_id->device->node_guid &&
		    kref_get_unless_zero(&dev->ref))
			goto out_unlock;
	}
	dev = kzalloc(sizeof(*dev), GFP_KERNEL);
	if (unlikely(!dev))
		goto out_err;

	kref_init(&dev->ref);
	err = ibtrs_ib_dev_init(dev, cm_id->device);
	if (unlikely(err))
		goto out_free;
	list_add(&dev->entry, &device_list);
out_unlock:
	mutex_unlock(&device_list_mutex);

	return dev;

out_free:
	kfree(dev);
out_err:
	mutex_unlock(&device_list_mutex);

	return NULL;
}
EXPORT_SYMBOL_GPL(ibtrs_ib_dev_find_get);

static void ibtrs_ib_dev_free(struct kref *ref)
{
	struct ibtrs_ib_dev *dev;

	dev = container_of(ref, struct ibtrs_ib_dev, ref);

	mutex_lock(&device_list_mutex);
	list_del(&dev->entry);
	mutex_unlock(&device_list_mutex);
	ibtrs_ib_dev_destroy(dev);
	kfree(dev);
}

void ibtrs_ib_dev_put(struct ibtrs_ib_dev *dev)
{
	kref_put(&dev->ref, ibtrs_ib_dev_free);
}
EXPORT_SYMBOL_GPL(ibtrs_ib_dev_put);

static int create_cq(struct ibtrs_con *con, int cq_vector, u16 cq_size,
		     enum ib_poll_context poll_ctx)
{
	struct rdma_cm_id *cm_id = con->cm_id;
	struct ib_cq *cq;

	cq = ib_alloc_cq(cm_id->device, con, cq_size * 2 + 1,
			 cq_vector, poll_ctx);
	if (unlikely(IS_ERR(cq))) {
		ibtrs_err(con, "Creating completion queue failed, errno: %ld\n",
			  PTR_ERR(cq));
		return PTR_ERR(cq);
	}
	con->cq = cq;

	return 0;
}

static int create_qp(struct ibtrs_con *con, struct ib_pd *pd,
		     u16 wr_queue_size, u32 max_send_sge)
{
	struct ib_qp_init_attr init_attr = {NULL};
	struct rdma_cm_id *cm_id = con->cm_id;
	int ret;

	init_attr.cap.max_send_wr = wr_queue_size + 1;/*1 more for beacon*/
	init_attr.cap.max_recv_wr = wr_queue_size;
	init_attr.cap.max_recv_sge = 2;
	init_attr.event_handler = qp_event_handler;
	init_attr.qp_context = con;
	init_attr.cap.max_send_sge = max_send_sge;

	init_attr.qp_type = IB_QPT_RC;
	init_attr.send_cq = con->cq;
	init_attr.recv_cq = con->cq;
	init_attr.sq_sig_type = IB_SIGNAL_REQ_WR;

	ret = rdma_create_qp(cm_id, pd, &init_attr);
	if (unlikely(ret)) {
		ibtrs_err(con, "Creating QP failed, err: %d\n", ret);
		return ret;
	}
	con->qp = cm_id->qp;

	return ret;
}

int ibtrs_cq_qp_create(struct ibtrs_sess *sess, struct ibtrs_con *con,
		       u32 max_send_sge, int cq_vector, u16 cq_size,
		       u16 wr_queue_size, enum ib_poll_context poll_ctx)
{
	int err;

	err = create_cq(con, cq_vector, cq_size, poll_ctx);
	if (unlikely(err))
		return err;

	err = create_qp(con, sess->ib_dev->pd, wr_queue_size, max_send_sge);
	if (unlikely(err)) {
		ib_free_cq(con->cq);
		con->cq = NULL;
		return err;
	}
	con->sess = sess;

	return 0;
}
EXPORT_SYMBOL_GPL(ibtrs_cq_qp_create);

void ibtrs_cq_qp_destroy(struct ibtrs_con *con)
{
	if (con->cm_id->qp)
		rdma_destroy_qp(con->cm_id);
	if (con->cq)
		ib_free_cq(con->cq);
}
EXPORT_SYMBOL_GPL(ibtrs_cq_qp_destroy);

static void schedule_hb(struct ibtrs_sess *sess)
{
	schedule_delayed_work(&sess->hb_dwork,
			      msecs_to_jiffies(sess->hb_timeout_ms));
}

static void hb_work(struct work_struct *work)
{
	struct ibtrs_sess *sess;
	int err;

	sess = container_of(to_delayed_work(work), typeof(*sess), hb_dwork);
	err = ibtrs_post_rdma_write_imm_empty(sess->hb_con,
					      sess->hb_cqe,
					      IBTRS_HB_IMM,
					      IB_SEND_SIGNALED);
	if (unlikely(err)) {
		sess->hb_err_handler(sess->hb_con, err);
		return;
	}

	schedule_hb(sess);
}

void ibtrs_start_hb(struct ibtrs_con *con, struct ib_cqe *cqe,
		    unsigned timeout_ms, ibtrs_hb_handler_t *err_handler)
{
	struct ibtrs_sess *sess = con->sess;

	sess->hb_con = con;
	sess->hb_cqe = cqe;
	sess->hb_timeout_ms = timeout_ms;
	sess->hb_err_handler = err_handler;
	INIT_DELAYED_WORK(&sess->hb_dwork, hb_work);
	schedule_hb(sess);
}
EXPORT_SYMBOL_GPL(ibtrs_start_hb);

void ibtrs_stop_hb(struct ibtrs_sess *sess)
{
	cancel_delayed_work_sync(&sess->hb_dwork);
	sess->hb_con = NULL;
	sess->hb_cqe = NULL;
	sess->hb_timeout_ms = 0;
	sess->hb_err_handler = NULL;
}
EXPORT_SYMBOL_GPL(ibtrs_stop_hb);
