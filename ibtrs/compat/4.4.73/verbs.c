/*
 * Copyright (c) 2015 HGST, a Western Digital Company.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 */
#define COMPAT

#include <linux/module.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <rdma/ib_verbs.h>

#include "../compat-4.4.73.h"

/* # of WCs to poll for with a single call to ib_poll_cq */
#define IB_POLL_BATCH			16

/* # of WCs to iterate over before yielding */
#define IB_POLL_BUDGET_IRQ		256
#define IB_POLL_BUDGET_WORKQUEUE	65536

#define IB_POLL_FLAGS \
	(IB_CQ_NEXT_COMP | IB_CQ_REPORT_MISSED_EVENTS)

extern struct workqueue_struct *ib_comp_wq;

static int __ib_process_cq(struct backport_ib_cq *bcq, int budget)
{
	int i, n, completed = 0;

	/*
	 * budget might be (-1) if the caller does not
	 * want to bound this call, thus we need unsigned
	 * minimum here.
	 */
	while ((n = ib_poll_cq(bcq->cq, min_t(u32, IB_POLL_BATCH,
	      budget - completed), (struct ib_wc *)bcq->wc)) > 0) {
		for (i = 0; i < n; i++) {
			struct backport_ib_wc *wc = &bcq->wc[i];

			if (wc->wr_cqe)
				wc->wr_cqe->done(bcq, wc);
			else
				WARN_ON_ONCE(wc->status == IB_WC_SUCCESS);
		}

		completed += n;

		if (n != IB_POLL_BATCH ||
		    (budget != -1 && completed >= budget))
			break;
	}

	return completed;
}

/**
 * ib_process_direct_cq - process a CQ in caller context
 * @cq:		CQ to process
 * @budget:	number of CQEs to poll for
 *
 * This function is used to process all outstanding CQ entries on a
 * %IB_POLL_DIRECT CQ.  It does not offload CQ processing to a different
 * context and does not ask for completion interrupts from the HCA.
 *
 * Note: do not pass -1 as %budget unless it is guaranteed that the number
 * of completions that will be processed is small.
 */
int ib_process_cq_direct(struct backport_ib_cq *bcq, int budget)
{
	WARN_ON_ONCE(bcq->poll_ctx != IB_POLL_DIRECT);

	return __ib_process_cq(bcq, budget);
}
EXPORT_SYMBOL(ib_process_cq_direct);

static void ib_cq_completion_direct(struct ib_cq *cq, void *private)
{
	WARN_ONCE(1, "got unsolicited completion for CQ 0x%p\n", cq);
}

static int ib_poll_handler(struct irq_poll *iop, int budget)
{
	struct backport_ib_cq *bcq;
	int completed;

	bcq = container_of(iop, struct backport_ib_cq, iop);
	completed = __ib_process_cq(bcq, budget);
	if (completed < budget) {
		irq_poll_complete(&bcq->iop);
		if (ib_req_notify_cq(bcq->cq, IB_POLL_FLAGS) > 0)
			irq_poll_sched(&bcq->iop);
	}

	return completed;
}

static void ib_cq_completion_softirq(struct ib_cq *cq, void *private)
{
	struct backport_ib_cq *bcq = private;

	irq_poll_sched(&bcq->iop);
}

static void ib_cq_poll_work(struct work_struct *work)
{
	struct backport_ib_cq *bcq;
	int completed;

	bcq = container_of(work, struct backport_ib_cq, work);
	completed = __ib_process_cq(bcq, IB_POLL_BUDGET_WORKQUEUE);
	if (completed >= IB_POLL_BUDGET_WORKQUEUE ||
	    ib_req_notify_cq(bcq->cq, IB_POLL_FLAGS) > 0)
		queue_work(ib_comp_wq, &bcq->work);
}

static void ib_cq_completion_workqueue(struct ib_cq *cq, void *private)
{
	struct backport_ib_cq *bcq = private;

	queue_work(ib_comp_wq, &bcq->work);
}

/**
 * ib_alloc_cq - allocate a completion queue
 * @dev:		device to allocate the CQ for
 * @private:		driver private data, accessible from cq->cq_context
 * @nr_cqe:		number of CQEs to allocate
 * @comp_vector:	HCA completion vectors for this CQ
 * @poll_ctx:		context to poll the CQ from.
 *
 * This is the proper interface to allocate a CQ for in-kernel users. A
 * CQ allocated with this interface will automatically be polled from the
 * specified context. The ULP must use wr->wr_cqe instead of wr->wr_id
 * to use this CQ abstraction.
 */
struct backport_ib_cq *ib_alloc_cq(struct ib_device *dev, void *private,
		int nr_cqe, int comp_vector, enum ib_poll_context poll_ctx)
{
	ib_comp_handler comp_handler;
	struct backport_ib_cq *bcq;
	struct ib_cq *cq;
	int ret = -ENOMEM;

	bcq = kzalloc(sizeof(*bcq), GFP_KERNEL);
	if (unlikely(!bcq))
		return ERR_PTR(ret);

	bcq->cq_context = private;
	bcq->poll_ctx = poll_ctx;
	bcq->wc = kmalloc_array(IB_POLL_BATCH, sizeof(*bcq->wc), GFP_KERNEL);
	if (unlikely(!bcq->wc))
		goto out_free_bcq;

	switch (poll_ctx) {
	case IB_POLL_DIRECT:
		comp_handler = ib_cq_completion_direct;
		break;
	case IB_POLL_SOFTIRQ:
		comp_handler = ib_cq_completion_softirq;
		irq_poll_init(&bcq->iop, IB_POLL_BUDGET_IRQ, ib_poll_handler);
		break;
	case IB_POLL_WORKQUEUE:
		comp_handler = ib_cq_completion_workqueue;
		INIT_WORK(&bcq->work, ib_cq_poll_work);
		break;
	default:
		ret = -EINVAL;
		goto out_free_wc;
	}

	cq = ib_create_cq(dev, comp_handler, NULL, bcq, nr_cqe, comp_vector);
	if (unlikely(IS_ERR(cq)))
		goto out_free_wc;

	bcq->cq = cq;

	switch (poll_ctx) {
	case IB_POLL_SOFTIRQ:
	case IB_POLL_WORKQUEUE:
		ib_req_notify_cq(cq, IB_CQ_NEXT_COMP);
		break;
	default:
		break;
	}

	return bcq;

out_free_wc:
	kfree(bcq->wc);
out_free_bcq:
	kfree(bcq);

	return ERR_PTR(ret);
}
EXPORT_SYMBOL(ib_alloc_cq);

/**
 * ib_free_cq - free a completion queue
 * @cq:		completion queue to free.
 */
void ib_free_cq(struct backport_ib_cq *bcq)
{
	switch (bcq->poll_ctx) {
	case IB_POLL_DIRECT:
		break;
	case IB_POLL_SOFTIRQ:
		irq_poll_disable(&bcq->iop);
		break;
	case IB_POLL_WORKQUEUE:
		cancel_work_sync(&bcq->work);
		break;
	default:
		WARN_ON_ONCE(1);
	}

	ib_destroy_cq(bcq->cq);
	kfree(bcq->wc);
	kfree(bcq);
}
EXPORT_SYMBOL(ib_free_cq);

struct ib_drain_cqe {
	struct ib_cqe cqe;
	struct completion done;
};

static void ib_drain_qp_done(struct backport_ib_cq *cq,
			     struct backport_ib_wc *wc)
{
	struct ib_drain_cqe *cqe = container_of(wc->wr_cqe, struct ib_drain_cqe,
						cqe);

	complete(&cqe->done);
}

/*
 * Post a WR and block until its completion is reaped for the SQ.
 */
static void __ib_drain_sq(struct ib_qp *qp)
{
	struct ib_cq *cq = qp->send_cq;
	struct ib_qp_attr attr = { .qp_state = IB_QPS_ERR };
	struct ib_drain_cqe sdrain;
	struct backport_ib_send_wr swr = {}, *bad_swr;
	struct backport_ib_cq *bcq;
	int ret;

	bcq = cq->cq_context;
	swr.wr_cqe = &sdrain.cqe;
	sdrain.cqe.done = ib_drain_qp_done;
	init_completion(&sdrain.done);

	ret = ib_modify_qp(qp, &attr, IB_QP_STATE);
	if (ret) {
		WARN_ONCE(ret, "failed to drain send queue: %d\n", ret);
		return;
	}

	ret = ib_post_send(qp, (struct ib_send_wr *)&swr,
			   (struct ib_send_wr **)&bad_swr);
	if (ret) {
		WARN_ONCE(ret, "failed to drain send queue: %d\n", ret);
		return;
	}

	if (bcq->poll_ctx == IB_POLL_DIRECT)
		while (wait_for_completion_timeout(&sdrain.done, HZ / 10) <= 0)
			ib_process_cq_direct(bcq, -1);
	else
		wait_for_completion(&sdrain.done);
}

/*
 * Post a WR and block until its completion is reaped for the RQ.
 */
static void __ib_drain_rq(struct ib_qp *qp)
{
	struct ib_cq *cq = qp->recv_cq;
	struct ib_qp_attr attr = { .qp_state = IB_QPS_ERR };
	struct ib_drain_cqe rdrain;
	struct backport_ib_recv_wr rwr = {}, *bad_rwr;
	struct backport_ib_cq *bcq;
	int ret;

	bcq = cq->cq_context;
	rwr.wr_cqe = &rdrain.cqe;
	rdrain.cqe.done = ib_drain_qp_done;
	init_completion(&rdrain.done);

	ret = ib_modify_qp(qp, &attr, IB_QP_STATE);
	if (ret) {
		WARN_ONCE(ret, "failed to drain recv queue: %d\n", ret);
		return;
	}

	ret = ib_post_recv(qp, (struct ib_recv_wr *)&rwr,
			   (struct ib_recv_wr **)&bad_rwr);
	if (ret) {
		WARN_ONCE(ret, "failed to drain recv queue: %d\n", ret);
		return;
	}

	if (bcq->poll_ctx == IB_POLL_DIRECT)
		while (wait_for_completion_timeout(&rdrain.done, HZ / 10) <= 0)
			ib_process_cq_direct(bcq, -1);
	else
		wait_for_completion(&rdrain.done);
}

/**
 * ib_drain_sq() - Block until all SQ CQEs have been consumed by the
 *		   application.
 * @qp:            queue pair to drain
 *
 * If the device has a provider-specific drain function, then
 * call that.  Otherwise call the generic drain function
 * __ib_drain_sq().
 *
 * The caller must:
 *
 * ensure there is room in the CQ and SQ for the drain work request and
 * completion.
 *
 * allocate the CQ using ib_alloc_cq().
 *
 * ensure that there are no other contexts that are posting WRs concurrently.
 * Otherwise the drain is not guaranteed.
 */
void ib_drain_sq(struct ib_qp *qp)
{
	__ib_drain_sq(qp);
}
EXPORT_SYMBOL(ib_drain_sq);

/**
 * ib_drain_rq() - Block until all RQ CQEs have been consumed by the
 *		   application.
 * @qp:            queue pair to drain
 *
 * If the device has a provider-specific drain function, then
 * call that.  Otherwise call the generic drain function
 * __ib_drain_rq().
 *
 * The caller must:
 *
 * ensure there is room in the CQ and RQ for the drain work request and
 * completion.
 *
 * allocate the CQ using ib_alloc_cq().
 *
 * ensure that there are no other contexts that are posting WRs concurrently.
 * Otherwise the drain is not guaranteed.
 */
void ib_drain_rq(struct ib_qp *qp)
{
	__ib_drain_rq(qp);
}
EXPORT_SYMBOL(ib_drain_rq);

/**
 * ib_drain_qp() - Block until all CQEs have been consumed by the
 *		   application on both the RQ and SQ.
 * @qp:            queue pair to drain
 *
 * The caller must:
 *
 * ensure there is room in the CQ(s), SQ, and RQ for drain work requests
 * and completions.
 *
 * allocate the CQs using ib_alloc_cq().
 *
 * ensure that there are no other contexts that are posting WRs concurrently.
 * Otherwise the drain is not guaranteed.
 */
void ib_drain_qp(struct ib_qp *qp)
{
	ib_drain_sq(qp);
	if (!qp->srq)
		ib_drain_rq(qp);
}
EXPORT_SYMBOL(ib_drain_qp);
