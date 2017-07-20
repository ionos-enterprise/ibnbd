#define pr_fmt(fmt) KBUILD_MODNAME " L" __stringify(__LINE__) ": " fmt

#include <rdma/ibtrs.h>
#include "ibtrs-pri.h"
#include "ibtrs-log.h"

int ibtrs_post_beacon(struct ibtrs_con *con)
{
	struct ib_send_wr *bad_wr;

	return ib_post_send(con->qp, &con->beacon, &bad_wr);
}
EXPORT_SYMBOL_GPL(ibtrs_post_beacon);

int ibtrs_post_send(struct ib_qp *qp, struct ib_mr *mr, struct ibtrs_iu *iu,
		    u32 size)
{
	struct ib_sge list;
	struct ib_send_wr wr, *bad_wr;

	if ((WARN_ON(size == 0)))
		return -EINVAL;

	list.addr   = iu->dma_addr;
	list.length = size;
	list.lkey   = mr->lkey;

	memset(&wr, 0, sizeof(wr));
	wr.next       = NULL;
	wr.wr_cqe     = &iu->cqe;
	wr.sg_list    = &list;
	wr.num_sge    = 1;
	wr.opcode     = IB_WR_SEND;
	wr.send_flags = IB_SEND_SIGNALED;

	return ib_post_send(qp, &wr, &bad_wr);
}
EXPORT_SYMBOL_GPL(ibtrs_post_send);

int ibtrs_post_rdma_write_imm(struct ib_qp *qp, struct ib_cqe *cqe,
			      struct ib_sge *sge, unsigned int num_sge,
			      u32 rkey, u64 rdma_addr, u32 imm_data,
			      enum ib_send_flags flags)
{
	struct ib_send_wr *bad_wr;
	struct ib_rdma_wr wr;
	int i;

	wr.wr.next	  = NULL;
	wr.wr.wr_cqe	  = cqe;
	wr.wr.sg_list	  = sge;
	wr.wr.num_sge	  = num_sge;
	wr.rkey		  = rkey;
	wr.remote_addr	  = rdma_addr;
	wr.wr.opcode	  = IB_WR_RDMA_WRITE_WITH_IMM;
	wr.wr.ex.imm_data = cpu_to_be32(imm_data);
	wr.wr.send_flags  = flags;

	/* if one of the sges has 0 size,, the operation will fail with an
	 * length error
	 */
	for (i = 0; i < num_sge; i++)
		if (WARN_ON(sge[i].length == 0))
			return -EINVAL;

	return ib_post_send(qp, &wr.wr, &bad_wr);
}
EXPORT_SYMBOL_GPL(ibtrs_post_rdma_write_imm);

int ibtrs_post_rdma_write_imm_empty(struct ib_qp *qp, struct ib_cqe *cqe,
				    u32 imm_data, enum ib_send_flags flags)
{
	struct ib_send_wr wr, *bad_wr;

	memset(&wr, 0, sizeof(wr));
	wr.wr_cqe	= cqe;
	wr.send_flags	= flags;
	wr.opcode	= IB_WR_RDMA_WRITE_WITH_IMM;
	wr.ex.imm_data	= cpu_to_be32(imm_data);

	return ib_post_send(qp, &wr, &bad_wr);
}
EXPORT_SYMBOL_GPL(ibtrs_post_rdma_write_imm_empty);

static const char *ib_event_str(enum ib_event_type ev)
{
	switch (ev) {
	case IB_EVENT_CQ_ERR:
		return "IB_EVENT_CQ_ERR";
	case IB_EVENT_QP_FATAL:
		return "IB_EVENT_QP_FATAIL";
	case IB_EVENT_QP_REQ_ERR:
		return "IB_EVENT_QP_REQ_ERR";
	case IB_EVENT_QP_ACCESS_ERR:
		return "IB_EVENT_QP_ACCESS_ERR";
	case IB_EVENT_COMM_EST:
		return "IB_EVENT_COMM_EST";
	case IB_EVENT_SQ_DRAINED:
		return "IB_EVENT_SQ_DRAINED";
	case IB_EVENT_PATH_MIG:
		return "IB_EVENT_PATH_MIG";
	case IB_EVENT_PATH_MIG_ERR:
		return "IB_EVENT_PATH_MIG_ERR";
	case IB_EVENT_DEVICE_FATAL:
		return "IB_EVENT_DEVICE_FATAL";
	case IB_EVENT_PORT_ACTIVE:
		return "IB_EVENT_PORT_ACTIVE";
	case IB_EVENT_PORT_ERR:
		return "IB_EVENT_PORT_ERR";
	case IB_EVENT_LID_CHANGE:
		return "IB_EVENT_LID_CHANGE";
	case IB_EVENT_PKEY_CHANGE:
		return "IB_EVENT_PKEY_CHANGE";
	case IB_EVENT_SM_CHANGE:
		return "IB_EVENT_SM_CHANGE";
	case IB_EVENT_SRQ_ERR:
		return "IB_EVENT_SRQ_ERR";
	case IB_EVENT_SRQ_LIMIT_REACHED:
		return "IB_EVENT_SRQ_LIMIT_REACHED";
	case IB_EVENT_QP_LAST_WQE_REACHED:
		return "IB_EVENT_QP_LAST_WQE_REACHED";
	case IB_EVENT_CLIENT_REREGISTER:
		return "IB_EVENT_CLIENT_REREGISTER";
	case IB_EVENT_GID_CHANGE:
		return "IB_EVENT_GID_CHANGE";
	default:
		return "Unknown IB event";
	}
};

static void qp_event_handler(struct ib_event *ev, void *ctx)
{
	struct ibtrs_con *con = ctx;

	switch (ev->event) {
	case IB_EVENT_COMM_EST:
		ibtrs_info(con, "QP event %s (%d) received\n",
			   ib_event_str(ev->event), ev->event);
		rdma_notify(con->cm_id, IB_EVENT_COMM_EST);
		break;
	default:
		ibtrs_info(con, "Unhandled QP event %s (%d) received\n",
			   ib_event_str(ev->event), ev->event);
		break;
	}
}

int ibtrs_ib_dev_init(struct ibtrs_ib_dev *d, struct ib_device *dev)
{
	d->pd = ib_alloc_pd(dev, IB_PD_UNSAFE_GLOBAL_RKEY);
	if (IS_ERR(d->pd))
		return PTR_ERR(d->pd);
	d->mr = d->pd->__internal_mr;
	d->dev = dev;

	return 0;
}
EXPORT_SYMBOL_GPL(ibtrs_ib_dev_init);

void ibtrs_ib_dev_destroy(struct ibtrs_ib_dev *d)
{
	if (d->pd) {
		ib_dealloc_pd(d->pd);
		d->mr = NULL;
		d->pd = NULL;
		d->dev = NULL;
	}
}
EXPORT_SYMBOL_GPL(ibtrs_ib_dev_destroy);

int ibtrs_request_cq_notifications(struct ibtrs_con *con)
{
	return ib_req_notify_cq(con->cq, IB_CQ_NEXT_COMP |
				IB_CQ_REPORT_MISSED_EVENTS);
}
EXPORT_SYMBOL_GPL(ibtrs_request_cq_notifications);

static int create_cq(struct ibtrs_con *con, struct rdma_cm_id *cm_id,
		     int cq_vector, u16 cq_size, enum ib_poll_context poll_ctx)
{
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

static int create_qp(struct ibtrs_con *con, struct rdma_cm_id *cm_id,
		     struct ib_pd *pd, u16 wr_queue_size, u32 max_send_sge)
{
	struct ib_qp_init_attr init_attr = {NULL};
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
		       struct rdma_cm_id *cm_id, u32 max_send_sge,
		       int cq_vector, u16 cq_size, u16 wr_queue_size,
		       struct ibtrs_ib_dev *ibdev,
		       enum ib_poll_context poll_ctx)
{
	int err, ret;

	err = create_cq(con, cm_id, cq_vector, cq_size, poll_ctx);
	if (unlikely(err))
		return err;

	err = create_qp(con, cm_id, ibdev->pd, wr_queue_size, max_send_sge);
	if (unlikely(err)) {
		ret = ib_destroy_cq(con->cq);
		if (ret)
			ibtrs_err(con, "Destroying CQ failed, err: %d\n", ret);
		return err;
	}
	con->beacon.wr_cqe = &con->beacon_cqe;
	con->beacon.opcode = IB_WR_SEND;
	con->cm_id = cm_id;
	con->sess = sess;

	return 0;
}
EXPORT_SYMBOL_GPL(ibtrs_cq_qp_create);

void ibtrs_cq_qp_destroy(struct ibtrs_con *con)
{
	int err;

	rdma_destroy_qp(con->cm_id);
	err = ib_destroy_cq(con->cq);
	if (err)
		ibtrs_err(con, "Destroying CQ failed, err: %d\n", err);
}
EXPORT_SYMBOL_GPL(ibtrs_cq_qp_destroy);
