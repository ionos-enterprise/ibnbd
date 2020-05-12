#define pr_fmt(fmt) KBUILD_MODNAME " L" __stringify(__LINE__) ": " fmt

#include <rdma/ibtrs.h>
#include "ibtrs-pri.h"
#include "ibtrs-log.h"

int ibtrs_write_empty_imm(struct ib_qp *qp, u32 imm_data,
			  enum ib_send_flags flags)
{
	struct ib_send_wr wr, *bad_wr;

	memset(&wr, 0, sizeof(wr));
	wr.send_flags	= flags;
	wr.opcode	= IB_WR_RDMA_WRITE_WITH_IMM;
	wr.ex.imm_data	= cpu_to_be32(imm_data);

	return ib_post_send(qp, &wr, &bad_wr);
}
EXPORT_SYMBOL_GPL(ibtrs_write_empty_imm);

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

static int post_rdma_write(struct ib_qp *qp, struct ib_cqe *cqe,
			   struct ib_sge *sge, size_t num_sge,
			   u32 rkey, u64 rdma_addr, u32 imm_data,
			   enum ib_wr_opcode opcode, enum ib_send_flags flags)
{
	struct ib_send_wr *bad_wr;
	struct ib_rdma_wr wr;
	int i;

	wr.wr.next	= NULL;
	wr.wr.wr_cqe	= cqe;
	wr.wr.sg_list	= sge;
	wr.wr.num_sge	= num_sge;
	wr.rkey		= rkey;
	wr.remote_addr	= rdma_addr;
	wr.wr.opcode	  = opcode;
	wr.wr.ex.imm_data = cpu_to_be32(imm_data);
	wr.wr.send_flags = flags;

	/* if one of the sges has 0 size,, the operation will fail with an
	 * length error
	 */
	for (i = 0; i < num_sge; i++)
		if (WARN_ON(sge[i].length == 0))
			return -EINVAL;

	return ib_post_send(qp, &wr.wr, &bad_wr);
}

int ib_post_rdma_write_imm(struct ib_qp *qp, struct ib_cqe *cqe,
			   struct ib_sge *sge, unsigned int num_sge,
			   u32 rkey, u64 rdma_addr, u32 imm_data,
			   enum ib_send_flags flags)
{
	return post_rdma_write(qp, cqe, sge, num_sge, rkey, rdma_addr,
			       imm_data, IB_WR_RDMA_WRITE_WITH_IMM, flags);
}
EXPORT_SYMBOL_GPL(ib_post_rdma_write_imm);

/* TODO delete */
int ib_get_max_wr_queue_size(struct ib_device *dev)
{
	struct ib_device_attr *attr = &dev->attrs;

	return attr->max_qp_wr;
}
EXPORT_SYMBOL_GPL(ib_get_max_wr_queue_size);

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

int ib_session_init(struct ib_device *dev, struct ib_session *s)
{
	s->pd = ib_alloc_pd(dev, IB_PD_UNSAFE_GLOBAL_RKEY);
	if (IS_ERR(s->pd))
		return PTR_ERR(s->pd);

	s->mr = s->pd->__internal_mr;

	return 0;
}
EXPORT_SYMBOL_GPL(ib_session_init);

static int init_cq(struct ibtrs_con *con, struct rdma_cm_id *cm_id,
		   int cq_vector, u16 cq_size, enum ib_poll_context poll_ctx)
{
	con->cq = ib_alloc_cq(cm_id->device, con, cq_size * 2 + 1,
			      cq_vector, poll_ctx);
	if (IS_ERR(con->cq)) {
		ibtrs_err(con, "Creating completion queue failed, errno: %ld\n",
			  PTR_ERR(con->cq));
		return PTR_ERR(con->cq);
	}

	return 0;
}

int ibtrs_request_cq_notifications(struct ibtrs_con *con)
{
	return ib_req_notify_cq(con->cq, IB_CQ_NEXT_COMP |
				IB_CQ_REPORT_MISSED_EVENTS);
}
EXPORT_SYMBOL_GPL(ibtrs_request_cq_notifications);

void ibtrs_con_destroy(struct ibtrs_con *con)
{
	int err;

	err = ib_destroy_qp(con->qp);
	if (err)
		ibtrs_err(con, "Destroying QP failed, err: %d\n", err);

	err = ib_destroy_cq(con->cq);
	if (err)
		ibtrs_err(con, "Destroying CQ failed, err: %d\n", err);
}
EXPORT_SYMBOL_GPL(ibtrs_con_destroy);

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
	if (ret) {
		ibtrs_err(con, "Creating QP failed, err: %d\n", ret);
		return ret;
	}
	con->qp = cm_id->qp;

	return ret;
}

int post_beacon(struct ibtrs_con *con)
{
	struct ib_send_wr *bad_wr;

	return ib_post_send(con->qp, &con->beacon, &bad_wr);
}
EXPORT_SYMBOL_GPL(post_beacon);

int ibtrs_con_init(struct ibtrs_sess *ibtrs_sess, struct ibtrs_con *con,
		   struct rdma_cm_id *cm_id, u32 max_send_sge, int cq_vector,
		   u16 cq_size, u16 wr_queue_size, struct ib_session *session,
		   enum ib_poll_context poll_ctx)
{
	int err, ret;

	err = init_cq(con, cm_id, cq_vector, cq_size, poll_ctx);
	if (err)
		return err;

	err = create_qp(con, cm_id, session->pd, wr_queue_size, max_send_sge);
	if (err) {
		ret = ib_destroy_cq(con->cq);
		if (ret)
			ibtrs_err(con, "Destroying CQ failed, err: %d\n", ret);
		return err;
	}
	con->beacon.wr_cqe = &con->beacon_cqe;
	con->beacon.opcode = IB_WR_SEND;
	con->cm_id = cm_id;
	con->sess = ibtrs_sess;

	return 0;
}
EXPORT_SYMBOL_GPL(ibtrs_con_init);

void ib_session_destroy(struct ib_session *session)
{
	if (session->pd) {
		ib_dealloc_pd(session->pd);
		session->pd = NULL;
	}
}
EXPORT_SYMBOL_GPL(ib_session_destroy);
