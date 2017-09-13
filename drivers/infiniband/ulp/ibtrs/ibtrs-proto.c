#define pr_fmt(fmt) KBUILD_MODNAME " L" __stringify(__LINE__) ": " fmt

#include "ibtrs-pri.h"
#include "ibtrs-log.h"

static int
ibtrs_validate_msg_user(const struct ibtrs_msg_user *msg)
{
	/* keep as place holder */
	return 0;
}

static int
ibtrs_validate_msg_rdma_write(const struct ibtrs_msg_rdma_write *msg)
{
	if (unlikely(msg->hdr.tsize <= sizeof(*msg))) {
		pr_err("RDMA-Write msg received with invalid length %d"
		       " expected > %lu\n", msg->hdr.tsize, sizeof(*msg));
		return -EINVAL;
	}

	return 0;
}

static int
ibtrs_validate_msg_req_rdma_write(const struct ibtrs_msg_req_rdma_write *msg)
{
	if (unlikely(msg->hdr.tsize <= sizeof(*msg))) {
		pr_err("Request-RDMA-Write msg request received with invalid"
		       " length %d expected > %lu\n", msg->hdr.tsize,
		       sizeof(*msg));
		return -EINVAL;
	}

	return 0;
}

int ibtrs_validate_message(const struct ibtrs_msg_hdr *hdr)
{
	switch (hdr->type) {
	case IBTRS_MSG_RDMA_WRITE: {
		const struct ibtrs_msg_rdma_write *msg;

		msg = container_of(hdr, typeof(*msg), hdr);
		return ibtrs_validate_msg_rdma_write(msg);
	}
	case IBTRS_MSG_REQ_RDMA_WRITE: {
		const struct ibtrs_msg_req_rdma_write *req;

		req = container_of(hdr, typeof(*req), hdr);
		return ibtrs_validate_msg_req_rdma_write(req);
	}
	case IBTRS_MSG_USER: {
		const struct ibtrs_msg_user *msg;

		msg = container_of(hdr, typeof(*msg), hdr);
		return ibtrs_validate_msg_user(msg);
	}
	default:
		pr_err("Received IBTRS message with unknown type\n");
		return -EINVAL;
	}
	return 0;
}
EXPORT_SYMBOL_GPL(ibtrs_validate_message);
