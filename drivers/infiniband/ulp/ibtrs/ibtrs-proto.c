#define pr_fmt(fmt) KBUILD_MODNAME " L" __stringify(__LINE__) ": " fmt

#include "ibtrs-pri.h"
#include "ibtrs-log.h"

static int
ibtrs_validate_msg_rdma_write(const struct ibtrs_msg_rdma_write *msg)
{
	if (unlikely(le32_to_cpu(msg->hdr.tsize) <= sizeof(*msg))) {
		pr_err("RDMA-Write msg received with invalid length %d"
		       " expected > %lu\n",
		       le32_to_cpu(msg->hdr.tsize), sizeof(*msg));
		return -EINVAL;
	}

	return 0;
}

static int
ibtrs_validate_msg_req_rdma_write(const struct ibtrs_msg_req_rdma_write *msg)
{
	if (unlikely(le32_to_cpu(msg->hdr.tsize) <= sizeof(*msg))) {
		pr_err("Request-RDMA-Write msg request received with invalid"
		       " length %d expected > %lu\n",
		       le32_to_cpu(msg->hdr.tsize), sizeof(*msg));
		return -EINVAL;
	}

	return 0;
}

int ibtrs_validate_message(const struct ibtrs_msg_hdr *hdr)
{
	switch (le16_to_cpu(hdr->type)) {
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
	default:
		pr_err("Received IBTRS message with unknown type\n");
		return -EINVAL;
	}
	return 0;
}
EXPORT_SYMBOL_GPL(ibtrs_validate_message);
