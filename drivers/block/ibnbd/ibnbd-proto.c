#define pr_fmt(fmt) KBUILD_MODNAME " L" __stringify(__LINE__) ": " fmt

#include "ibnbd-proto.h"

static int ibnbd_validate_msg_sess_info(const struct ibnbd_msg_sess_info *msg,
					size_t len)
{
	if (unlikely(len != sizeof(*msg))) {
		pr_err("Sess info message with unexpected length received"
		       " %lu instead of %lu\n", len, sizeof(*msg));
		return -EINVAL;
	}

	return 0;
}

static int
ibnbd_validate_msg_sess_info_rsp(const struct ibnbd_msg_sess_info_rsp *msg,
				 size_t len)
{
	if (unlikely(len != sizeof(*msg))) {
		pr_err("Sess info message with unexpected length received"
		       " %lu instead of %lu\n", len, sizeof(*msg));
		return -EINVAL;
	}

	return 0;
}

static int ibnbd_validate_msg_open_resp(const struct ibnbd_msg_open_rsp *msg,
					size_t len)
{
	if (unlikely(msg->result))
		return 0;

	if (unlikely(len != sizeof(*msg))) {
		pr_err("Open Response msg received with unexpected length"
		       " %zuB instead of %luB\n", len, sizeof(*msg));
		return -EINVAL;
	}

	if (unlikely(!msg->logical_block_size)) {
		pr_err("Open Resp msg received with unexpected with"
		       " invalid logical_block_size value %d\n",
		       msg->logical_block_size);
		return -EINVAL;
	}

	if (unlikely(!msg->physical_block_size)) {
		pr_err("Open Resp msg received with invalid"
		       " physical_block_size value %d\n",
		       msg->physical_block_size);
		return -EINVAL;
	}

	if (unlikely(!msg->max_hw_sectors)) {
		pr_err("Open Resp msg received with invalid"
		       " max_hw_sectors value %d\n", msg->max_hw_sectors);
		return -EINVAL;
	}

	return 0;
}

static int ibnbd_validate_msg_revalidate(const struct ibnbd_msg_revalidate *msg,
					 size_t len)
{
	if (unlikely(len != sizeof(*msg))) {
		pr_err("Device resize message with unexpected length received"
		       " %lu instead of %lu\n", len, sizeof(*msg));
		return -EINVAL;
	}

	return 0;
}

static int ibnbd_validate_msg_open(const struct ibnbd_msg_open *msg,
				   size_t len)
{
	if (len != sizeof(*msg)) {
		pr_err("Open msg received with unexpected length"
		       " %zuB instead of %luB\n", len, sizeof(*msg));
		return -EINVAL;
	}
	if (msg->dev_name[strnlen(msg->dev_name, NAME_MAX)] != '\0') {
		pr_err("Open msg received with invalid dev_name value,"
		       " null terminator missing\n");
		return -EINVAL;
	}

	if (unlikely(msg->access_mode != IBNBD_ACCESS_RO &&
		     msg->access_mode != IBNBD_ACCESS_RW &&
		     msg->access_mode != IBNBD_ACCESS_MIGRATION)) {
		pr_err("Open msg received with invalid access_mode value %d\n",
		       msg->access_mode);
		return -EINVAL;
	}

	return 0;
}

static int ibnbd_validate_msg_close(const struct ibnbd_msg_close *msg, size_t
				    len)
{
	if (unlikely(len != sizeof(*msg))) {
		pr_err("Close msg received with unexpected length %lu instead"
		       " of %lu\n", len, sizeof(*msg));
		return -EINVAL;
	}

	return 0;
}

static int ibnbd_validate_msg_close_rsp(const struct ibnbd_msg_close_rsp *msg,
					size_t len)
{
	if (unlikely(len != sizeof(*msg))) {
		pr_err("Close_rsp msg received with unexpected length %lu"
		       " instead of %lu\n", len, sizeof(*msg));
		return -EINVAL;
	}

	return 0;
}

int ibnbd_validate_message(const void *data, size_t len)
{
	const struct ibnbd_msg_hdr *hdr = data;

	switch (hdr->type) {
	case IBNBD_MSG_SESS_INFO: {
		const struct ibnbd_msg_sess_info *msg = data;

		return ibnbd_validate_msg_sess_info(msg, len);
	}
	case IBNBD_MSG_SESS_INFO_RSP: {
		const struct ibnbd_msg_sess_info_rsp *msg = data;

		return ibnbd_validate_msg_sess_info_rsp(msg, len);
	}
	case IBNBD_MSG_OPEN_RSP: {
		const struct ibnbd_msg_open_rsp *msg = data;

		return ibnbd_validate_msg_open_resp(msg, len);
	}
	case IBNBD_MSG_REVAL: {
		const struct ibnbd_msg_revalidate *msg = data;

		return ibnbd_validate_msg_revalidate(msg, len);
	}
	case IBNBD_MSG_OPEN: {
		const struct ibnbd_msg_open *msg = data;

		return ibnbd_validate_msg_open(msg, len);
	}
	case IBNBD_MSG_CLOSE: {
		const struct ibnbd_msg_close *msg = data;

		return ibnbd_validate_msg_close(msg, len);
	}
	case IBNBD_MSG_CLOSE_RSP: {
		const struct ibnbd_msg_close_rsp *msg = data;

		return ibnbd_validate_msg_close_rsp(msg, len);
	}
	default:
		pr_err("Ignoring received message with unknown type %d\n",
		       hdr->type);
		return -EINVAL;
	}
}
EXPORT_SYMBOL_GPL(ibnbd_validate_message);

const char *ibnbd_io_mode_str(enum ibnbd_io_mode mode)
{
	switch (mode) {
	case IBNBD_FILEIO:
		return "fileio";
	case IBNBD_BLOCKIO:
		return "blockio";
	case IBNBD_AUTOIO:
		return "autoio";
	default:
		return "unknown";
	}
}
EXPORT_SYMBOL_GPL(ibnbd_io_mode_str);

const char *ibnbd_access_mode_str(enum ibnbd_access_mode mode)
{
	switch (mode) {
	case IBNBD_ACCESS_RO:
		return "ro";
	case IBNBD_ACCESS_RW:
		return "rw";
	case IBNBD_ACCESS_MIGRATION:
		return "migration";
	default:
		return "unknown";
	}
}
EXPORT_SYMBOL_GPL(ibnbd_access_mode_str);
