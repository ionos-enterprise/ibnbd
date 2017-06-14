#include <linux/ctype.h>
#include "ibnbd.h"
#include "ibnbd-proto.h"

u32 ibnbd_io_flags_to_bi_rw(u32 flags)
{
	u32 result = 0;

	if (flags == 0)
		return result;

	if (flags & IBNBD_RW_REQ_WRITE)
		result |= WRITE;

	if (flags & IBNBD_RW_REQ_SYNC)
		result |= REQ_SYNC;

	if (flags & IBNBD_RW_REQ_DISCARD)
		result |= REQ_OP_DISCARD;

	if (flags & IBNBD_RW_REQ_SECURE)
		result |= REQ_OP_SECURE_ERASE;

	if (flags & IBNBD_RW_REQ_WRITE_SAME)
		result |= REQ_OP_WRITE_SAME;

	if (flags & IBNBD_RW_REQ_FUA)
		result |= REQ_FUA;

	if (flags & IBNBD_RW_REQ_FLUSH)
		result |= REQ_OP_FLUSH | REQ_PREFLUSH;

	return result;
}
EXPORT_SYMBOL_GPL(ibnbd_io_flags_to_bi_rw);

u32 rq_cmd_to_ibnbd_io_flags(struct request *rq)
{
	u32 result = 0;

	if (req_op(rq) == REQ_OP_WRITE)
		result |= IBNBD_RW_REQ_WRITE;

	if (rq_is_sync(rq))
		result |= IBNBD_RW_REQ_SYNC;

	if (req_op(rq) == REQ_OP_DISCARD)
		result |= IBNBD_RW_REQ_DISCARD;

	if (req_op(rq) == REQ_OP_SECURE_ERASE)
		result |= IBNBD_RW_REQ_SECURE;

	if (req_op(rq) == REQ_OP_WRITE_SAME)
		result |= IBNBD_RW_REQ_WRITE_SAME;

	if (rq->cmd_flags & REQ_FUA)
		result |= IBNBD_RW_REQ_FUA;

	if (req_op(rq) == REQ_OP_FLUSH)
		result |= IBNBD_RW_REQ_FLUSH;

	return result;
}
EXPORT_SYMBOL_GPL(rq_cmd_to_ibnbd_io_flags);
