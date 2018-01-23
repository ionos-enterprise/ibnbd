/*
 * InfiniBand Network Block Driver
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

#include <linux/module.h>

#include "ibnbd.h"
#include "ibnbd-proto.h"

MODULE_AUTHOR("ibnbd@profitbricks.com");
MODULE_DESCRIPTION("InfiniBand Network Block Device Core");
MODULE_VERSION(IBNBD_VER_STRING);
MODULE_LICENSE("GPL");

u32 ibnbd_to_bio_flags(u32 ibnbd_flags)
{
	u32 bio_flags;

	switch (ibnbd_op(ibnbd_flags)) {
	case IBNBD_OP_READ:
		bio_flags = REQ_OP_READ;
		break;
	case IBNBD_OP_WRITE:
		bio_flags = REQ_OP_WRITE;
		break;
	case IBNBD_OP_FLUSH:
		bio_flags = REQ_OP_FLUSH | REQ_PREFLUSH;
		break;
	case IBNBD_OP_DISCARD:
		bio_flags = REQ_OP_DISCARD;
		break;
	case IBNBD_OP_SECURE_ERASE:
		bio_flags = REQ_OP_SECURE_ERASE;
		break;
	case IBNBD_OP_WRITE_SAME:
		bio_flags = REQ_OP_WRITE_SAME;
		break;
	default:
		WARN(1, "Unknown IBNBD type: %d (flags %d)\n",
		     ibnbd_op(ibnbd_flags), ibnbd_flags);
		bio_flags = 0;
	}

	if (ibnbd_flags & IBNBD_F_SYNC)
		bio_flags |= REQ_SYNC;

	if (ibnbd_flags & IBNBD_F_FUA)
		bio_flags |= REQ_FUA;

	return bio_flags;
}
EXPORT_SYMBOL_GPL(ibnbd_to_bio_flags);

u32 rq_to_ibnbd_flags(struct request *rq)
{
	u32 ibnbd_flags;

	switch (req_op(rq)) {
	case REQ_OP_READ:
		ibnbd_flags = IBNBD_OP_READ;
		break;
	case REQ_OP_WRITE:
		ibnbd_flags = IBNBD_OP_WRITE;
		break;
	case REQ_OP_DISCARD:
		ibnbd_flags = IBNBD_OP_DISCARD;
		break;
	case REQ_OP_SECURE_ERASE:
		ibnbd_flags = IBNBD_OP_SECURE_ERASE;
		break;
	case REQ_OP_WRITE_SAME:
		ibnbd_flags = IBNBD_OP_WRITE_SAME;
		break;
	case REQ_OP_FLUSH:
		ibnbd_flags = IBNBD_OP_FLUSH;
		break;
	default:
		WARN(1, "Unknown request type %d (flags %llu)\n",
		     req_op(rq), (unsigned long long)rq->cmd_flags);
		ibnbd_flags = 0;
	}

	if (op_is_sync(rq->cmd_flags))
		ibnbd_flags |= IBNBD_F_SYNC;

	if (op_is_flush(rq->cmd_flags))
		ibnbd_flags |= IBNBD_F_FUA;

	return ibnbd_flags;
}
EXPORT_SYMBOL_GPL(rq_to_ibnbd_flags);

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
