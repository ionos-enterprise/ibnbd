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

	if (op_is_sync((rq->cmd_flags)))
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
