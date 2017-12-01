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

#include <linux/ctype.h>
#include "ibnbd.h"
#include "ibnbd-proto.h"

u32 ibnbd_to_bio_flags(u32 flags)
{
	u32 result = 0;

	if (flags == 0)
		return result;

	if (flags & IBNBD_RW_REQ_WRITE)
		result |= REQ_OP_WRITE;

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
EXPORT_SYMBOL_GPL(ibnbd_to_bio_flags);

u32 rq_to_ibnbd_flags(struct request *rq)
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
