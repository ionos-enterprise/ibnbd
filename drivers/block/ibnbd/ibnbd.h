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

#ifndef IBNBD_H
#define IBNBD_H

#include <linux/types.h>
#include <linux/blkdev.h>
#include <linux/inet.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <rdma/ib.h>

#define IBNBD_VER_MAJOR 1
#define IBNBD_VER_MINOR 0
#define IBNBD_VER_STRING __stringify(IBNBD_VER_MAJOR) "." \
			 __stringify(IBNBD_VER_MINOR)

/* TODO: should be configurable */
#define IBTRS_PORT 1234

static inline int ibnbd_sockaddr_to_str(const struct sockaddr *addr,
					char *buf, size_t len)
{
	switch (addr->sa_family) {
	case AF_IB:
		return scnprintf(buf, len, "gid:%pI6",
				 &((struct sockaddr_ib *)addr)->sib_addr.sib_raw);
	case AF_INET:
		return scnprintf(buf, len, "ip:%pI4",
				 &((struct sockaddr_in *)addr)->sin_addr);
	case AF_INET6:
		return scnprintf(buf, len, "ip:%pI6c",
				 &((struct sockaddr_in6 *)addr)->sin6_addr);
	default:
		pr_err("Invalid address family\n");
		return -EINVAL;
	}
}

u32 rq_cmd_to_ibnbd_io_flags(struct request *rq);
u32 ibnbd_io_flags_to_bi_rw(u32 flags);

#endif /* IBNBD_H */
