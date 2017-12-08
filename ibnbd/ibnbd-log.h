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

#ifndef IBNBD_LOG_H
#define IBNBD_LOG_H

#include "ibnbd-clt.h"
#include "ibnbd-srv.h"

#define ibnbd_diskname(dev) ({						\
	struct gendisk *gd = ((struct ibnbd_clt_dev *)dev)->gd;		\
	gd ? gd->disk_name : "<no dev>";				\
})

void unknown_type(void);

#define ibnbd_log(fn, dev, fmt, ...) ({					\
	__builtin_choose_expr(						\
		__builtin_types_compatible_p(				\
			typeof(dev), struct ibnbd_clt_dev *),		\
		fn("<%s@%s> %s: " fmt, (dev)->pathname,		\
		   (dev)->sess->sessname, ibnbd_diskname(dev),		\
		   ##__VA_ARGS__),					\
		__builtin_choose_expr(					\
			__builtin_types_compatible_p(typeof(dev),	\
					struct ibnbd_srv_sess_dev *),	\
			fn("<%s@%s>: " fmt, (dev)->pathname,	\
			   (dev)->sess->sessname, ##__VA_ARGS__),		\
			unknown_type()));				\
})

#define ibnbd_err(dev, fmt, ...)	\
	ibnbd_log(pr_err, dev, fmt, ##__VA_ARGS__)
#define ibnbd_err_rl(dev, fmt, ...)	\
	ibnbd_log(pr_err_ratelimited, dev, fmt, ##__VA_ARGS__)
#define ibnbd_wrn(dev, fmt, ...)	\
	ibnbd_log(pr_warn, dev, fmt, ##__VA_ARGS__)
#define ibnbd_wrn_rl(dev, fmt, ...) \
	ibnbd_log(pr_warn_ratelimited, dev, fmt, ##__VA_ARGS__)
#define ibnbd_info(dev, fmt, ...) \
	ibnbd_log(pr_info, dev, fmt, ##__VA_ARGS__)
#define ibnbd_info_rl(dev, fmt, ...) \
	ibnbd_log(pr_info_ratelimited, dev, fmt, ##__VA_ARGS__)

#endif /* IBNBD_LOG_H */
