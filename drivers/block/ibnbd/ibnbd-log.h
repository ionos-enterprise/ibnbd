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
