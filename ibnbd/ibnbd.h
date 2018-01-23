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

u32 rq_to_ibnbd_flags(struct request *rq);
u32 ibnbd_to_bio_flags(u32 flags);

#endif /* IBNBD_H */
