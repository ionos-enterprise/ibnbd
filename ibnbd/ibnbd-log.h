/* SPDX-License-Identifier: GPL-2.0-or-later */
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
 * Copyright (c) 2018 - 2019 1&1 IONOS Cloud GmbH. All rights reserved.
 * Authors: Roman Penyaev <roman.penyaev@profitbricks.com>
 *          Jack Wang <jinpu.wang@cloud.ionos.com>
 *          Danil Kipnis <danil.kipnis@cloud.ionos.com>
 */

#ifndef IBNBD_LOG_H
#define IBNBD_LOG_H

#include "ibnbd-clt.h"
#include "ibnbd-srv.h"

void unknown_type(void);

#define ibnbd_clt_log(fn, dev, fmt, ...) (				\
		fn("<%s@%s> " fmt, (dev)->pathname,			\
		(dev)->sess->sessname,					\
		   ##__VA_ARGS__))
#define ibnbd_srv_log(fn, dev, fmt, ...) (				\
			fn("<%s@%s>: " fmt, (dev)->pathname,		\
			   (dev)->sess->sessname, ##__VA_ARGS__))

#define ibnbd_clt_err(dev, fmt, ...)	\
	ibnbd_clt_log(pr_err, dev, fmt, ##__VA_ARGS__)
#define ibnbd_clt_err_rl(dev, fmt, ...)	\
	ibnbd_clt_log(pr_err_ratelimited, dev, fmt, ##__VA_ARGS__)
#define ibnbd_clt_info(dev, fmt, ...) \
	ibnbd_clt_log(pr_info, dev, fmt, ##__VA_ARGS__)
#define ibnbd_clt_info_rl(dev, fmt, ...) \
	ibnbd_clt_log(pr_info_ratelimited, dev, fmt, ##__VA_ARGS__)

#define ibnbd_srv_err(dev, fmt, ...)	\
	ibnbd_srv_log(pr_err, dev, fmt, ##__VA_ARGS__)
#define ibnbd_srv_err_rl(dev, fmt, ...)	\
	ibnbd_srv_log(pr_err_ratelimited, dev, fmt, ##__VA_ARGS__)
#define ibnbd_srv_info(dev, fmt, ...) \
	ibnbd_srv_log(pr_info, dev, fmt, ##__VA_ARGS__)
#define ibnbd_srv_info_rl(dev, fmt, ...) \
	ibnbd_srv_log(pr_info_ratelimited, dev, fmt, ##__VA_ARGS__)

#endif /* IBNBD_LOG_H */
