/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * InfiniBand Transport Layer
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
 *          Jinpu Wang <jinpu.wang@cloud.ionos.com>
 *          Danil Kipnis <danil.kipnis@cloud.ionos.com>
 */

/* Copyright (c) 2019 1&1 IONOS SE. All rights reserved.
 * Authors: Jack Wang <jinpu.wang@cloud.ionos.com>
 *          Danil Kipnis <danil.kipnis@cloud.ionos.com>
 *          Guoqing Jiang <guoqing.jiang@cloud.ionos.com>
 *          Lutz Pogrell <lutz.pogrell@cloud.ionos.com>
 */
#ifndef IBTRS_LOG_H
#define IBTRS_LOG_H

#define ibtrs_prefix(obj) (obj->sessname)

#define ibtrs_log(fn, obj, fmt, ...)				\
	fn("<%s>: " fmt, ibtrs_prefix(obj), ##__VA_ARGS__)

#define ibtrs_err(obj, fmt, ...)	\
	ibtrs_log(pr_err, obj, fmt, ##__VA_ARGS__)
#define ibtrs_err_rl(obj, fmt, ...)	\
	ibtrs_log(pr_err_ratelimited, obj, fmt, ##__VA_ARGS__)
#define ibtrs_wrn(obj, fmt, ...)	\
	ibtrs_log(pr_warn, obj, fmt, ##__VA_ARGS__)
#define ibtrs_wrn_rl(obj, fmt, ...) \
	ibtrs_log(pr_warn_ratelimited, obj, fmt, ##__VA_ARGS__)
#define ibtrs_info(obj, fmt, ...) \
	ibtrs_log(pr_info, obj, fmt, ##__VA_ARGS__)
#define ibtrs_info_rl(obj, fmt, ...) \
	ibtrs_log(pr_info_ratelimited, obj, fmt, ##__VA_ARGS__)

#endif /* IBTRS_LOG_H */
