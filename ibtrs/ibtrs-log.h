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

#ifndef IBTRS_LOG_H
#define IBTRS_LOG_H

#define P1 )
#define P2 ))
#define P3 )))
#define P4 ))))
#define P(N) P ## N

#define CAT(a, ...) PRIMITIVE_CAT(a, __VA_ARGS__)
#define PRIMITIVE_CAT(a, ...) a ## __VA_ARGS__

#define LIST(...)						\
	__VA_ARGS__,						\
	({ unknown_type(); NULL; })				\
	CAT(P, COUNT_ARGS(__VA_ARGS__))				\

#define EMPTY()
#define DEFER(id) id EMPTY()

#define _CASE(obj, type, member)				\
	__builtin_choose_expr(					\
	__builtin_types_compatible_p(				\
		typeof(obj), type),				\
		((type)obj)->member
#define CASE(o, t, m) DEFER(_CASE)(o,t,m)

/*
 * Below we define retrieving of sessname from common IBTRS types.
 * Client or server related types have to be defined by special
 * TYPES_TO_SESSNAME macro.
 */

void unknown_type(void);

#ifndef TYPES_TO_SESSNAME
#define TYPES_TO_SESSNAME(...) ({ unknown_type(); NULL; })
#endif

#define ibtrs_prefix(obj)					\
	_CASE(obj, struct ibtrs_con *,  sess->sessname),	\
	_CASE(obj, struct ibtrs_sess *, sessname),		\
	TYPES_TO_SESSNAME(obj)					\
	))

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
