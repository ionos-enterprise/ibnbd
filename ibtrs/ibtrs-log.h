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

#ifndef IBTRS_LOG_H
#define IBTRS_LOG_H

#define P1 )
#define P2 ))
#define P3 )))
#define P4 ))))
#define P(N) P ## N

#define CAT(a, ...) PRIMITIVE_CAT(a, __VA_ARGS__)
#define PRIMITIVE_CAT(a, ...) a ## __VA_ARGS__

#define COUNT_ARGS(...) COUNT_ARGS_(,##__VA_ARGS__,6,5,4,3,2,1,0)
#define COUNT_ARGS_(z,a,b,c,d,e,f,cnt,...) cnt

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
