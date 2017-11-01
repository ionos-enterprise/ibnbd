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

struct fake_sess {
	struct ibtrs_sess s;
};

#define FAKE_OR_REAL(dev)						\
	typeof(__builtin_choose_expr(					\
		       __builtin_types_compatible_p(typeof(dev),	\
						    struct ibtrs_con *), \
		       (struct fake_sess *)NULL,			\
		       (typeof(dev))NULL))


#define ibtrs_prefix(dev) ({					\
	const struct ibtrs_sess *_sess;				\
								\
	__builtin_choose_expr(					\
		__builtin_types_compatible_p(			\
			typeof(dev), struct ibtrs_con *),	\
		_sess = ((struct ibtrs_con *)dev)->sess,	\
		_sess = &((FAKE_OR_REAL(dev))(dev))->s		\
	);							\
	_sess->sessname;					\
})

#define ibtrs_log(fn, dev, fmt, ...)				\
	fn("<%s>: " fmt, ibtrs_prefix(dev), ##__VA_ARGS__)

#define ibtrs_err(dev, fmt, ...)	\
	ibtrs_log(pr_err, dev, fmt, ##__VA_ARGS__)
#define ibtrs_err_rl(dev, fmt, ...)	\
	ibtrs_log(pr_err_ratelimited, dev, fmt, ##__VA_ARGS__)
#define ibtrs_wrn(dev, fmt, ...)	\
	ibtrs_log(pr_warn, dev, fmt, ##__VA_ARGS__)
#define ibtrs_wrn_rl(dev, fmt, ...) \
	ibtrs_log(pr_warn_ratelimited, dev, fmt, ##__VA_ARGS__)
#define ibtrs_info(dev, fmt, ...) \
	ibtrs_log(pr_info, dev, fmt, ##__VA_ARGS__)
#define ibtrs_info_rl(dev, fmt, ...) \
	ibtrs_log(pr_info_ratelimited, dev, fmt, ##__VA_ARGS__)

#endif /* IBTRS_LOG_H */
