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

#undef pr_fmt
#define pr_fmt(fmt) KBUILD_MODNAME " L" __stringify(__LINE__) ": " fmt

#include "ibtrs-srv.h"

void ibtrs_srv_update_rdma_stats(struct ibtrs_srv_stats *s,
				 size_t size, int d)
{
	atomic64_inc(&s->rdma_stats.dir[d].cnt);
	atomic64_add(size, &s->rdma_stats.dir[d].size_total);
}

void ibtrs_srv_update_wc_stats(struct ibtrs_srv_stats *s)
{
	atomic64_inc(&s->wc_comp.calls);
	atomic64_inc(&s->wc_comp.total_wc_cnt);
}

int ibtrs_srv_reset_rdma_stats(struct ibtrs_srv_stats *stats, bool enable)
{
	if (enable) {
		struct ibtrs_srv_stats_rdma_stats *r = &stats->rdma_stats;

		memset(r, 0, sizeof(*r));
		return 0;
	}

	return -EINVAL;
}

ssize_t ibtrs_srv_stats_rdma_to_str(struct ibtrs_srv_stats *stats,
				    char *page, size_t len)
{
	struct ibtrs_srv_stats_rdma_stats *r = &stats->rdma_stats;
	struct ibtrs_srv_sess *sess;

	sess = container_of(stats, typeof(*sess), stats);

	return scnprintf(page, len, "%ld %ld %ld %ld %u\n",
			 atomic64_read(&r->dir[READ].cnt),
			 atomic64_read(&r->dir[READ].size_total),
			 atomic64_read(&r->dir[WRITE].cnt),
			 atomic64_read(&r->dir[WRITE].size_total),
			 atomic_read(&sess->ids_inflight));
}

int ibtrs_srv_reset_wc_completion_stats(struct ibtrs_srv_stats *stats,
					bool enable)
{
	if (enable) {
		memset(&stats->wc_comp, 0, sizeof(stats->wc_comp));
		return 0;
	}

	return -EINVAL;
}

int ibtrs_srv_stats_wc_completion_to_str(struct ibtrs_srv_stats *stats,
					 char *buf, size_t len)
{
	return snprintf(buf, len, "%ld %ld\n",
			atomic64_read(&stats->wc_comp.total_wc_cnt),
			atomic64_read(&stats->wc_comp.calls));
}

ssize_t ibtrs_srv_reset_all_help(struct ibtrs_srv_stats *stats,
				 char *page, size_t len)
{
	return scnprintf(page, PAGE_SIZE, "echo 1 to reset all statistics\n");
}

int ibtrs_srv_reset_all_stats(struct ibtrs_srv_stats *stats, bool enable)
{
	if (enable) {
		ibtrs_srv_reset_wc_completion_stats(stats, enable);
		ibtrs_srv_reset_rdma_stats(stats, enable);
		return 0;
	}

	return -EINVAL;
}
