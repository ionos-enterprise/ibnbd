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

	return scnprintf(page, len, "%lld %lld %lld %lld %u\n",
			 (s64)atomic64_read(&r->dir[READ].cnt),
			 (s64)atomic64_read(&r->dir[READ].size_total),
			 (s64)atomic64_read(&r->dir[WRITE].cnt),
			 (s64)atomic64_read(&r->dir[WRITE].size_total),
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
	return snprintf(buf, len, "%lld %lld\n",
			(s64)atomic64_read(&stats->wc_comp.total_wc_cnt),
			(s64)atomic64_read(&stats->wc_comp.calls));
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
