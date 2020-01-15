// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * RDMA Transport Layer
 *
 * Copyright (c) 2014 - 2018 ProfitBricks GmbH. All rights reserved.
 *
 * Copyright (c) 2018 - 2019 1&1 IONOS Cloud GmbH. All rights reserved.
 *
 * Copyright (c) 2019 - 2020 1&1 IONOS SE. All rights reserved.
 */
#undef pr_fmt
#define pr_fmt(fmt) KBUILD_MODNAME " L" __stringify(__LINE__) ": " fmt

#include "rtrs-srv.h"

void rtrs_srv_update_rdma_stats(struct rtrs_srv_stats *s,
				 size_t size, int d)
{
	atomic64_inc(&s->rdma_stats.dir[d].cnt);
	atomic64_add(size, &s->rdma_stats.dir[d].size_total);
}

void rtrs_srv_update_wc_stats(struct rtrs_srv_stats *s)
{
	atomic64_inc(&s->wc_comp.calls);
	atomic64_inc(&s->wc_comp.total_wc_cnt);
}

int rtrs_srv_reset_rdma_stats(struct rtrs_srv_stats *stats, bool enable)
{
	if (enable) {
		struct rtrs_srv_stats_rdma_stats *r = &stats->rdma_stats;

		memset(r, 0, sizeof(*r));
		return 0;
	}

	return -EINVAL;
}

ssize_t rtrs_srv_stats_rdma_to_str(struct rtrs_srv_stats *stats,
				    char *page, size_t len)
{
	struct rtrs_srv_stats_rdma_stats *r = &stats->rdma_stats;
	struct rtrs_srv_sess *sess;

	sess = container_of(stats, typeof(*sess), stats);

	return scnprintf(page, len, "%lld %lld %lld %lld %u\n",
			 (s64)atomic64_read(&r->dir[READ].cnt),
			 (s64)atomic64_read(&r->dir[READ].size_total),
			 (s64)atomic64_read(&r->dir[WRITE].cnt),
			 (s64)atomic64_read(&r->dir[WRITE].size_total),
			 atomic_read(&sess->ids_inflight));
}

int rtrs_srv_reset_wc_completion_stats(struct rtrs_srv_stats *stats,
					bool enable)
{
	if (enable) {
		memset(&stats->wc_comp, 0, sizeof(stats->wc_comp));
		return 0;
	}

	return -EINVAL;
}

int rtrs_srv_stats_wc_completion_to_str(struct rtrs_srv_stats *stats,
					 char *buf, size_t len)
{
	return snprintf(buf, len, "%lld %lld\n",
			(s64)atomic64_read(&stats->wc_comp.total_wc_cnt),
			(s64)atomic64_read(&stats->wc_comp.calls));
}

ssize_t rtrs_srv_reset_all_help(struct rtrs_srv_stats *stats,
				 char *page, size_t len)
{
	return scnprintf(page, PAGE_SIZE, "echo 1 to reset all statistics\n");
}

int rtrs_srv_reset_all_stats(struct rtrs_srv_stats *stats, bool enable)
{
	if (enable) {
		rtrs_srv_reset_wc_completion_stats(stats, enable);
		rtrs_srv_reset_rdma_stats(stats, enable);
		return 0;
	}

	return -EINVAL;
}
