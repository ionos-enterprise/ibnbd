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

#include "ibtrs-clt.h"

static inline int ibtrs_clt_ms_to_id(unsigned long ms)
{
	int id = ms ? ilog2(ms) - MIN_LOG_LAT + 1 : 0;

	return clamp(id, 0, LOG_LAT_SZ - 1);
}

void ibtrs_clt_update_rdma_lat(struct ibtrs_clt_stats *stats, bool read,
			       unsigned long ms)
{
	struct ibtrs_clt_stats_pcpu *s;
	int id;

	id = ibtrs_clt_ms_to_id(ms);
	s = this_cpu_ptr(stats->pcpu_stats);
	if (read) {
		s->rdma_lat_distr[id].read++;
		if (s->rdma_lat_max.read < ms)
			s->rdma_lat_max.read = ms;
	} else {
		s->rdma_lat_distr[id].write++;
		if (s->rdma_lat_max.write < ms)
			s->rdma_lat_max.write = ms;
	}
}

void ibtrs_clt_decrease_inflight(struct ibtrs_clt_stats *stats)
{
	atomic_dec(&stats->inflight);
}

void ibtrs_clt_update_wc_stats(struct ibtrs_clt_con *con)
{
	struct ibtrs_clt_sess *sess = to_clt_sess(con->c.sess);
	struct ibtrs_clt_stats *stats = &sess->stats;
	struct ibtrs_clt_stats_pcpu *s;
	int cpu;

	cpu = raw_smp_processor_id();
	s = this_cpu_ptr(stats->pcpu_stats);
	s->wc_comp.cnt++;
	s->wc_comp.total_cnt++;
	if (unlikely(con->cpu != cpu)) {
		s->cpu_migr.to++;

		/* Careful here, override s pointer */
		s = per_cpu_ptr(stats->pcpu_stats, con->cpu);
		atomic_inc(&s->cpu_migr.from);
	}
}

void ibtrs_clt_inc_failover_cnt(struct ibtrs_clt_stats *stats)
{
	struct ibtrs_clt_stats_pcpu *s;

	s = this_cpu_ptr(stats->pcpu_stats);
	s->rdma.failover_cnt++;
}

static inline u32 ibtrs_clt_stats_get_avg_wc_cnt(struct ibtrs_clt_stats *stats)
{
	u32 cnt = 0;
	u64 sum = 0;
	int cpu;

	for_each_possible_cpu(cpu) {
		struct ibtrs_clt_stats_pcpu *s;

		s = per_cpu_ptr(stats->pcpu_stats, cpu);
		sum += s->wc_comp.total_cnt;
		cnt += s->wc_comp.cnt;
	}

	return cnt ? sum / cnt : 0;
}

int ibtrs_clt_stats_wc_completion_to_str(struct ibtrs_clt_stats *stats,
					 char *buf, size_t len)
{
	return scnprintf(buf, len, "%u\n",
			 ibtrs_clt_stats_get_avg_wc_cnt(stats));
}

ssize_t ibtrs_clt_stats_rdma_lat_distr_to_str(struct ibtrs_clt_stats *stats,
					      char *page, size_t len)
{
	struct ibtrs_clt_stats_rdma_lat res[LOG_LAT_SZ];
	struct ibtrs_clt_stats_rdma_lat max;
	struct ibtrs_clt_stats_pcpu *s;

	ssize_t cnt = 0;
	int i, cpu;

	max.write = 0;
	max.read = 0;
	for_each_possible_cpu(cpu) {
		s = per_cpu_ptr(stats->pcpu_stats, cpu);

		if (max.write < s->rdma_lat_max.write)
			max.write = s->rdma_lat_max.write;
		if (max.read < s->rdma_lat_max.read)
			max.read = s->rdma_lat_max.read;
	}
	for (i = 0; i < ARRAY_SIZE(res); i++) {
		res[i].write = 0;
		res[i].read = 0;
		for_each_possible_cpu(cpu) {
			s = per_cpu_ptr(stats->pcpu_stats, cpu);

			res[i].write += s->rdma_lat_distr[i].write;
			res[i].read += s->rdma_lat_distr[i].read;
		}
	}

	for (i = 0; i < ARRAY_SIZE(res) - 1; i++)
		cnt += scnprintf(page + cnt, len - cnt,
				 "< %6d ms: %llu %llu\n",
				 1 << (i + MIN_LOG_LAT), res[i].read,
				 res[i].write);
	cnt += scnprintf(page + cnt, len - cnt, ">= %5d ms: %llu %llu\n",
			 1 << (i - 1 + MIN_LOG_LAT), res[i].read,
			 res[i].write);
	cnt += scnprintf(page + cnt, len - cnt, " maximum ms: %llu %llu\n",
			 max.read, max.write);

	return cnt;
}

int ibtrs_clt_stats_migration_cnt_to_str(struct ibtrs_clt_stats *stats,
					 char *buf, size_t len)
{
	struct ibtrs_clt_stats_pcpu *s;

	size_t used;
	int cpu;

	used = scnprintf(buf, len, "    ");
	for_each_possible_cpu(cpu)
		used += scnprintf(buf + used, len - used, " CPU%u", cpu);

	used += scnprintf(buf + used, len - used, "\nfrom:");
	for_each_possible_cpu(cpu) {
		s = per_cpu_ptr(stats->pcpu_stats, cpu);
		used += scnprintf(buf + used, len - used, " %d",
				  atomic_read(&s->cpu_migr.from));
	}

	used += scnprintf(buf + used, len - used, "\nto  :");
	for_each_possible_cpu(cpu) {
		s = per_cpu_ptr(stats->pcpu_stats, cpu);
		used += scnprintf(buf + used, len - used, " %d",
				  s->cpu_migr.to);
	}
	used += scnprintf(buf + used, len - used, "\n");

	return used;
}

int ibtrs_clt_stats_reconnects_to_str(struct ibtrs_clt_stats *stats, char *buf,
				      size_t len)
{
	return scnprintf(buf, len, "%d %d\n",
			 stats->reconnects.successful_cnt,
			 stats->reconnects.fail_cnt);
}

ssize_t ibtrs_clt_stats_rdma_to_str(struct ibtrs_clt_stats *stats,
				    char *page, size_t len)
{
	struct ibtrs_clt_stats_rdma sum;
	struct ibtrs_clt_stats_rdma *r;
	int cpu;

	memset(&sum, 0, sizeof(sum));

	for_each_possible_cpu(cpu) {
		r = &per_cpu_ptr(stats->pcpu_stats, cpu)->rdma;

		sum.dir[READ].cnt	  += r->dir[READ].cnt;
		sum.dir[READ].size_total  += r->dir[READ].size_total;
		sum.dir[WRITE].cnt	  += r->dir[WRITE].cnt;
		sum.dir[WRITE].size_total += r->dir[WRITE].size_total;
		sum.failover_cnt	  += r->failover_cnt;
	}

	return scnprintf(page, len, "%llu %llu %llu %llu %u %llu\n",
			 sum.dir[READ].cnt, sum.dir[READ].size_total,
			 sum.dir[WRITE].cnt, sum.dir[WRITE].size_total,
			 atomic_read(&stats->inflight), sum.failover_cnt);
}

int ibtrs_clt_stats_sg_list_distr_to_str(struct ibtrs_clt_stats *stats,
					 char *buf, size_t len)
{
	struct ibtrs_clt_stats_pcpu *s;

	int i, cpu, cnt;

	cnt = scnprintf(buf, len, "n\\cpu:");
	for_each_possible_cpu(cpu)
		cnt += scnprintf(buf + cnt, len - cnt, "%5d", cpu);

	for (i = 0; i < SG_DISTR_SZ; i++) {
		if (i <= MAX_LIN_SG)
			cnt += scnprintf(buf + cnt, len - cnt, "\n= %3d:", i);
		else if (i < SG_DISTR_SZ - 1)
			cnt += scnprintf(buf + cnt, len - cnt,
					 "\n< %3d:",
					 1 << (i + MIN_LOG_SG - MAX_LIN_SG));
		else
			cnt += scnprintf(buf + cnt, len - cnt,
					 "\n>=%3d:",
					 1 << (i + MIN_LOG_SG - MAX_LIN_SG - 1));

		for_each_possible_cpu(cpu) {
			unsigned int p, p_i, p_f;
			u64 total, distr;

			s = per_cpu_ptr(stats->pcpu_stats, cpu);
			total = s->sg_list_total;
			distr = s->sg_list_distr[i];

			p = total ? distr * 1000 / total : 0;
			p_i = p / 10;
			p_f = p % 10;

			if (distr)
				cnt += scnprintf(buf + cnt, len - cnt,
						 " %2u.%01u", p_i, p_f);
			else
				cnt += scnprintf(buf + cnt, len - cnt, "    0");
		}
	}

	cnt += scnprintf(buf + cnt, len - cnt, "\ntotal:");
	for_each_possible_cpu(cpu) {
		s = per_cpu_ptr(stats->pcpu_stats, cpu);
		cnt += scnprintf(buf + cnt, len - cnt, " %llu",
				 s->sg_list_total);
	}
	cnt += scnprintf(buf + cnt, len - cnt, "\n");

	return cnt;
}

ssize_t ibtrs_clt_reset_all_help(struct ibtrs_clt_stats *s,
				 char *page, size_t len)
{
	return scnprintf(page, len, "echo 1 to reset all statistics\n");
}

int ibtrs_clt_reset_rdma_stats(struct ibtrs_clt_stats *stats, bool enable)
{
	struct ibtrs_clt_stats_pcpu *s;
	int cpu;

	if (unlikely(!enable))
		return -EINVAL;

	for_each_possible_cpu(cpu) {
		s = per_cpu_ptr(stats->pcpu_stats, cpu);
		memset(&s->rdma, 0, sizeof(s->rdma));
	}

	return 0;
}

int ibtrs_clt_reset_rdma_lat_distr_stats(struct ibtrs_clt_stats *stats,
					 bool enable)
{
	struct ibtrs_clt_stats_pcpu *s;
	int cpu;

	if (enable) {
		for_each_possible_cpu(cpu) {
			s = per_cpu_ptr(stats->pcpu_stats, cpu);
			memset(&s->rdma_lat_max, 0, sizeof(s->rdma_lat_max));
			memset(&s->rdma_lat_distr, 0,
			       sizeof(s->rdma_lat_distr));
		}
	}
	stats->enable_rdma_lat = enable;

	return 0;
}

int ibtrs_clt_reset_sg_list_distr_stats(struct ibtrs_clt_stats *stats,
					bool enable)
{
	struct ibtrs_clt_stats_pcpu *s;
	int cpu;

	if (unlikely(!enable))
		return -EINVAL;

	for_each_possible_cpu(cpu) {
		s = per_cpu_ptr(stats->pcpu_stats, cpu);
		memset(&s->sg_list_total, 0, sizeof(s->sg_list_total));
		memset(&s->sg_list_distr, 0, sizeof(s->sg_list_distr));
	}

	return 0;
}

int ibtrs_clt_reset_cpu_migr_stats(struct ibtrs_clt_stats *stats, bool enable)
{
	struct ibtrs_clt_stats_pcpu *s;
	int cpu;

	if (unlikely(!enable))
		return -EINVAL;

	for_each_possible_cpu(cpu) {
		s = per_cpu_ptr(stats->pcpu_stats, cpu);
		memset(&s->cpu_migr, 0, sizeof(s->cpu_migr));
	}

	return 0;
}

int ibtrs_clt_reset_reconnects_stat(struct ibtrs_clt_stats *stats, bool enable)
{
	if (unlikely(!enable))
		return -EINVAL;

	memset(&stats->reconnects, 0, sizeof(stats->reconnects));

	return 0;
}

int ibtrs_clt_reset_wc_comp_stats(struct ibtrs_clt_stats *stats, bool enable)
{
	struct ibtrs_clt_stats_pcpu *s;
	int cpu;

	if (unlikely(!enable))
		return -EINVAL;

	for_each_possible_cpu(cpu) {
		s = per_cpu_ptr(stats->pcpu_stats, cpu);
		memset(&s->wc_comp, 0, sizeof(s->wc_comp));
	}

	return 0;
}

int ibtrs_clt_reset_all_stats(struct ibtrs_clt_stats *s, bool enable)
{
	if (enable) {
		ibtrs_clt_reset_rdma_stats(s, enable);
		ibtrs_clt_reset_rdma_lat_distr_stats(s, enable);
		ibtrs_clt_reset_sg_list_distr_stats(s, enable);
		ibtrs_clt_reset_cpu_migr_stats(s, enable);
		ibtrs_clt_reset_reconnects_stat(s, enable);
		ibtrs_clt_reset_wc_comp_stats(s, enable);
		atomic_set(&s->inflight, 0);
		return 0;
	}

	return -EINVAL;
}

static inline void ibtrs_clt_record_sg_distr(u64 stat[SG_DISTR_SZ], u64 *total,
					     unsigned int cnt)
{
	int i;

	i = cnt > MAX_LIN_SG ? ilog2(cnt) + MAX_LIN_SG - MIN_LOG_SG + 1 : cnt;
	i = i < SG_DISTR_SZ ? i : SG_DISTR_SZ - 1;

	stat[i]++;
	(*total)++;
}

static inline void ibtrs_clt_update_rdma_stats(struct ibtrs_clt_stats *stats,
					       size_t size, int d)
{
	struct ibtrs_clt_stats_pcpu *s;

	s = this_cpu_ptr(stats->pcpu_stats);
	s->rdma.dir[d].cnt++;
	s->rdma.dir[d].size_total += size;
}

void ibtrs_clt_update_all_stats(struct ibtrs_clt_io_req *req, int dir)
{
	struct ibtrs_clt_con *con = req->con;
	struct ibtrs_clt_sess *sess = to_clt_sess(con->c.sess);
	struct ibtrs_clt_stats *stats = &sess->stats;
	unsigned int len;

	struct ibtrs_clt_stats_pcpu *s;

	s = this_cpu_ptr(stats->pcpu_stats);
	ibtrs_clt_record_sg_distr(s->sg_list_distr, &s->sg_list_total,
				  req->sg_cnt);
	len = req->usr_len + req->data_len;
	ibtrs_clt_update_rdma_stats(stats, len, dir);
	atomic_inc(&stats->inflight);
}

int ibtrs_clt_init_stats(struct ibtrs_clt_stats *stats)
{
	stats->enable_rdma_lat = false;
	stats->pcpu_stats = alloc_percpu(typeof(*stats->pcpu_stats));
	if (unlikely(!stats->pcpu_stats))
		return -ENOMEM;

	/*
	 * successful_cnt will be set to 0 after session
	 * is established for the first time
	 */
	stats->reconnects.successful_cnt = -1;

	return 0;
}

void ibtrs_clt_free_stats(struct ibtrs_clt_stats *stats)
{
	free_percpu(stats->pcpu_stats);
}
