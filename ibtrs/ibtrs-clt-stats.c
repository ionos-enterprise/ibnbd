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

#include "ibtrs-clt.h"

static inline int ibtrs_clt_ms_to_id(unsigned long ms)
{
	int id = ms ? ilog2(ms) - MIN_LOG_LAT + 1 : 0;

	return clamp(id, 0, LOG_LAT_SZ - 1);
}

void ibtrs_clt_update_rdma_lat(struct ibtrs_clt_stats *s, bool read,
			       unsigned long ms)
{
	const int id = ibtrs_clt_ms_to_id(ms);
	const int cpu = raw_smp_processor_id();

	if (read) {
		s->rdma_lat_distr[cpu][id].read++;
		if (s->rdma_lat_max[cpu].read < ms)
			s->rdma_lat_max[cpu].read = ms;
	} else {
		s->rdma_lat_distr[cpu][id].write++;
		if (s->rdma_lat_max[cpu].write < ms)
			s->rdma_lat_max[cpu].write = ms;
	}
}

void ibtrs_clt_decrease_inflight(struct ibtrs_clt_stats *s)
{
	s->rdma_stats[raw_smp_processor_id()].inflight--;
}

void ibtrs_clt_update_wc_stats(struct ibtrs_clt_con *con)
{
	struct ibtrs_clt_sess *sess = to_clt_sess(con->c.sess);
	unsigned cpu = raw_smp_processor_id();

	if (unlikely(con->cpu != cpu)) {
		pr_debug_ratelimited("WC processing is migrated from CPU %d to "
				     "%d, state %s, user: %s\n",
				     con->cpu, cpu,
				     ibtrs_clt_state_str(sess->state),
				     con->c.cid == 0 ? "true" : "false");
		atomic_inc(&sess->stats.cpu_migr.from[con->cpu]);
		sess->stats.cpu_migr.to[cpu]++;
	}
	sess->stats.wc_comp[cpu].cnt++;
	sess->stats.wc_comp[cpu].total_cnt++;
}

void ibtrs_clt_inc_failover_cnt(struct ibtrs_clt_stats *s)
{
	s->rdma_stats[raw_smp_processor_id()].failover_cnt++;
}

static inline u32 ibtrs_clt_stats_get_avg_wc_cnt(struct ibtrs_clt_stats *stats)
{
	u32 cnt = 0;
	u64 sum = 0;
	int i;

	for (i = 0; i < num_online_cpus(); i++) {
		sum += stats->wc_comp[i].total_cnt;
		cnt += stats->wc_comp[i].cnt;
	}

	return cnt ? sum / cnt : 0;
}

int ibtrs_clt_stats_wc_completion_to_str(struct ibtrs_clt_stats *stats,
					 char *buf, size_t len)
{
	return scnprintf(buf, len, "%u\n",
			 ibtrs_clt_stats_get_avg_wc_cnt(stats));
}

ssize_t ibtrs_clt_stats_rdma_lat_distr_to_str(struct ibtrs_clt_stats *s,
					      char *page, size_t len)
{
	ssize_t cnt = 0;
	int i, cpu;
	struct ibtrs_clt_stats_rdma_lat_entry res[LOG_LAT_SZ];
	struct ibtrs_clt_stats_rdma_lat_entry max;

	max.write	= 0;
	max.read	= 0;
	for (cpu = 0; cpu < num_online_cpus(); cpu++) {
		if (max.write < s->rdma_lat_max[cpu].write)
			max.write = s->rdma_lat_max[cpu].write;
		if (max.read < s->rdma_lat_max[cpu].read)
			max.read = s->rdma_lat_max[cpu].read;
	}

	for (i = 0; i < ARRAY_SIZE(res); i++) {
		res[i].write	= 0;
		res[i].read	= 0;
		for (cpu = 0; cpu < num_online_cpus(); cpu++) {
			res[i].write += s->rdma_lat_distr[cpu][i].write;
			res[i].read += s->rdma_lat_distr[cpu][i].read;
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
	int i;
	size_t used = 0;

	used += scnprintf(buf + used, len - used, "    ");

	for (i = 0; i < num_online_cpus(); i++)
		used += scnprintf(buf + used, len - used, " CPU%u", i);

	used += scnprintf(buf + used, len - used, "\nfrom:");

	for (i = 0; i < num_online_cpus(); i++)
		used += scnprintf(buf + used, len - used, " %d",
				  atomic_read(&stats->cpu_migr.from[i]));

	used += scnprintf(buf + used, len - used, "\n"
			  "to  :");

	for (i = 0; i < num_online_cpus(); i++)
		used += scnprintf(buf + used, len - used, " %d",
				  stats->cpu_migr.to[i]);

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
	struct ibtrs_clt_stats_rdma_stats s;
	struct ibtrs_clt_stats_rdma_stats *r = stats->rdma_stats;
	int i;

	memset(&s, 0, sizeof(s));

	for (i = 0; i < num_online_cpus(); i++) {
		s.dir[READ].cnt		+= r[i].dir[READ].cnt;
		s.dir[READ].size_total	+= r[i].dir[READ].size_total;
		s.dir[WRITE].cnt	+= r[i].dir[WRITE].cnt;
		s.dir[WRITE].size_total	+= r[i].dir[WRITE].size_total;
		s.failover_cnt		+= r[i].failover_cnt;
		s.inflight		+= r[i].inflight;
	}

	return scnprintf(page, len, "%llu %llu %llu %llu %llu %u\n",
			 s.dir[READ].cnt, s.dir[READ].size_total,
			 s.dir[WRITE].cnt, s.dir[WRITE].size_total,
			 s.failover_cnt, s.inflight);
}

int ibtrs_clt_stats_sg_list_distr_to_str(struct ibtrs_clt_stats *stats,
					 char *buf, size_t len)
{
	int cnt = 0;
	unsigned p, p_i, p_f;
	u64 *total = stats->sg_list_total;
	u64 **distr = stats->sg_list_distr;
	int i, j;

	cnt += scnprintf(buf + cnt, len - cnt, "n\\cpu:");
	for (j = 0; j < num_online_cpus(); j++)
		cnt += scnprintf(buf + cnt, len - cnt, "%5d", j);

	for (i = 0; i < SG_DISTR_LEN + 1; i++) {
		if (i <= MAX_LIN_SG)
			cnt += scnprintf(buf + cnt, len - cnt, "\n= %3d:", i);
		else if (i < SG_DISTR_LEN)
			cnt += scnprintf(buf + cnt, len - cnt,
					 "\n< %3d:",
					 1 << (i + MIN_LOG_SG - MAX_LIN_SG));
		else
			cnt += scnprintf(buf + cnt, len - cnt,
					 "\n>=%3d:",
					 1 << (i + MIN_LOG_SG - MAX_LIN_SG - 1));

		for (j = 0; j < num_online_cpus(); j++) {
			p = total[j] ? distr[j][i] * 1000 / total[j] : 0;
			p_i = p / 10;
			p_f = p % 10;

			if (distr[j][i])
				cnt += scnprintf(buf + cnt, len - cnt,
						 " %2u.%01u", p_i, p_f);
			else
				cnt += scnprintf(buf + cnt, len - cnt, "    0");
		}
	}

	cnt += scnprintf(buf + cnt, len - cnt, "\ntotal:");
	for (j = 0; j < num_online_cpus(); j++)
		cnt += scnprintf(buf + cnt, len - cnt, " %llu", total[j]);
	cnt += scnprintf(buf + cnt, len - cnt, "\n");

	return cnt;
}

ssize_t ibtrs_clt_reset_all_help(struct ibtrs_clt_stats *s,
				 char *page, size_t len)
{
	return scnprintf(page, len, "echo 1 to reset all statistics\n");
}

int ibtrs_clt_reset_rdma_stats(struct ibtrs_clt_stats *s, bool enable)
{
	if (enable) {
		memset(s->rdma_stats, 0,
		       num_online_cpus() * sizeof(*s->rdma_stats));
		return 0;
	}

	return -EINVAL;
}

int ibtrs_clt_reset_rdma_lat_distr_stats(struct ibtrs_clt_stats *s,
					 bool enable)
{
	if (enable) {
		memset(s->rdma_lat_max, 0,
		       num_online_cpus() * sizeof(*s->rdma_lat_max));

		memset(s->rdma_lat_distr, 0,
		       num_online_cpus() * sizeof(*s->rdma_lat_distr));
	}
	s->enable_rdma_lat = enable;

	return 0;
}

int ibtrs_clt_reset_sg_list_distr_stats(struct ibtrs_clt_stats *stats,
					       bool enable)
{
	int i;

	if (enable) {
		memset(stats->sg_list_total, 0,
		       num_online_cpus() *
		       sizeof(*stats->sg_list_total));

		for (i = 0; i < num_online_cpus(); i++)
			memset(stats->sg_list_distr[i], 0,
			       sizeof(*stats->sg_list_distr[0]) *
			       (SG_DISTR_LEN + 1));
		return 0;
	}

	return -EINVAL;
}


int ibtrs_clt_reset_cpu_migr_stats(struct ibtrs_clt_stats *stats, bool enable)
{
	if (enable) {
		memset(stats->cpu_migr.from, 0,
		       num_online_cpus() *
		       sizeof(*stats->cpu_migr.from));

		memset(stats->cpu_migr.to, 0,
		       num_online_cpus() * sizeof(*stats->cpu_migr.to));
		return 0;
	}

	return -EINVAL;
}

int ibtrs_clt_reset_reconnects_stat(struct ibtrs_clt_stats *stats, bool enable)
{
	if (enable) {
		memset(&stats->reconnects, 0,
		       sizeof(stats->reconnects));
		return 0;
	}

	return -EINVAL;
}

int ibtrs_clt_reset_wc_comp_stats(struct ibtrs_clt_stats *stats, bool enable)
{
	if (enable) {
		memset(stats->wc_comp, 0,
		       num_online_cpus() * sizeof(*stats->wc_comp));
		return 0;
	}

	return -EINVAL;
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

		return 0;
	}

	return -EINVAL;
}

static inline void ibtrs_clt_record_sg_distr(u64 *stat, u64 *total,
					     unsigned int cnt)
{
	int i;

	i = cnt > MAX_LIN_SG ? ilog2(cnt) + MAX_LIN_SG - MIN_LOG_SG + 1 : cnt;
	i = i > SG_DISTR_LEN ? SG_DISTR_LEN : i;

	stat[i]++;
	(*total)++;
}

static inline void ibtrs_clt_update_rdma_stats(struct ibtrs_clt_stats *s,
					       size_t size, int d)
{
	int cpu = raw_smp_processor_id();

	s->rdma_stats[cpu].dir[d].cnt++;
	s->rdma_stats[cpu].dir[d].size_total += size;
	s->rdma_stats[cpu].inflight++;
}

void ibtrs_clt_update_all_stats(struct ibtrs_clt_io_req *req, int dir)
{
	struct ibtrs_clt_con *con = req->con;
	struct ibtrs_clt_sess *sess = to_clt_sess(con->c.sess);
	struct ibtrs_clt_stats *stats = &sess->stats;
	struct ibtrs_tag *tag = req->tag;
	unsigned int len;

	ibtrs_clt_record_sg_distr(stats->sg_list_distr[tag->cpu_id],
				  &stats->sg_list_total[tag->cpu_id],
				  req->sg_cnt);
	len = req->usr_len + req->data_len;
	ibtrs_clt_update_rdma_stats(stats, len, dir);
}

static int ibtrs_clt_init_sg_list_distr_stats(struct ibtrs_clt_stats *stats)
{
	u64 **list_d, *list_t;
	int i;

	list_d = kmalloc_array(num_online_cpus(), sizeof(*list_d), GFP_KERNEL);
	if (unlikely(!list_d))
		return -ENOMEM;

	for (i = 0; i < num_online_cpus(); i++) {
		list_d[i] = kzalloc_node(sizeof(*list_d[0]) * (SG_DISTR_LEN + 1),
					 GFP_KERNEL, cpu_to_node(i));
		if (unlikely(!list_d[i]))
			goto err;
	}
	list_t = kcalloc(num_online_cpus(), sizeof(*list_t), GFP_KERNEL);
	if (unlikely(!list_t))
		goto err;

	stats->sg_list_distr = list_d;
	stats->sg_list_total = list_t;

	return 0;

err:
	while (i--)
		kfree(list_d[i]);

	kfree(list_d);

	return -ENOMEM;
}

static int ibtrs_clt_init_cpu_migr_stats(struct ibtrs_clt_stats *stats)
{
	stats->cpu_migr.from = kcalloc(num_online_cpus(),
				       sizeof(*stats->cpu_migr.from),
				       GFP_KERNEL);
	if (unlikely(!stats->cpu_migr.from))
		return -ENOMEM;

	stats->cpu_migr.to = kcalloc(num_online_cpus(),
				     sizeof(*stats->cpu_migr.to),
				     GFP_KERNEL);
	if (unlikely(!stats->cpu_migr.to)) {
		kfree(stats->cpu_migr.from);
		stats->cpu_migr.from = NULL;

		return -ENOMEM;
	}

	return 0;
}

static int ibtrs_clt_init_rdma_lat_distr_stats(struct ibtrs_clt_stats *s)
{
	s->rdma_lat_max = kcalloc(num_online_cpus(),
				  sizeof(*s->rdma_lat_max),
				  GFP_KERNEL);
	if (unlikely(!s->rdma_lat_max))
		return -ENOMEM;

	s->rdma_lat_distr = kcalloc(num_online_cpus(),
				    sizeof(*s->rdma_lat_distr),
				    GFP_KERNEL);
	if (unlikely(!s->rdma_lat_distr))
		goto err1;

	return 0;

err1:
	kfree(s->rdma_lat_max);
	s->rdma_lat_max = NULL;

	return -ENOMEM;
}

static int ibtrs_clt_init_wc_comp_stats(struct ibtrs_clt_stats *stats)
{
	stats->wc_comp = kcalloc(num_online_cpus(),
				 sizeof(*stats->wc_comp),
				 GFP_KERNEL);
	if (unlikely(!stats->wc_comp))
		return -ENOMEM;

	return 0;
}

static int ibtrs_clt_init_rdma_stats(struct ibtrs_clt_stats *s)
{
	s->rdma_stats = kcalloc(num_online_cpus(), sizeof(*s->rdma_stats),
				GFP_KERNEL);
	if (unlikely(!s->rdma_stats))
		return -ENOMEM;

	return 0;
}

static void ibtrs_clt_free_rdma_stats(struct ibtrs_clt_stats *stats)
{
	kfree(stats->rdma_stats);
	stats->rdma_stats = NULL;
}

static void ibtrs_clt_free_wc_comp_stats(struct ibtrs_clt_stats *stats)
{
	kfree(stats->wc_comp);
	stats->wc_comp = NULL;
}

static void ibtrs_clt_free_sg_list_distr_stats(struct ibtrs_clt_stats *stats)
{
	int i;

	for (i = 0; i < num_online_cpus(); i++)
		kfree(stats->sg_list_distr[i]);
	kfree(stats->sg_list_distr);
	stats->sg_list_distr = NULL;
	kfree(stats->sg_list_total);
	stats->sg_list_total = NULL;
}

static void ibtrs_clt_free_cpu_migr_stats(struct ibtrs_clt_stats *stats)
{
	kfree(stats->cpu_migr.to);
	stats->cpu_migr.to = NULL;
	kfree(stats->cpu_migr.from);
	stats->cpu_migr.from = NULL;
}

static void ibtrs_clt_free_rdma_lat_stats(struct ibtrs_clt_stats *stats)
{
	kfree(stats->rdma_lat_distr);
	stats->rdma_lat_distr = NULL;
	kfree(stats->rdma_lat_max);
	stats->rdma_lat_max = NULL;
}

int ibtrs_clt_init_stats(struct ibtrs_clt_stats *stats)
{
	int err;

	err = ibtrs_clt_init_sg_list_distr_stats(stats);
	if (unlikely(err))
		return err;

	err = ibtrs_clt_init_cpu_migr_stats(stats);
	if (unlikely(err))
		goto err_sg_list;

	err = ibtrs_clt_init_rdma_lat_distr_stats(stats);
	if (unlikely(err))
		goto err_migr;

	err = ibtrs_clt_init_wc_comp_stats(stats);
	if (unlikely(err))
		goto err_rdma_lat;

	err = ibtrs_clt_init_rdma_stats(stats);
	if (unlikely(err))
		goto err_wc_comp;

	/*
	 * successfull_cnt will be set to 0 after session
	 * is established for the first time
	 */
	stats->reconnects.successful_cnt = -1;

	return 0;

err_wc_comp:
	ibtrs_clt_free_wc_comp_stats(stats);
err_rdma_lat:
	ibtrs_clt_free_rdma_lat_stats(stats);
err_migr:
	ibtrs_clt_free_cpu_migr_stats(stats);
err_sg_list:
	ibtrs_clt_free_sg_list_distr_stats(stats);

	return err;
}

void ibtrs_clt_free_stats(struct ibtrs_clt_stats *stats)
{
	ibtrs_clt_free_rdma_stats(stats);
	ibtrs_clt_free_rdma_lat_stats(stats);
	ibtrs_clt_free_cpu_migr_stats(stats);
	ibtrs_clt_free_sg_list_distr_stats(stats);
	ibtrs_clt_free_wc_comp_stats(stats);
}
