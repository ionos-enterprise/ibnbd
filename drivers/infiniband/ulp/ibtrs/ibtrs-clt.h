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

#ifndef IBTRS_CLT_H
#define IBTRS_CLT_H

#include <linux/uuid.h>

#include "ibtrs-pri.h"

/**
 * enum ibtrs_clt_state - Client states.
 */
enum ibtrs_clt_state {
	IBTRS_CLT_CONNECTING,
	IBTRS_CLT_CONNECTING_ERR,
	IBTRS_CLT_RECONNECTING,
	IBTRS_CLT_CONNECTED,
	IBTRS_CLT_CLOSING,
	IBTRS_CLT_CLOSED,
};

static inline const char *ibtrs_clt_state_str(enum ibtrs_clt_state state)
{
	switch (state) {
	case IBTRS_CLT_CONNECTING:
		return "IBTRS_CLT_CONNECTING";
	case IBTRS_CLT_CONNECTING_ERR:
		return "IBTRS_CLT_CONNECTING_ERR";
	case IBTRS_CLT_RECONNECTING:
		return "IBTRS_CLT_RECONNECTING";
	case IBTRS_CLT_CONNECTED:
		return "IBTRS_CLT_CONNECTED";
	case IBTRS_CLT_CLOSING:
		return "IBTRS_CLT_CLOSING";
	case IBTRS_CLT_CLOSED:
		return "IBTRS_CLT_CLOSED";
	default:
		return "UNKNOWN";
	}
}

enum ibtrs_fast_reg {
	IBTRS_FAST_MEM_NONE,
	IBTRS_FAST_MEM_FR,
	IBTRS_FAST_MEM_FMR
};

struct ibtrs_clt_stats_reconnects {
	u32 successful_cnt;
	u32 fail_cnt;
};

struct ibtrs_clt_stats_wc_comp {
	u32 cnt;
	u64 total_cnt;
};

struct ibtrs_clt_stats_cpu_migration {
	atomic_t *from;
	int *to;
};

struct ibtrs_clt_stats_rdma_stats {
	u64 cnt_read;
	u64 size_total_read;
	u64 cnt_write;
	u64 size_total_write;

	u16 inflight;
};

#define MIN_LOG_SG 2
#define MAX_LOG_SG 5
#define MAX_LIN_SG BIT(MIN_LOG_SG)
#define SG_DISTR_LEN (MAX_LOG_SG - MIN_LOG_SG + MAX_LIN_SG + 1)

struct ibtrs_clt_stats_rdma_lat_entry {
	u64 read;
	u64 write;
};

#define MAX_LOG_LATENCY	16
#define MIN_LOG_LATENCY	0

struct ibtrs_clt_stats_user_ib_msgs {
	u32 recv_msg_cnt;
	u32 sent_msg_cnt;
	u64 recv_size;
	u64 sent_size;
};

struct ibtrs_clt_stats {
	struct ibtrs_clt_stats_cpu_migration	cpu_migr;
	struct ibtrs_clt_stats_rdma_stats	*rdma_stats;
	bool					enable_rdma_lat;
	u64					*sg_list_total;
	u64					**sg_list_distr;
	struct ibtrs_clt_stats_reconnects	reconnects;
	struct ibtrs_clt_stats_rdma_lat_entry	**rdma_lat_distr;
	struct ibtrs_clt_stats_rdma_lat_entry	*rdma_lat_max;
	struct ibtrs_clt_stats_user_ib_msgs	user_ib_msgs;
	struct ibtrs_clt_stats_wc_comp		*wc_comp;
};

struct ibtrs_clt_sess {
	struct ibtrs_sess	s;
	struct ibtrs_clt	*clt;
	wait_queue_head_t	state_wq;
	enum ibtrs_clt_state	state;
	struct mutex		init_mutex;
	bool			established;
	short			port;
	struct rdma_req		*reqs;
	struct ib_fmr_pool	*fmr_pool;
	size_t			pdu_sz;
	struct ibtrs_clt_ops	ops;
	struct delayed_work	reconnect_dwork;
	struct work_struct	close_work;
	unsigned		max_reconnect_attempts;
	unsigned		reconnect_attempts;
	unsigned		reconnect_delay_sec;
	void			*tags;
	unsigned long		*tags_map;
	wait_queue_head_t	tags_wait;
	u64			*srv_rdma_addr;
	u32			srv_rdma_buf_rkey;
	u32			max_io_size;
	u32			max_req_size;
	u32			chunk_size;
	u32			max_desc;
	u32			queue_depth;
	u16			user_queue_depth;
	enum ibtrs_fast_reg	fast_reg_mode;
	u64			mr_page_mask;
	u32			mr_page_size;
	u32			mr_max_size;
	u32			max_pages_per_mr;
	int			max_sge;
	struct kobject		kobj;
	struct kobject		kobj_stats;
	struct ibtrs_clt_stats  stats;
};

struct ibtrs_clt {
	struct ibtrs_clt_sess	*paths[MAX_PATHS_NUM];
	size_t			paths_num;
};

/* See ibtrs-log.h */
#define TYPES_TO_SESSNAME(obj)						\
	LIST(CASE(obj, struct ibtrs_clt_sess *, s.sessname))

#define TAG_SIZE(sess) (sizeof(struct ibtrs_tag) + (sess)->pdu_sz)
#define GET_TAG(sess, idx) ((sess)->tags + TAG_SIZE(sess) * idx)

/**
 * ibtrs_clt_reconnect() - Reconnect the session
 * @sess: Session handler
 */
int ibtrs_clt_reconnect(struct ibtrs_clt_sess *sess);

void ibtrs_clt_set_max_reconnect_attempts(struct ibtrs_clt_sess *sess,
					  s16 value);

s16 ibtrs_clt_get_max_reconnect_attempts(const struct ibtrs_clt_sess *sess);
int ibtrs_clt_get_user_queue_depth(struct ibtrs_clt_sess *sess);
int ibtrs_clt_set_user_queue_depth(struct ibtrs_clt_sess *sess, u16 queue_depth);
int ibtrs_clt_reset_sg_list_distr_stats(struct ibtrs_clt_stats *stats,
					bool enable);
int ibtrs_clt_stats_sg_list_distr_to_str(struct ibtrs_clt_stats *stats,
					 char *buf, size_t len);
int ibtrs_clt_reset_rdma_lat_distr_stats(struct ibtrs_clt_stats *stats,
					 bool enable);
ssize_t ibtrs_clt_stats_rdma_lat_distr_to_str(struct ibtrs_clt_stats *stats,
					      char *page, size_t len);
int ibtrs_clt_reset_cpu_migr_stats(struct ibtrs_clt_stats *stats, bool enable);
int ibtrs_clt_stats_migration_cnt_to_str(struct ibtrs_clt_stats *stats, char *buf,
					 size_t len);
int ibtrs_clt_reset_reconnects_stat(struct ibtrs_clt_stats *stats, bool enable);
int ibtrs_clt_stats_reconnects_to_str(struct ibtrs_clt_stats *stats, char *buf,
				      size_t len);
int ibtrs_clt_reset_user_ib_msgs_stats(struct ibtrs_clt_stats *stats, bool enable);
int ibtrs_clt_stats_user_ib_msgs_to_str(struct ibtrs_clt_stats *stats, char *buf,
					size_t len);
int ibtrs_clt_reset_wc_comp_stats(struct ibtrs_clt_stats *stats, bool enable);
int ibtrs_clt_stats_wc_completion_to_str(struct ibtrs_clt_stats *stats, char *buf,
					 size_t len);
int ibtrs_clt_reset_rdma_stats(struct ibtrs_clt_stats *stats, bool enable);
ssize_t ibtrs_clt_stats_rdma_to_str(struct ibtrs_clt_stats *stats,
				    char *page, size_t len);
bool ibtrs_clt_sess_is_connected(const struct ibtrs_clt_sess *sess);
int ibtrs_clt_reset_all_stats(struct ibtrs_clt_stats *stats, bool enable);
ssize_t ibtrs_clt_reset_all_help(struct ibtrs_clt_stats *stats,
				 char *page, size_t len);

/* ibtrs-clt-sysfs.c */

int ibtrs_clt_create_sysfs_files(void);
void ibtrs_clt_destroy_sysfs_files(void);
int ibtrs_clt_create_sess_files(struct ibtrs_clt_sess *sess);
void ibtrs_clt_destroy_sess_files(struct ibtrs_clt_sess *sess);

#endif /* IBTRS_CLT_H */
