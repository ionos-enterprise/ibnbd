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

#ifndef IBTRS_SRV_H
#define IBTRS_SRV_H

#include <linux/refcount.h>
#include "ibtrs-pri.h"

/**
 * enum ibtrs_srv_state - Server states.
 */
enum ibtrs_srv_state {
	IBTRS_SRV_CONNECTING,
	IBTRS_SRV_CONNECTED,
	IBTRS_SRV_CLOSING,
	IBTRS_SRV_CLOSED,
};

static inline const char *ibtrs_srv_state_str(enum ibtrs_srv_state state)
{
	switch (state) {
	case IBTRS_SRV_CONNECTING:
		return "IBTRS_SRV_CONNECTING";
	case IBTRS_SRV_CONNECTED:
		return "IBTRS_SRV_CONNECTED";
	case IBTRS_SRV_CLOSING:
		return "IBTRS_SRV_CLOSING";
	case IBTRS_SRV_CLOSED:
		return "IBTRS_SRV_CLOSED";
	default:
		return "UNKNOWN";
	}
}

struct ibtrs_stats_wc_comp {
	atomic64_t	calls;
	atomic64_t	total_wc_cnt;
};

struct ibtrs_srv_stats_rdma_stats {
	atomic64_t	cnt_read;
	atomic64_t	size_total_read;
	atomic64_t	cnt_write;
	atomic64_t	size_total_write;
};

struct ibtrs_srv_stats {
	struct ibtrs_srv_stats_rdma_stats	rdma_stats;
	atomic_t				apm_cnt;
	struct ibtrs_stats_wc_comp		wc_comp;
};

struct ibtrs_srv_con {
	struct ibtrs_con	c;
	atomic_t		wr_cnt;
};

struct ibtrs_srv_op {
	struct ibtrs_srv_con		*con;
	u32				msg_id;
	u8				dir;
	u64				data_dma_addr;
	struct ibtrs_msg_req_rdma_write *req;
	struct ib_rdma_wr		*tx_wr;
	struct ib_sge			*tx_sg;
};

struct ibtrs_srv_sess {
	struct ibtrs_sess	s;
	struct ibtrs_srv	*srv;
	struct work_struct	close_work;
	enum ibtrs_srv_state	state;
	spinlock_t		state_lock;
	int			cur_cq_vector;
	struct ibtrs_srv_op	**ops_ids;
	atomic_t		ids_inflight;
	wait_queue_head_t	ids_waitq;
	dma_addr_t		*rdma_addr;
	bool			established;
	u8			off_len; /* number of bits for offset in
					  * one client buffer.
					  * 32 - ilog2(sess->queue_depth)
					  */
	u32			off_mask; /* mask to get offset in client buf
					   * out of the imm field
					   */
	struct kobject		kobj;
	struct kobject		kobj_stats;
	struct ibtrs_srv_stats	stats;
};

struct ibtrs_srv {
	struct ibtrs_srv_sess	*paths[MAX_PATHS_NUM];
	int			paths_up;
	struct mutex		paths_ev_mutex;
	size_t			paths_num;
	struct mutex		paths_mutex;
	uuid_t			paths_uuid;
	refcount_t		refcount;
	struct ibtrs_srv_ctx	*ctx;
	struct list_head	ctx_list;
	void			*priv;
	size_t			queue_depth;
	struct page		**chunks;
	struct kobject		kobj;
	struct kobject		kobj_paths;
};

struct ibtrs_srv_ctx {
	rdma_ev_fn *rdma_ev;
	link_ev_fn *link_ev;
	struct rdma_cm_id *cm_id_ip;
	struct rdma_cm_id *cm_id_ib;
	struct mutex srv_mutex;
	struct list_head srv_list;
};

/* See ibtrs-log.h */
#define TYPES_TO_SESSNAME(obj)						\
	LIST(CASE(obj, struct ibtrs_srv_sess *, s.sessname))

void ibtrs_srv_queue_close(struct ibtrs_srv_sess *sess);

int ibtrs_srv_current_hca_port_to_str(struct ibtrs_srv_sess *sess,
				      char *buf, size_t len);
const char *ibtrs_srv_get_sess_hca_name(struct ibtrs_srv_sess *sess);
int ibtrs_srv_reset_rdma_stats(struct ibtrs_srv_stats *stats, bool enable);
ssize_t ibtrs_srv_stats_rdma_to_str(struct ibtrs_srv_stats *stats,
				    char *page, size_t len);
int ibtrs_srv_reset_wc_completion_stats(struct ibtrs_srv_stats *stats,
					bool enable);
int ibtrs_srv_stats_wc_completion_to_str(struct ibtrs_srv_stats *stats, char *buf,
					 size_t len);
int ibtrs_srv_reset_all_stats(struct ibtrs_srv_stats *stats, bool enable);
ssize_t ibtrs_srv_reset_all_help(struct ibtrs_srv_stats *stats,
				 char *page, size_t len);

/* ibtrs-srv-sysfs.c */

int ibtrs_srv_create_sysfs_module_files(void);
void ibtrs_srv_destroy_sysfs_module_files(void);

int ibtrs_srv_create_once_sysfs_root_folders(struct ibtrs_srv *srv,
					     const char *sessname);
void ibtrs_srv_destroy_sysfs_root_folders(struct ibtrs_srv *srv);

int ibtrs_srv_create_sess_files(struct ibtrs_srv_sess *sess);
void ibtrs_srv_destroy_sess_files(struct ibtrs_srv_sess *sess);

#endif /* IBTRS_SRV_H */
