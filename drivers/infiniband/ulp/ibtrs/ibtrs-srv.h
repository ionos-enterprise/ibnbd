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
 *          Swapnil Ingle <swapnil.ingle@profitbricks.com>
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

#ifndef IBTRS_SRV_H
#define IBTRS_SRV_H

#include <linux/device.h>
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
	struct {
		atomic64_t	cnt;
		atomic64_t	size_total;
	} dir[2];
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
	struct ibtrs_msg_rdma_read	*rd_msg;
	struct ib_rdma_wr		*tx_wr;
	struct ib_sge			*tx_sg;
};

struct ibtrs_srv_mr {
	struct ib_mr	*mr;
	struct sg_table	sgt;
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
	struct ibtrs_srv_mr	*mrs;
	unsigned int		mrs_num;
	dma_addr_t		*dma_addr;
	bool			established;
	unsigned int		mem_bits;
	struct kobject		kobj;
	struct kobject		kobj_stats;
	struct ibtrs_srv_stats	stats;
};

struct ibtrs_srv {
	struct list_head	paths_list;
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
	struct device		dev;
	unsigned		dev_ref;
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

/* ibtrs-srv-stats.c */

void ibtrs_srv_update_rdma_stats(struct ibtrs_srv_stats *s, size_t size, int d);
void ibtrs_srv_update_wc_stats(struct ibtrs_srv_stats *s);

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

int ibtrs_srv_create_sess_files(struct ibtrs_srv_sess *sess);
void ibtrs_srv_destroy_sess_files(struct ibtrs_srv_sess *sess);

#endif /* IBTRS_SRV_H */
