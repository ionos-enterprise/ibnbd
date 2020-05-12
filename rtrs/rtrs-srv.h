/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * RDMA Transport Layer
 *
 * Copyright (c) 2014 - 2018 ProfitBricks GmbH. All rights reserved.
 *
 * Copyright (c) 2018 - 2019 1&1 IONOS Cloud GmbH. All rights reserved.
 *
 * Copyright (c) 2019 1&1 IONOS SE. All rights reserved.
 */

#ifndef RTRS_SRV_H
#define RTRS_SRV_H

#include <linux/device.h>
#include <linux/refcount.h>
#include "rtrs-pri.h"

/**
 * enum rtrs_srv_state - Server states.
 */
enum rtrs_srv_state {
	RTRS_SRV_CONNECTING,
	RTRS_SRV_CONNECTED,
	RTRS_SRV_CLOSING,
	RTRS_SRV_CLOSED,
};

struct rtrs_stats_wc_comp {
	atomic64_t	calls;
	atomic64_t	total_wc_cnt;
};

struct rtrs_srv_stats_rdma_stats {
	struct {
		atomic64_t	cnt;
		atomic64_t	size_total;
	} dir[2];
};

struct rtrs_srv_stats {
	struct rtrs_srv_stats_rdma_stats	rdma_stats;
	struct rtrs_stats_wc_comp		wc_comp;
};

struct rtrs_srv_con {
	struct rtrs_con		c;
	atomic_t		wr_cnt;
};

/* IO context in rtrs_srv, each io has one */
struct rtrs_srv_op {
	struct rtrs_srv_con		*con;
	u32				msg_id;
	u8				dir;
	struct rtrs_msg_rdma_read	*rd_msg;
	struct ib_rdma_wr		*tx_wr;
	struct ib_sge			*tx_sg;
};

/* server side memory region context, when always_invalidate=Y, we need
 * queue_depth of memory regrion to invalidate each memory region.
 */
struct rtrs_srv_mr {
	struct ib_mr	*mr;
	struct sg_table	sgt;
	struct ib_cqe	inv_cqe; /* only for always_invalidate=true */
	u32		msg_id; /* only for always_invalidate=true */
	u32		msg_off; /* only for always_invalidate=true */
	struct rtrs_iu	*iu; /* send buffer for new rkey msg */
};

struct rtrs_srv_sess {
	struct rtrs_sess	s;
	struct rtrs_srv	*srv;
	struct work_struct	close_work;
	enum rtrs_srv_state	state;
	spinlock_t		state_lock;
	int			cur_cq_vector;
	struct rtrs_srv_op	**ops_ids;
	atomic_t		ids_inflight;
	wait_queue_head_t	ids_waitq;
	struct rtrs_srv_mr	*mrs;
	unsigned int		mrs_num;
	dma_addr_t		*dma_addr;
	bool			established;
	unsigned int		mem_bits;
	struct kobject		kobj;
	struct kobject		kobj_stats;
	struct rtrs_srv_stats	stats;
};

struct rtrs_srv {
	struct list_head	paths_list;
	int			paths_up;
	struct mutex		paths_ev_mutex;
	size_t			paths_num;
	struct mutex		paths_mutex;
	uuid_t			paths_uuid;
	refcount_t		refcount;
	struct rtrs_srv_ctx	*ctx;
	struct list_head	ctx_list;
	void			*priv;
	size_t			queue_depth;
	struct page		**chunks;
	struct device		dev;
	unsigned int		dev_ref;
	struct kobject		kobj_paths;
};

struct rtrs_srv_ctx {
	rdma_ev_fn *rdma_ev;
	link_ev_fn *link_ev;
	struct rdma_cm_id *cm_id_ip;
	struct rdma_cm_id *cm_id_ib;
	struct mutex srv_mutex;
	struct list_head srv_list;
};

extern struct class *rtrs_dev_class;

void close_sess(struct rtrs_srv_sess *sess);

/* rtrs-srv-stats.c */

void rtrs_srv_update_rdma_stats(struct rtrs_srv_stats *s, size_t size, int d);
void rtrs_srv_update_wc_stats(struct rtrs_srv_stats *s);

int rtrs_srv_reset_rdma_stats(struct rtrs_srv_stats *stats, bool enable);
ssize_t rtrs_srv_stats_rdma_to_str(struct rtrs_srv_stats *stats,
				    char *page, size_t len);
int rtrs_srv_reset_wc_completion_stats(struct rtrs_srv_stats *stats,
					bool enable);
int rtrs_srv_stats_wc_completion_to_str(struct rtrs_srv_stats *stats, char *buf,
					 size_t len);
int rtrs_srv_reset_all_stats(struct rtrs_srv_stats *stats, bool enable);
ssize_t rtrs_srv_reset_all_help(struct rtrs_srv_stats *stats,
				 char *page, size_t len);

/* rtrs-srv-sysfs.c */

int rtrs_srv_create_sess_files(struct rtrs_srv_sess *sess);
void rtrs_srv_destroy_sess_files(struct rtrs_srv_sess *sess);

#endif /* RTRS_SRV_H */
