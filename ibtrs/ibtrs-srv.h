/* SPDX-License-Identifier: GPL-2.0-or-later */
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
 * Copyright (c) 2018 - 2019 1&1 IONOS Cloud GmbH. All rights reserved.
 * Authors: Roman Penyaev <roman.penyaev@profitbricks.com>
 *          Jinpu Wang <jinpu.wang@cloud.ionos.com>
 *          Danil Kipnis <danil.kipnis@cloud.ionos.com>
 */
/* Copyright (c) 2019 1&1 IONOS SE. All rights reserved.
 * Authors: Jack Wang <jinpu.wang@cloud.ionos.com>
 *          Danil Kipnis <danil.kipnis@cloud.ionos.com>
 *          Guoqing Jiang <guoqing.jiang@cloud.ionos.com>
 *          Lutz Pogrell <lutz.pogrell@cloud.ionos.com>
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
	struct ib_cqe	inv_cqe; /* only for always_invalidate=true */
	u32		msg_id; /* only for always_invalidate=true */
	u32		msg_off; /* only for always_invalidate=true */
	struct ibtrs_iu	*iu; /* send buffer for new rkey msg */
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

extern struct class *ibtrs_dev_class;

void close_sess(struct ibtrs_srv_sess *sess);

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
