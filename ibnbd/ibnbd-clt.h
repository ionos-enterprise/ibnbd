/*
 * InfiniBand Network Block Driver
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

#ifndef IBNBD_CLT_H
#define IBNBD_CLT_H

#include <linux/wait.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/blk-mq.h>
#include <linux/refcount.h>

#include "ibtrs.h"
#include "ibnbd-proto.h"
#include "ibnbd-log.h"

#define BMAX_SEGMENTS 31
#define RECONNECT_DELAY 30
#define MAX_RECONNECTS -1

enum ibnbd_clt_dev_state {
	DEV_STATE_INIT,
	DEV_STATE_MAPPED,
	DEV_STATE_MAPPED_DISCONNECTED,
	DEV_STATE_UNMAPPED,
};

struct ibnbd_iu_comp {
	wait_queue_head_t wait;
	int errno;
};

struct ibnbd_iu {
	union {
		struct request *rq; /* for block io */
		void *buf; /* for user messages */
	};
	struct ibtrs_tag	*tag;
	union {
		/* use to send msg associated with a dev */
		struct ibnbd_clt_dev *dev;
		/* use to send msg associated with a sess */
		struct ibnbd_clt_session *sess;
	};
	blk_status_t		status;
	struct scatterlist	sglist[BMAX_SEGMENTS];
	struct work_struct	work;
	int			errno;
	struct ibnbd_iu_comp	*comp;
};

struct ibnbd_cpu_qlist {
	struct list_head	requeue_list;
	spinlock_t		requeue_lock;
	unsigned int		cpu;
};

struct ibnbd_clt_session {
	struct list_head        list;
	struct ibtrs_clt        *ibtrs;
	wait_queue_head_t       ibtrs_waitq;
	bool                    ibtrs_ready;
	struct ibnbd_cpu_qlist	__percpu
				*cpu_queues;
	DECLARE_BITMAP(cpu_queues_bm, NR_CPUS);
	int	__percpu	*cpu_rr; /* per-cpu var for CPU round-robin */
	atomic_t		busy;
	int			queue_depth;
	u32			max_io_size;
	struct blk_mq_tag_set	tag_set;
	struct mutex		lock; /* protects state and devs_list */
	struct list_head        devs_list; /* list of struct ibnbd_clt_dev */
	refcount_t		refcount;
	char			sessname[NAME_MAX];
	u8			ver; /* protocol version */
};

/**
 * Submission queues.
 */
struct ibnbd_queue {
	struct list_head	requeue_list;
	unsigned long		in_list;
	struct ibnbd_clt_dev	*dev;
	struct blk_mq_hw_ctx	*hctx;
};

struct ibnbd_clt_dev {
	struct ibnbd_clt_session	*sess;
	struct request_queue	*queue;
	struct ibnbd_queue	*hw_queues;
	u32			device_id;
	/* local Idr index - used to track minor number allocations. */
	u32			clt_device_id;
	struct mutex		lock;
	enum ibnbd_clt_dev_state	dev_state;
	enum ibnbd_io_mode	io_mode; /* user requested */
	enum ibnbd_io_mode	remote_io_mode; /* server really used */
	char			pathname[NAME_MAX];
	enum ibnbd_access_mode	access_mode;
	bool			read_only;
	bool			rotational;
	u32			max_hw_sectors;
	u32			max_write_same_sectors;
	u32			max_discard_sectors;
	u32			discard_granularity;
	u32			discard_alignment;
	u16			secure_discard;
	u16			physical_block_size;
	u16			logical_block_size;
	u16			max_segments;
	size_t			nsectors;
	u64			size;		/* device size in bytes */
	struct list_head        list;
	struct gendisk		*gd;
	struct kobject		kobj;
	char			blk_symlink_name[NAME_MAX];
	refcount_t		refcount;
	struct work_struct	unmap_on_rmmod_work;
};

/* ibnbd-clt.c */

struct ibnbd_clt_dev *ibnbd_clt_map_device(const char *sessname,
					   struct ibtrs_addr *paths,
					   size_t path_cnt,
					   const char *pathname,
					   enum ibnbd_access_mode access_mode,
					   enum ibnbd_io_mode io_mode);
int ibnbd_clt_unmap_device(struct ibnbd_clt_dev *dev, bool force,
			   const struct attribute *sysfs_self);

int ibnbd_clt_remap_device(struct ibnbd_clt_dev *dev);
int ibnbd_clt_resize_disk(struct ibnbd_clt_dev *dev, size_t newsize);

/* ibnbd-clt-sysfs.c */

int ibnbd_clt_create_sysfs_files(void);

void ibnbd_clt_destroy_sysfs_files(void);
void ibnbd_clt_destroy_default_group(void);

void ibnbd_clt_remove_dev_symlink(struct ibnbd_clt_dev *dev);

#endif /* IBNBD_CLT_H */
