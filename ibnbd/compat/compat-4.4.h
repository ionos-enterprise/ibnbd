/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2018 - 2019 1&1 IONOS Cloud GmbH. All rights reserved.
 * Authors: Roman Penyaev <roman.penyaev@profitbricks.com>
 */

#ifndef LINUX_4_4_COMPAT_H
#define LINUX_4_4_COMPAT_H

/*
 * linux/sysfs.h
 */
#define sysfs_remove_file_self ORIGINAL_sysfs_remove_file_self
#include <linux/sysfs.h>
#include <linux/device.h>
#undef sysfs_remove_file_self

static inline
void sysfs_remove_file_self(struct kobject *kobj,
			    const struct attribute *attr)
{
       struct device_attribute dattr = {
               .attr.name = attr->name
       };
       struct device *device;

       /*
        * Unfortunately original sysfs_remove_file_self() is not exported,
        * so consider this as a hack to call self removal of a sysfs entry
        * just using another "door".
        */

       device = container_of(kobj, typeof(*device), kobj);
       device_remove_file_self(device, &dattr);
}

#include <linux/version.h>
#include <linux/blk-mq.h>

#define __GFP_RETRY_MAYFAIL __GFP_REPEAT

typedef int blk_status_t;
#define bi_status bi_error
#define bi_opf bi_rw
#define bio_set_dev(bio, bdev) ((bio)->bi_bdev = bdev)
#define rq_flags cmd_flags

#define op_is_flush(op) ((op) & REQ_FUA)
#define op_is_sync(op) rw_is_sync(op)

static inline int req_op(struct request *rq)
{
	if (rq->cmd_flags & REQ_WRITE_SAME)
		return REQ_WRITE_SAME;
	else if (rq->cmd_flags & REQ_DISCARD)
		return (REQ_DISCARD | REQ_WRITE);
	else if (rq->cmd_flags & REQ_FLUSH)
		return REQ_FLUSH;
	else if (rq->cmd_flags & REQ_SECURE)
		return REQ_SECURE;
	else if (rq->cmd_flags & REQ_WRITE)
		return REQ_WRITE;
	else
		return READ;
}

#define REQ_OP_READ         READ
#define REQ_OP_WRITE        REQ_WRITE
#define REQ_OP_WRITE_SAME   REQ_WRITE_SAME
#define REQ_OP_FLUSH        REQ_FLUSH
#define REQ_OP_DISCARD      (REQ_DISCARD | REQ_WRITE)
#define REQ_OP_SECURE_ERASE REQ_SECURE
#define REQ_OP_WRITE_SAME   REQ_WRITE_SAME
#define REQ_PREFLUSH        0

#define RQF_DONTPREP   REQ_DONTPREP

#define BLK_STS_OK        BLK_MQ_RQ_QUEUE_OK
#define BLK_STS_IOERR     BLK_MQ_RQ_QUEUE_ERROR
#define BLK_STS_RESOURCE  BLK_MQ_RQ_QUEUE_BUSY

#define QUEUE_FLAG_SECERASE  QUEUE_FLAG_SECDISCARD

#define BIOSET_NEED_BVECS  1

struct backport_blk_mq_tag_set;
typedef int (backport_init_request_fn)(struct backport_blk_mq_tag_set *set,
				       struct request *,
				       unsigned int, unsigned int);

struct backport_blk_mq_ops {
	/*
	 * Queue request
	 */
	queue_rq_fn		*queue_rq;

	/*
	 * Map to specific hardware queue
	 */
	map_queue_fn		*map_queue;

	/*
	 * Called on request timeout
	 */
	timeout_fn		*timeout;

	/*
	 * Called to poll for completion of a specific tag.
	 */
	poll_fn			*poll;

	softirq_done_fn		*complete;

	/*
	 * Called when the block layer side of a hardware queue has been
	 * set up, allowing the driver to allocate/init matching structures.
	 * Ditto for exit/teardown.
	 */
	init_hctx_fn		*init_hctx;
	exit_hctx_fn		*exit_hctx;

	/*
	 * Called for every command allocated by the block layer to allow
	 * the driver to set up driver specific data.
	 *
	 * Tag greater than or equal to queue_depth is for setting up
	 * flush request.
	 *
	 * Ditto for exit/teardown.
	 */
	init_request_fn		*orig_init_request;
	exit_request_fn		*exit_request;

	/* Compat goes here */
	backport_init_request_fn		*init_request;
};

struct backport_blk_mq_tag_set {
	struct backport_blk_mq_ops	*ops;
	unsigned int		nr_hw_queues;
	unsigned int		queue_depth;	/* max hw supported */
	unsigned int		reserved_tags;
	unsigned int		cmd_size;	/* per-request extra data */
	int			numa_node;
	unsigned int		timeout;
	unsigned int		flags;		/* BLK_MQ_F_* */
	void			*driver_data;

	struct blk_mq_tags	**tags;

	struct mutex		tag_list_lock;
	struct list_head	tag_list;
};

static const struct {
	int             errno;
	const char      *name;
} blk_errors[] = {
	[BLK_STS_OK]            = { 0,          "" },
	[BLK_STS_RESOURCE]      = { -ENOMEM,    "kernel resource" },
	/* everything else not covered above: */
	[BLK_STS_IOERR]         = { -EIO,       "I/O" },
};

static inline int blk_status_to_errno(blk_status_t status)
{
	int idx = (__force int)status;

	if (idx >= ARRAY_SIZE(blk_errors)) {
		/*
		 * Negative errno will be propagated to unsigned
		 * of ARRAY_SIZE and be always greater than array
		 * size, so here we have normal errno, so return it.
		 */
		return idx;
	}
	return blk_errors[idx].errno;
}

static inline void backport_blk_mq_complete_request(struct request *rq)
{
	blk_mq_complete_request(rq, 0);
}

static inline void
backport_blk_queue_write_cache(struct request_queue *q, bool wc, bool fua)
{
	blk_queue_flush(q, REQ_FLUSH | (fua ? REQ_FUA : 0));
}

static inline void
backport_blk_queue_max_discard_segments(struct request_queue *q,
		unsigned short max_segments)
{
	return;
}

static inline void
backport_blk_queue_flag_set(unsigned int flag, struct request_queue *q)
{
	unsigned long flags;

	spin_lock_irqsave(q->queue_lock, flags);
	queue_flag_set(flag, q);
	spin_unlock_irqrestore(q->queue_lock, flags);
}

static inline blk_qc_t backport_submit_bio(struct bio *bio)
{
	return submit_bio(bio->bi_rw, bio);
}

static inline struct request_queue *
backport_blk_mq_init_queue(struct backport_blk_mq_tag_set *set)
{
	return blk_mq_init_queue((struct blk_mq_tag_set *)set);
}

static inline int
backport_init_request(void *data, struct request *rq,
		      unsigned int hctx_idx,
		      unsigned int request_idx,
		      unsigned int numa_node)
{
	struct backport_blk_mq_tag_set *set = data;

	(void)request_idx;

	return set->ops->init_request(set, rq, hctx_idx, numa_node);
}

static inline int
backport_blk_mq_alloc_tag_set(struct backport_blk_mq_tag_set *set)
{

	BUG_ON(set->driver_data);
	set->driver_data = set;
	set->ops->orig_init_request = backport_init_request;
	if (!set->ops->map_queue)
		set->ops->map_queue = blk_mq_map_queue;

	return blk_mq_alloc_tag_set((struct blk_mq_tag_set *)set);
}

static inline void
backport_blk_mq_free_tag_set(struct backport_blk_mq_tag_set *set)
{
	blk_mq_free_tag_set((struct blk_mq_tag_set *)set);
}

static inline bool
backport_blk_mq_run_hw_queue(struct blk_mq_hw_ctx *hctx, bool async)
{
	blk_mq_delay_queue(hctx, 0);
	return true;
}

static inline void
backport_blk_mq_delay_run_hw_queue(struct blk_mq_hw_ctx *hctx,
				   unsigned long msecs)
{
	blk_mq_delay_queue(hctx, msecs);
}

static inline ssize_t
backport_kernel_read(struct file *file, void *buf, size_t count,
		     loff_t *pos)
{
	return kernel_read(file, *pos, buf, count);
}

static inline ssize_t
backport_kernel_write(struct file *file, const void *buf, size_t count,
		      loff_t *pos)
{
	return kernel_write(file, buf, count, *pos);
}

static inline int
backport_bioset_init(struct bio_set *bs, unsigned int pool_size,
                     unsigned int front_pad, int flags)
{
    struct bio_set *tbs;

    tbs = bioset_create(pool_size, front_pad);
    if (unlikely(!tbs))
        return -ENOMEM;

    memcpy(bs, tbs, sizeof(*tbs));
    kfree(tbs);
    return 0;
}

static inline void
backport_bioset_exit(struct bio_set *bs)
{
    struct bio_set *tbs;

    tbs = kzalloc(sizeof(*tbs), GFP_KERNEL);
    if (WARN_ON(!tbs))
        return;
    memcpy(tbs, bs, sizeof(*bs));
    bioset_free(tbs);
}

#define blk_mq_ops backport_blk_mq_ops
#define blk_mq_tag_set backport_blk_mq_tag_set
#define blk_mq_init_queue backport_blk_mq_init_queue
#define blk_mq_alloc_tag_set backport_blk_mq_alloc_tag_set
#define blk_mq_free_tag_set backport_blk_mq_free_tag_set
#define blk_mq_complete_request backport_blk_mq_complete_request
#define blk_mq_run_hw_queue backport_blk_mq_run_hw_queue
#define blk_mq_delay_run_hw_queue backport_blk_mq_delay_run_hw_queue
#define blk_queue_write_cache backport_blk_queue_write_cache
#define blk_queue_max_discard_segments backport_blk_queue_max_discard_segments
#define blk_queue_secure_erase blk_queue_secdiscard
#define blk_queue_flag_set backport_blk_queue_flag_set
#define submit_bio backport_submit_bio
#define kernel_read backport_kernel_read
#define kernel_write backport_kernel_write
#define bioset_init backport_bioset_init
#define bioset_exit backport_bioset_exit

#endif /* LINUX_4_4_COMPAT_H */
