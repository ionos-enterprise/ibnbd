#ifndef LINUX_4_4_COMPAT_H
#define LINUX_4_4_COMPAT_H

#include <linux/version.h>
#include <linux/blk-mq.h>

#define __GFP_RETRY_MAYFAIL __GFP_REPEAT

typedef int blk_status_t;
#define bi_status bi_error
#define bi_opf bi_rw
#define bio_set_dev(bio, bdev) ((bio)->bi_bdev = bdev)
#define req_op(rq) ((rq)->cmd_flags)
#define rq_flags cmd_flags

#define REQ_OP_WRITE        REQ_WRITE
#define REQ_OP_WRITE_SAME   REQ_WRITE_SAME
#define REQ_OP_FLUSH        REQ_FLUSH
#define REQ_OP_DISCARD      REQ_DISCARD
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

	if (WARN_ON_ONCE(idx >= ARRAY_SIZE(blk_errors)))
		return -EIO;
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

static inline blk_qc_t backport_submit_bio(struct bio *bio)
{
	return submit_bio(bio->bi_rw, bio);
}

static inline struct bio_set *
backport_bioset_create(unsigned int pool_size, unsigned int front_pad, int flags)
{
	(void)flags;
	return bioset_create(pool_size, front_pad);
}

static inline struct request_queue *
backport_blk_mq_init_queue(struct backport_blk_mq_tag_set *set)
{
	return blk_mq_init_queue((struct blk_mq_tag_set *)set);
}

struct tags_priv {
	struct backport_blk_mq_tag_set *set;
	void *data;
};

static inline int
backport_init_request(void *data, struct request *rq,
		      unsigned int hctx_idx,
		      unsigned int request_idx,
		      unsigned int numa_node)
{
	struct tags_priv *p = data;
	int err;

	(void)request_idx;
	p->set->driver_data = p->data;
	err = p->set->ops->init_request(p->set, rq, hctx_idx, numa_node);
	p->set->driver_data = p;

	return err;
}

static inline int
backport_blk_mq_alloc_tag_set(struct backport_blk_mq_tag_set *set)
{
	struct tags_priv *p;
	int err;

	p = kmalloc(sizeof(*p), GFP_KERNEL);
	if (unlikely(!p))
		return -ENOMEM;

	p->set = set;
	p->data = set->driver_data;

	set->driver_data = p;
	set->ops->orig_init_request = backport_init_request;
	if (!set->ops->map_queue)
		set->ops->map_queue = blk_mq_map_queue;

	err = blk_mq_alloc_tag_set((struct blk_mq_tag_set *)set);
	if (unlikely(err))
		kfree(p);

	return err;
}

static inline void
backport_blk_mq_free_tag_set(struct backport_blk_mq_tag_set *set)
{
	struct tags_priv *p = set->driver_data;

	blk_mq_free_tag_set((struct blk_mq_tag_set *)set);
	kfree(p);
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

#define blk_mq_ops backport_blk_mq_ops
#define blk_mq_tag_set backport_blk_mq_tag_set
#define blk_mq_init_queue backport_blk_mq_init_queue
#define blk_mq_alloc_tag_set backport_blk_mq_alloc_tag_set
#define blk_mq_free_tag_set backport_blk_mq_free_tag_set
#define blk_mq_complete_request backport_blk_mq_complete_request
#define blk_queue_write_cache backport_blk_queue_write_cache
#define blk_queue_secure_erase blk_queue_secdiscard
#define submit_bio backport_submit_bio
#define bioset_create backport_bioset_create
#define kernel_read backport_kernel_read
#define kernel_write backport_kernel_write

#endif /* LINUX_4_4_COMPAT_H */
