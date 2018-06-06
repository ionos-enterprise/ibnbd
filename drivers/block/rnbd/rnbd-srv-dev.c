// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * RDMA Network Block Driver
 *
 * Copyright (c) 2014 - 2018 ProfitBricks GmbH. All rights reserved.
 * Copyright (c) 2018 - 2019 1&1 IONOS Cloud GmbH. All rights reserved.
 * Copyright (c) 2019 - 2020 1&1 IONOS SE. All rights reserved.
 */
#undef pr_fmt
#define pr_fmt(fmt) KBUILD_MODNAME " L" __stringify(__LINE__) ": " fmt

#include "rnbd-srv-dev.h"
#include "rnbd-log.h"

struct rnbd_dev *rnbd_dev_open(const char *path, fmode_t flags,
			       void (*io_cb)(void *priv, int error))
{
	struct rnbd_dev *dev;
	int ret;

	dev = kzalloc(sizeof(*dev), GFP_KERNEL);
	if (!dev)
		return ERR_PTR(-ENOMEM);

	dev->blk_open_flags = flags;
	dev->bdev = blkdev_get_by_path(path, flags, THIS_MODULE);
	ret = PTR_ERR_OR_ZERO(dev->bdev);
	if (ret)
		goto err;

	dev->blk_open_flags	= flags;
	dev->io_cb		= io_cb;
	bdevname(dev->bdev, dev->name);

	return dev;

err:
	kfree(dev);
	return ERR_PTR(ret);
}

void rnbd_dev_close(struct rnbd_dev *dev)
{
	blkdev_put(dev->bdev, dev->blk_open_flags);
	kfree(dev);
}

static void rnbd_dev_bi_end_io(struct bio *bio)
{
	struct rnbd_dev_blk_io *io = bio->bi_private;

	io->dev->io_cb(io->priv, blk_status_to_errno(bio->bi_status));
	bio_put(bio);
	kfree(io);
}

int rnbd_dev_submit_io(struct rnbd_dev *dev, sector_t sector, void *data,
			size_t len, u32 bi_size, enum rnbd_io_flags flags,
			short prio, void *priv)
{
	struct request_queue *q = bdev_get_queue(dev->bdev);
	struct rnbd_dev_blk_io *io;
	struct bio *bio;

	/* check if the buffer is suitable for bdev */
	if (WARN_ON(!blk_rq_aligned(q, (unsigned long)data, len)))
		return -EINVAL;

	/* Generate bio with pages pointing to the rdma buffer */
	bio = bio_map_kern(q, data, len, GFP_KERNEL);
	if (IS_ERR(bio))
		return PTR_ERR(bio);

	io = kmalloc(sizeof(*io), GFP_KERNEL);
	if (unlikely(!io)) {
		bio_put(bio);
		return -ENOMEM;
	}

	io->dev		= dev;
	io->priv	= priv;

	bio->bi_end_io		= rnbd_dev_bi_end_io;
	bio->bi_private		= io;
	bio->bi_opf		= rnbd_to_bio_flags(flags);
	bio->bi_iter.bi_sector	= sector;
	bio->bi_iter.bi_size	= bi_size;
	bio_set_prio(bio, prio);
	bio_set_dev(bio, dev->bdev);

	submit_bio(bio);

	return 0;
}
