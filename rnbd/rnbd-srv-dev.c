// SPDX-License-Identifier: GPL-2.0-or-later
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
 *
 * Copyright (c) 2018 - 2019 1&1 IONOS Cloud GmbH. All rights reserved.
 * Authors: Roman Penyaev <roman.penyaev@profitbricks.com>
 *          Jack Wang <jinpu.wang@cloud.ionos.com>
 *          Danil Kipnis <danil.kipnis@cloud.ionos.com>
 */

/* Copyright (c) 2019 1&1 IONOS SE. All rights reserved.
 * Authors: Jack Wang <jinpu.wang@cloud.ionos.com>
 *          Danil Kipnis <danil.kipnis@cloud.ionos.com>
 *          Guoqing Jiang <guoqing.jiang@cloud.ionos.com>
 *          Lutz Pogrell <lutz.pogrell@cloud.ionos.com>
 */
#undef pr_fmt
#define pr_fmt(fmt) KBUILD_MODNAME " L" __stringify(__LINE__) ": " fmt

#include "rnbd-srv-dev.h"
#include "rnbd-log.h"

struct rnbd_dev *rnbd_dev_open(const char *path, fmode_t flags,
				 struct bio_set *bs, rnbd_dev_io_fn io_cb)
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
	dev->ibd_bio_set	= bs;

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
}

/**
 *	rnbd_bio_map_kern	-	map kernel address into bio
 *	@q: the struct request_queue for the bio
 *	@data: pointer to buffer to map
 *	@bs: bio_set to use.
 *	@len: length in bytes
 *	@gfp_mask: allocation flags for bio allocation
 *
 *	Map the kernel address into a bio suitable for io to a block
 *	device. Returns an error pointer in case of error.
 */
static struct bio *rnbd_bio_map_kern(struct request_queue *q, void *data,
				      struct bio_set *bs,
				      unsigned int len, gfp_t gfp_mask)
{
	unsigned long kaddr = (unsigned long)data;
	unsigned long end = (kaddr + len + PAGE_SIZE - 1) >> PAGE_SHIFT;
	unsigned long start = kaddr >> PAGE_SHIFT;
	const int nr_pages = end - start;
	int offset, i;
	struct bio *bio;

	bio = bio_alloc_bioset(gfp_mask, nr_pages, bs);
	if (!bio)
		return ERR_PTR(-ENOMEM);

	offset = offset_in_page(kaddr);
	for (i = 0; i < nr_pages; i++) {
		unsigned int bytes = PAGE_SIZE - offset;

		if (len <= 0)
			break;

		if (bytes > len)
			bytes = len;

		if (bio_add_pc_page(q, bio, virt_to_page(data), bytes,
				    offset) < bytes) {
			/* we don't support partial mappings */
			bio_put(bio);
			return ERR_PTR(-EINVAL);
		}

		data += bytes;
		len -= bytes;
		offset = 0;
	}

	bio->bi_end_io = bio_put;
	return bio;
}

int rnbd_dev_submit_io(struct rnbd_dev *dev, sector_t sector, void *data,
			size_t len, u32 bi_size, enum rnbd_io_flags flags,
			short prio, void *priv)
{
	struct request_queue *q = bdev_get_queue(dev->bdev);
	struct rnbd_dev_blk_io *io;
	struct bio *bio;

	/* check if the buffer is suitable for bdev */
	if (unlikely(WARN_ON(!blk_rq_aligned(q, (unsigned long)data, len))))
		return -EINVAL;

	/* Generate bio with pages pointing to the rdma buffer */
	bio = rnbd_bio_map_kern(q, data, dev->ibd_bio_set, len, GFP_KERNEL);
	if (unlikely(IS_ERR(bio)))
		return PTR_ERR(bio);

	io = container_of(bio, struct rnbd_dev_blk_io, bio);

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
