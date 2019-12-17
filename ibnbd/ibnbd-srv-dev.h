/* SPDX-License-Identifier: GPL-2.0-or-later */
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
#ifndef IBNBD_SRV_DEV_H
#define IBNBD_SRV_DEV_H

#include <linux/fs.h>
#include "ibnbd-proto.h"

typedef void ibnbd_dev_io_fn(void *priv, int error);

struct ibnbd_dev {
	struct block_device	*bdev;
	struct bio_set		*ibd_bio_set;
	fmode_t			blk_open_flags;
	char			name[BDEVNAME_SIZE];
	ibnbd_dev_io_fn		*io_cb;
};

struct ibnbd_dev_blk_io {
	struct ibnbd_dev *dev;
	void		 *priv;
	/* have to be last member for front_pad usage of bioset_init */
	struct bio	bio;
};

/**
 * ibnbd_dev_open() - Open a device
 * @flags:	open flags
 * @bs:		bio_set to use during block io,
 * @io_cb:	is called when I/O finished
 */
struct ibnbd_dev *ibnbd_dev_open(const char *path, fmode_t flags,
				 struct bio_set *bs, ibnbd_dev_io_fn io_cb);

/**
 * ibnbd_dev_close() - Close a device
 */
void ibnbd_dev_close(struct ibnbd_dev *dev);

static inline int ibnbd_dev_get_logical_bsize(const struct ibnbd_dev *dev)
{
	return bdev_logical_block_size(dev->bdev);
}

static inline int ibnbd_dev_get_phys_bsize(const struct ibnbd_dev *dev)
{
	return bdev_physical_block_size(dev->bdev);
}

static inline int ibnbd_dev_get_max_segs(const struct ibnbd_dev *dev)
{
	return queue_max_segments(bdev_get_queue(dev->bdev));
}

static inline int ibnbd_dev_get_max_hw_sects(const struct ibnbd_dev *dev)
{
	return queue_max_hw_sectors(bdev_get_queue(dev->bdev));
}

static inline int
ibnbd_dev_get_max_write_same_sects(const struct ibnbd_dev *dev)
{
	return bdev_write_same(dev->bdev);
}

static inline int ibnbd_dev_get_secure_discard(const struct ibnbd_dev *dev)
{
	return blk_queue_secure_erase(bdev_get_queue(dev->bdev));
}

static inline int ibnbd_dev_get_max_discard_sects(const struct ibnbd_dev *dev)
{
	if (!blk_queue_discard(bdev_get_queue(dev->bdev)))
		return 0;

	return blk_queue_get_max_sectors(bdev_get_queue(dev->bdev),
					 REQ_OP_DISCARD);
}

static inline int ibnbd_dev_get_discard_granularity(const struct ibnbd_dev *dev)
{
	return bdev_get_queue(dev->bdev)->limits.discard_granularity;
}

static inline int ibnbd_dev_get_discard_alignment(const struct ibnbd_dev *dev)
{
	return bdev_get_queue(dev->bdev)->limits.discard_alignment;
}

/**
 * ibnbd_dev_submit_io() - Submit an I/O to the disk
 * @dev:	device to that the I/O is submitted
 * @sector:	address to read/write data to
 * @data:	I/O data to write or buffer to read I/O date into
 * @len:	length of @data
 * @bi_size:	Amount of data that will be read/written
 * @prio:       IO priority
 * @priv:	private data passed to @io_fn
 */
int ibnbd_dev_submit_io(struct ibnbd_dev *dev, sector_t sector, void *data,
			size_t len, u32 bi_size, enum ibnbd_io_flags flags,
			short prio, void *priv);

#endif /* IBNBD_SRV_DEV_H */
