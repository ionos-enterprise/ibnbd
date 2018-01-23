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

#ifndef IBNBD_SRV_DEV_H
#define IBNBD_SRV_DEV_H

#include <linux/fs.h>
#include "ibnbd-proto.h"

typedef void ibnbd_dev_io_fn(void *priv, int error);

struct ibnbd_dev {
	struct block_device	*bdev;
	struct bio_set		*ibd_bio_set;
	struct file		*file;
	fmode_t			blk_open_flags;
	enum ibnbd_io_mode	mode;
	char			name[BDEVNAME_SIZE];
	ibnbd_dev_io_fn		*io_cb;
};

/** ibnbd_dev_init() - Initialize ibnbd_dev
 *
 * This functions initialized the ibnbd-dev component.
 * It has to be called 1x time before ibnbd_dev_open() is used
 */
int ibnbd_dev_init(void);

/** ibnbd_dev_destroy() - Destroy ibnbd_dev
 *
 * This functions destroys the ibnbd-dev component.
 * It has to be called after the last device was closed.
 */
void ibnbd_dev_destroy(void);

/**
 * ibnbd_dev_open() - Open a device
 * @flags:	open flags
 * @mode:	open via VFS or block layer
 * @bs:		bio_set to use during block io,
 * @io_cb:	is called when I/O finished
 */
struct ibnbd_dev *ibnbd_dev_open(const char *path, fmode_t flags,
				 enum ibnbd_io_mode mode, struct bio_set *bs,
				 ibnbd_dev_io_fn io_cb);

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
	if (dev->mode == IBNBD_BLOCKIO)
		return blk_queue_secure_erase(bdev_get_queue(dev->bdev));
	return 0;
}

static inline int ibnbd_dev_get_max_discard_sects(const struct ibnbd_dev *dev)
{
	if (!blk_queue_discard(bdev_get_queue(dev->bdev)))
		return 0;

	if (dev->mode == IBNBD_BLOCKIO)
		return blk_queue_get_max_sectors(bdev_get_queue(dev->bdev),
						 REQ_OP_DISCARD);
	return 0;
}

static inline int ibnbd_dev_get_discard_granularity(const struct ibnbd_dev *dev)
{
	if (dev->mode == IBNBD_BLOCKIO)
		return bdev_get_queue(dev->bdev)->limits.discard_granularity;
	return 0;
}

static inline int ibnbd_dev_get_discard_alignment(const struct ibnbd_dev *dev)
{
	if (dev->mode == IBNBD_BLOCKIO)
		return bdev_get_queue(dev->bdev)->limits.discard_alignment;
	return 0;
}

/**
 * ibnbd_dev_submit_io() - Submit an I/O to the disk
 * @dev:	device to that the I/O is submitted
 * @sector:	address to read/write data to
 * @data:	I/O data to write or buffer to read I/O date into
 * @len:	length of @data
 * @bi_size:	Amount of data that will be read/written
 * @priv:	private data passed to @io_fn
 */
int ibnbd_dev_submit_io(struct ibnbd_dev *dev, sector_t sector, void *data,
			size_t len, u32 bi_size, enum ibnbd_io_flags flags,
			void *priv);

#endif /* IBNBD_SRV_DEV_H */
