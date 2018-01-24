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

#undef pr_fmt
#define pr_fmt(fmt) KBUILD_MODNAME " L" __stringify(__LINE__) ": " fmt

#include "ibnbd-srv-dev.h"
#include "ibnbd-log.h"

#define IBNBD_DEV_MAX_FILEIO_ACTIVE_WORKERS 0

struct ibnbd_dev_file_io_work {
	struct ibnbd_dev	*dev;
	void			*priv;

	sector_t		sector;
	void			*data;
	size_t			len;
	size_t			bi_size;
	enum ibnbd_io_flags	flags;

	struct work_struct	work;
};

struct ibnbd_dev_blk_io {
	struct ibnbd_dev *dev;
	void		 *priv;
};

static struct workqueue_struct *fileio_wq;

int ibnbd_dev_init(void)
{
	fileio_wq = alloc_workqueue("%s", WQ_UNBOUND,
				    IBNBD_DEV_MAX_FILEIO_ACTIVE_WORKERS,
				    "ibnbd_server_fileio_wq");
	if (!fileio_wq)
		return -ENOMEM;

	return 0;
}

void ibnbd_dev_destroy(void)
{
	destroy_workqueue(fileio_wq);
}

static inline struct block_device *ibnbd_dev_open_bdev(const char *path,
						       fmode_t flags)
{
	return blkdev_get_by_path(path, flags, THIS_MODULE);
}

static int ibnbd_dev_blk_open(struct ibnbd_dev *dev, const char *path,
			      fmode_t flags)
{
	dev->bdev = ibnbd_dev_open_bdev(path, flags);
	return PTR_ERR_OR_ZERO(dev->bdev);
}

static int ibnbd_dev_vfs_open(struct ibnbd_dev *dev, const char *path,
			      fmode_t flags)
{
	int oflags = O_DSYNC; /* enable write-through */

	if (flags & FMODE_WRITE)
		oflags |= O_RDWR;
	else if (flags & FMODE_READ)
		oflags |= O_RDONLY;
	else
		return -EINVAL;

	dev->file = filp_open(path, oflags, 0);
	return PTR_ERR_OR_ZERO(dev->file);
}

struct ibnbd_dev *ibnbd_dev_open(const char *path, fmode_t flags,
				 enum ibnbd_io_mode mode, struct bio_set *bs,
				 ibnbd_dev_io_fn io_cb)
{
	struct ibnbd_dev *dev;
	int ret;

	dev = kzalloc(sizeof(*dev), GFP_KERNEL);
	if (!dev)
		return ERR_PTR(-ENOMEM);

	if (mode == IBNBD_BLOCKIO) {
		dev->blk_open_flags = flags;
		ret = ibnbd_dev_blk_open(dev, path, dev->blk_open_flags);
		if (ret)
			goto err;
	} else if (mode == IBNBD_FILEIO) {
		dev->blk_open_flags = FMODE_READ;
		ret = ibnbd_dev_blk_open(dev, path, dev->blk_open_flags);
		if (ret)
			goto err;

		ret = ibnbd_dev_vfs_open(dev, path, flags);
		if (ret)
			goto blk_put;
	}

	dev->blk_open_flags	= flags;
	dev->mode		= mode;
	dev->io_cb		= io_cb;
	bdevname(dev->bdev, dev->name);
	dev->ibd_bio_set	= bs;

	return dev;

blk_put:
	blkdev_put(dev->bdev, dev->blk_open_flags);
err:
	kfree(dev);
	return ERR_PTR(ret);
}

void ibnbd_dev_close(struct ibnbd_dev *dev)
{
	flush_workqueue(fileio_wq);
	blkdev_put(dev->bdev, dev->blk_open_flags);
	if (dev->mode == IBNBD_FILEIO)
		filp_close(dev->file, dev->file);
	kfree(dev);
}

static void ibnbd_dev_bi_end_io(struct bio *bio)
{
	struct ibnbd_dev_blk_io *io = bio->bi_private;

	io->dev->io_cb(io->priv, blk_status_to_errno(bio->bi_status));
	bio_put(bio);
	kfree(io);
}

static void bio_map_kern_endio(struct bio *bio)
{
	bio_put(bio);
}

/**
 *	ibnbd_bio_map_kern	-	map kernel address into bio
 *	@q: the struct request_queue for the bio
 *	@data: pointer to buffer to map
 *	@bs: bio_set to use.
 *	@len: length in bytes
 *	@gfp_mask: allocation flags for bio allocation
 *
 *	Map the kernel address into a bio suitable for io to a block
 *	device. Returns an error pointer in case of error.
 */
static struct bio *ibnbd_bio_map_kern(struct request_queue *q, void *data,
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

	bio->bi_end_io = bio_map_kern_endio;
	return bio;
}

static int ibnbd_dev_blk_submit_io(struct ibnbd_dev *dev, sector_t sector,
				   void *data, size_t len, u32 bi_size,
				   enum ibnbd_io_flags flags, void *priv)
{
	struct request_queue *q = bdev_get_queue(dev->bdev);
	struct ibnbd_dev_blk_io *io;
	struct bio *bio;

	/* check if the buffer is suitable for bdev */
	if (unlikely(WARN_ON(!blk_rq_aligned(q, (unsigned long)data, len))))
		return -EINVAL;

	/* Generate bio with pages pointing to the rdma buffer */
	bio = ibnbd_bio_map_kern(q, data, dev->ibd_bio_set, len, GFP_KERNEL);
	if (unlikely(IS_ERR(bio)))
		return PTR_ERR(bio);

	io = kmalloc(sizeof(*io), GFP_KERNEL);
	if (unlikely(!io)) {
		bio_put(bio);
		return -ENOMEM;
	}

	io->dev		= dev;
	io->priv	= priv;

	bio->bi_end_io		= ibnbd_dev_bi_end_io;
	bio->bi_private		= io;
	bio->bi_opf		= ibnbd_to_bio_flags(flags);
	bio->bi_iter.bi_sector	= sector;
	bio->bi_iter.bi_size	= bi_size;
	bio_set_dev(bio, dev->bdev);

	submit_bio(bio);

	return 0;
}

static int ibnbd_dev_file_handle_flush(struct ibnbd_dev_file_io_work *w,
				       loff_t start)
{
	int ret;
	loff_t end;
	int len = w->bi_size;

	if (len)
		end = start + len - 1;
	else
		end = LLONG_MAX;

	ret = vfs_fsync_range(w->dev->file, start, end, 1);
	if (unlikely(ret))
		pr_info_ratelimited("I/O FLUSH failed on %s, vfs_sync err: %d\n",
				    w->dev->name, ret);
	return ret;
}

static int ibnbd_dev_file_handle_fua(struct ibnbd_dev_file_io_work *w,
				     loff_t start)
{
	int ret;
	loff_t end;
	int len = w->bi_size;

	if (len)
		end = start + len - 1;
	else
		end = LLONG_MAX;

	ret = vfs_fsync_range(w->dev->file, start, end, 1);
	if (unlikely(ret))
		pr_info_ratelimited("I/O FUA failed on %s, vfs_sync err: %d\n",
				    w->dev->name, ret);
	return ret;
}

static int ibnbd_dev_file_handle_write_same(struct ibnbd_dev_file_io_work *w)
{
	int i;

	if (unlikely(WARN_ON(w->bi_size % w->len)))
		return -EINVAL;

	for (i = 1; i < w->bi_size / w->len; i++)
		memcpy(w->data + i * w->len, w->data, w->len);

	return 0;
}

static void ibnbd_dev_file_submit_io_worker(struct work_struct *w)
{
	struct ibnbd_dev_file_io_work *dev_work;
	struct file *f;
	int ret, len;
	loff_t off;

	dev_work = container_of(w, struct ibnbd_dev_file_io_work, work);
	off = dev_work->sector * ibnbd_dev_get_logical_bsize(dev_work->dev);
	f = dev_work->dev->file;
	len = dev_work->bi_size;

	if (ibnbd_op(dev_work->flags) == IBNBD_OP_FLUSH) {
		ret = ibnbd_dev_file_handle_flush(dev_work, off);
		if (unlikely(ret))
			goto out;
	}

	if (ibnbd_op(dev_work->flags) == IBNBD_OP_WRITE_SAME) {
		ret = ibnbd_dev_file_handle_write_same(dev_work);
		if (unlikely(ret))
			goto out;
	}

	/* TODO Implement support for DIRECT */
	if (dev_work->bi_size) {
		loff_t off_tmp = off;

		if (ibnbd_op(dev_work->flags) == IBNBD_OP_WRITE)
			ret = kernel_write(f, dev_work->data, dev_work->bi_size,
					   &off_tmp);
		else
			ret = kernel_read(f, dev_work->data, dev_work->bi_size,
					  &off_tmp);

		if (unlikely(ret < 0)) {
			goto out;
		} else if (unlikely(ret != dev_work->bi_size)) {
			/* TODO implement support for partial completions */
			ret = -EIO;
			goto out;
		} else {
			ret = 0;
		}
	}

	if (dev_work->flags & IBNBD_F_FUA)
		ret = ibnbd_dev_file_handle_fua(dev_work, off);
out:
	dev_work->dev->io_cb(dev_work->priv, ret);
	kfree(dev_work);
}

static int ibnbd_dev_file_submit_io(struct ibnbd_dev *dev, sector_t sector,
				    void *data, size_t len, size_t bi_size,
				    enum ibnbd_io_flags flags, void *priv)
{
	struct ibnbd_dev_file_io_work *w;

	if (!ibnbd_flags_supported(flags)) {
		pr_info_ratelimited("Unsupported I/O flags: 0x%x on device "
				    "%s\n", flags, dev->name);
		return -ENOTSUPP;
	}

	w = kmalloc(sizeof(*w), GFP_KERNEL);
	if (!w)
		return -ENOMEM;

	w->dev		= dev;
	w->priv		= priv;
	w->sector	= sector;
	w->data		= data;
	w->len		= len;
	w->bi_size	= bi_size;
	w->flags	= flags;
	INIT_WORK(&w->work, ibnbd_dev_file_submit_io_worker);

	if (unlikely(!queue_work(fileio_wq, &w->work))) {
		kfree(w);
		return -EEXIST;
	}

	return 0;
}

int ibnbd_dev_submit_io(struct ibnbd_dev *dev, sector_t sector, void *data,
			size_t len, u32 bi_size, enum ibnbd_io_flags flags,
			void *priv)
{
	if (dev->mode == IBNBD_FILEIO)
		return ibnbd_dev_file_submit_io(dev, sector, data, len, bi_size,
						flags, priv);
	else if (dev->mode == IBNBD_BLOCKIO)
		return ibnbd_dev_blk_submit_io(dev, sector, data, len, bi_size,
					       flags, priv);

	pr_warn("Submitting I/O to %s failed, dev->mode contains invalid "
		"value: '%d', memory corrupted?", dev->name, dev->mode);

	return -EINVAL;
}
