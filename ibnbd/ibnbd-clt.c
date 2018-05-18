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

#undef pr_fmt
#define pr_fmt(fmt) KBUILD_MODNAME " L" __stringify(__LINE__) ": " fmt

#include <linux/module.h>
#include <linux/blkdev.h>
#include <linux/hdreg.h>
#include <linux/scatterlist.h>
#include <linux/idr.h>

#include "ibnbd-clt.h"

MODULE_AUTHOR("ibnbd@profitbricks.com");
MODULE_DESCRIPTION("InfiniBand Network Block Device Client");
MODULE_VERSION(IBNBD_VER_STRING);
MODULE_LICENSE("GPL");

/*
 * This is for closing devices when unloading the module:
 * we might be closing a lot (>256) of devices in parallel
 * and it is better not to use the system_wq.
 */
static struct workqueue_struct *unload_wq;
static int ibnbd_client_major;
static DEFINE_IDA(index_ida);
static DEFINE_MUTEX(ida_lock);
static DEFINE_MUTEX(sess_lock);
static LIST_HEAD(sess_list);

static bool softirq_enable;
module_param(softirq_enable, bool, 0444);
MODULE_PARM_DESC(softirq_enable, "finish request in softirq_fn."
		 " (default: 0)");
/*
 * Maximum number of partitions an instance can have.
 * 6 bits = 64 minors = 63 partitions (one minor is used for the device itself)
 */
#define IBNBD_PART_BITS		6
#define KERNEL_SECTOR_SIZE      512

static inline bool ibnbd_clt_get_sess(struct ibnbd_clt_session *sess)
{
	return refcount_inc_not_zero(&sess->refcount);
}

static void free_sess(struct ibnbd_clt_session *sess);

static void ibnbd_clt_put_sess(struct ibnbd_clt_session *sess)
{
	might_sleep();

	if (refcount_dec_and_test(&sess->refcount))
		free_sess(sess);
}

static inline bool ibnbd_clt_dev_is_mapped(struct ibnbd_clt_dev *dev)
{
	return dev->dev_state == DEV_STATE_MAPPED;
}

static void ibnbd_clt_put_dev(struct ibnbd_clt_dev *dev)
{
	might_sleep();

	if (refcount_dec_and_test(&dev->refcount)) {
		mutex_lock(&ida_lock);
		ida_simple_remove(&index_ida, dev->clt_device_id);
		mutex_unlock(&ida_lock);
		kfree(dev->hw_queues);
		ibnbd_clt_put_sess(dev->sess);
		kfree(dev);
	}
}

static inline bool ibnbd_clt_get_dev(struct ibnbd_clt_dev *dev)
{
	return refcount_inc_not_zero(&dev->refcount);
}

static int ibnbd_clt_set_dev_attr(struct ibnbd_clt_dev *dev,
				  const struct ibnbd_msg_open_rsp *rsp)
{
	struct ibnbd_clt_session *sess = dev->sess;

	if (unlikely(!rsp->logical_block_size))
		return -EINVAL;

	dev->device_id		    = le32_to_cpu(rsp->device_id);
	dev->nsectors		    = le64_to_cpu(rsp->nsectors);
	dev->logical_block_size	    = le16_to_cpu(rsp->logical_block_size);
	dev->physical_block_size    = le16_to_cpu(rsp->physical_block_size);
	dev->max_write_same_sectors = le32_to_cpu(rsp->max_write_same_sectors);
	dev->max_discard_sectors    = le32_to_cpu(rsp->max_discard_sectors);
	dev->discard_granularity    = le32_to_cpu(rsp->discard_granularity);
	dev->discard_alignment	    = le32_to_cpu(rsp->discard_alignment);
	dev->secure_discard	    = le16_to_cpu(rsp->secure_discard);
	dev->rotational		    = rsp->rotational;
	dev->remote_io_mode	    = rsp->io_mode;

	dev->max_hw_sectors = sess->max_io_size / dev->logical_block_size;
	dev->max_segments = BMAX_SEGMENTS;

	if (dev->remote_io_mode == IBNBD_BLOCKIO) {
		dev->max_hw_sectors = min_t(u32, dev->max_hw_sectors,
					    le32_to_cpu(rsp->max_hw_sectors));
		dev->max_segments = min_t(u16, dev->max_segments,
					  le16_to_cpu(rsp->max_segments));
	}

	return 0;
}

static int ibnbd_clt_revalidate_disk(struct ibnbd_clt_dev *dev,
				     size_t new_nsectors)
{
	int err = 0;

	ibnbd_info(dev, "Device size changed from %zu to %zu sectors\n",
		   dev->nsectors, new_nsectors);
	dev->nsectors = new_nsectors;
	set_capacity(dev->gd,
		     dev->nsectors * (dev->logical_block_size /
				      KERNEL_SECTOR_SIZE));
	err = revalidate_disk(dev->gd);
	if (err)
		ibnbd_err(dev, "Failed to change device size from"
			  " %zu to %zu, err: %d\n", dev->nsectors,
			  new_nsectors, err);
	return err;
}

static int process_msg_open_rsp(struct ibnbd_clt_dev *dev,
				struct ibnbd_msg_open_rsp *rsp)
{
	int err = 0;

	mutex_lock(&dev->lock);
	if (dev->dev_state == DEV_STATE_UNMAPPED) {
		ibnbd_info(dev, "Ignoring Open-Response message from server for "
			   " unmapped device\n");
		err = -ENOENT;
		goto out;
	}
	if (dev->dev_state == DEV_STATE_MAPPED_DISCONNECTED) {
		u64 nsectors = le64_to_cpu(rsp->nsectors);

		/*
		 * If the device was remapped and the size changed in the
		 * meantime we need to revalidate it
		 */
		if (dev->nsectors != nsectors)
			ibnbd_clt_revalidate_disk(dev, nsectors);
		ibnbd_info(dev, "Device online, device remapped successfully\n");
	}
	err = ibnbd_clt_set_dev_attr(dev, rsp);
	if (unlikely(err))
		goto out;
	dev->dev_state = DEV_STATE_MAPPED;

out:
	mutex_unlock(&dev->lock);

	return err;
}

int ibnbd_clt_resize_disk(struct ibnbd_clt_dev *dev, size_t newsize)
{
	int ret = 0;

	mutex_lock(&dev->lock);
	if (dev->dev_state != DEV_STATE_MAPPED) {
		pr_err("Failed to set new size of the device, "
		       "device is not opened\n");
		ret = -ENOENT;
		goto out;
	}
	ret = ibnbd_clt_revalidate_disk(dev, newsize);

out:
	mutex_unlock(&dev->lock);

	return ret;
}

static inline void ibnbd_clt_dev_requeue(struct ibnbd_queue *q)
{
	if (WARN_ON(!q->hctx))
		return;

	/* We can come here from interrupt, thus async=true */
	blk_mq_run_hw_queue(q->hctx, true);
}

enum {
	IBNBD_DELAY_10ms   = 10,
	IBNBD_DELAY_IFBUSY = -1,
};

/**
 * ibnbd_get_cpu_qlist() - finds a list with HW queues to be requeued
 *
 * Description:
 *     Each CPU has a list of HW queues, which needs to be requeed.  If a list
 *     is not empty - it is marked with a bit.  This function finds first
 *     set bit in a bitmap and returns corresponding CPU list.
 */
static struct ibnbd_cpu_qlist *
ibnbd_get_cpu_qlist(struct ibnbd_clt_session *sess, int cpu)
{
	int bit;

	/* First half */
	bit = find_next_bit(sess->cpu_queues_bm, nr_cpu_ids, cpu);
	if (bit < nr_cpu_ids) {
		return per_cpu_ptr(sess->cpu_queues, bit);
	} else if (cpu != 0) {
		/* Second half */
		bit = find_next_bit(sess->cpu_queues_bm, cpu, 0);
		if (bit < cpu)
			return per_cpu_ptr(sess->cpu_queues, bit);
	}

	return NULL;
}

static inline int nxt_cpu(int cpu)
{
	return (cpu + 1) % nr_cpu_ids;
}

/**
 * ibnbd_requeue_if_needed() - requeue if CPU queue is marked as non empty
 *
 * Description:
 *     Each CPU has it's own list of HW queues, which should be requeued.
 *     Function finds such list with HW queues, takes a list lock, picks up
 *     the first HW queue out of the list and requeues it.
 *
 * Return:
 *     True if the queue was requeued, false otherwise.
 *
 * Context:
 *     Does not matter.
 */
static inline bool ibnbd_requeue_if_needed(struct ibnbd_clt_session *sess)
{
	struct ibnbd_queue *q = NULL;
	struct ibnbd_cpu_qlist *cpu_q;
	unsigned long flags;
	int *cpup;

	/*
	 * To keep fairness and not to let other queues starve we always
	 * try to wake up someone else in round-robin manner.  That of course
	 * increases latency but queues always have a chance to be executed.
	 */
	cpup = get_cpu_ptr(sess->cpu_rr);
	for (cpu_q = ibnbd_get_cpu_qlist(sess, nxt_cpu(*cpup)); cpu_q;
	     cpu_q = ibnbd_get_cpu_qlist(sess, nxt_cpu(cpu_q->cpu))) {
		if (!spin_trylock_irqsave(&cpu_q->requeue_lock, flags))
			continue;
		if (likely(test_bit(cpu_q->cpu, sess->cpu_queues_bm))) {
			q = list_first_entry_or_null(&cpu_q->requeue_list,
						     typeof(*q), requeue_list);
			if (WARN_ON(!q))
				goto clear_bit;
			list_del_init(&q->requeue_list);
			clear_bit_unlock(0, &q->in_list);

			if (list_empty(&cpu_q->requeue_list)) {
				/* Clear bit if nothing is left */
clear_bit:
				clear_bit(cpu_q->cpu, sess->cpu_queues_bm);
			}
		}
		spin_unlock_irqrestore(&cpu_q->requeue_lock, flags);

		if (q)
			break;
	}

	/**
	 * Saves the CPU that is going to be requeued on the per-cpu var. Just
	 * incrementing it doesn't work because ibnbd_get_cpu_qlist() will
	 * always return the first CPU with something on the queue list when the
	 * value stored on the var is greater than the last CPU with something
	 * on the list.
	 */
	if (cpu_q)
		*cpup = cpu_q->cpu;
	put_cpu_var(sess->cpu_rr);

	if (q)
		ibnbd_clt_dev_requeue(q);

	return !!q;
}

/**
 * ibnbd_requeue_all_if_idle() - requeue all queues left in the list if
 *     session is idling (there are no requests in-flight).
 *
 * Description:
 *     This function tries to rerun all stopped queues if there are no
 *     requests in-flight anymore.  This function tries to solve an obvious
 *     problem, when number of tags < than number of queues (hctx), which
 *     are stopped and put to sleep.  If last tag, which has been just put,
 *     does not wake up all left queues (hctxs), IO requests hang forever.
 *
 *     That can happen when all number of tags, say N, have been exhausted
 *     from one CPU, and we have many block devices per session, say M.
 *     Each block device has it's own queue (hctx) for each CPU, so eventually
 *     we can put that number of queues (hctxs) to sleep: M x nr_cpu_ids.
 *     If number of tags N < M x nr_cpu_ids finally we will get an IO hang.
 *
 *     To avoid this hang last caller of ibnbd_put_tag() (last caller is the
 *     one who observes sess->busy == 0) must wake up all remaining queues.
 *
 * Context:
 *     Does not matter.
 */
static inline void ibnbd_requeue_all_if_idle(struct ibnbd_clt_session *sess)
{
	bool requeued;

	do {
		requeued = ibnbd_requeue_if_needed(sess);
	} while (atomic_read(&sess->busy) == 0 && requeued);
}

static struct ibtrs_tag *ibnbd_get_tag(struct ibnbd_clt_session *sess,
				       enum ibtrs_clt_con_type con_type,
				       int wait)
{
	struct ibtrs_tag *tag;

	tag = ibtrs_clt_get_tag(sess->ibtrs, con_type,
				wait ? IBTRS_TAG_WAIT : IBTRS_TAG_NOWAIT);
	if (likely(tag))
		/* We have a subtle rare case here, when all tags can be
		 * consumed before busy counter increased.  This is safe,
		 * because loser will get NULL as a tag, observe 0 busy
		 * counter and immediately restart the queue himself.
		 */
		atomic_inc(&sess->busy);

	return tag;
}

static void ibnbd_put_tag(struct ibnbd_clt_session *sess, struct ibtrs_tag *tag)
{
	ibtrs_clt_put_tag(sess->ibtrs, tag);
	atomic_dec(&sess->busy);
	/* Paired with ibnbd_clt_dev_add_to_requeue().  Decrement first
	 * and then check queue bits.
	 */
	smp_mb__after_atomic();
	ibnbd_requeue_all_if_idle(sess);
}

static struct ibnbd_iu *ibnbd_get_iu(struct ibnbd_clt_session *sess,
				     enum ibtrs_clt_con_type con_type,
				     int wait)
{
	struct ibnbd_iu *iu;
	struct ibtrs_tag *tag;

	tag = ibnbd_get_tag(sess, con_type,
			    wait ? IBTRS_TAG_WAIT : IBTRS_TAG_NOWAIT);
	if (unlikely(!tag))
		return NULL;
	iu = ibtrs_tag_to_pdu(tag);
	iu->tag = tag; /* yes, ibtrs_tag_from_pdu() can be nice here,
			* but also we have to think about MQ mode
			*/

	return iu;
}

static void ibnbd_put_iu(struct ibnbd_clt_session *sess, struct ibnbd_iu *iu)
{
	ibnbd_put_tag(sess, iu->tag);
}

static void ibnbd_softirq_done_fn(struct request *rq)
{
	struct ibnbd_clt_dev *dev	= rq->rq_disk->private_data;
	struct ibnbd_clt_session *sess	= dev->sess;
	struct ibnbd_iu *iu;

	iu = blk_mq_rq_to_pdu(rq);
	ibnbd_put_tag(sess, iu->tag);
	blk_mq_end_request(rq, iu->status);
}

static void msg_io_conf(void *priv, int errno)
{
	struct ibnbd_iu *iu = (struct ibnbd_iu *)priv;
	struct ibnbd_clt_dev *dev = iu->dev;
	struct request *rq = iu->rq;

	iu->status = errno ? BLK_STS_IOERR : BLK_STS_OK;

	if (softirq_enable) {
		blk_mq_complete_request(rq);
	} else {
		ibnbd_put_tag(dev->sess, iu->tag);
		blk_mq_end_request(rq, iu->status);
	}

	if (errno)
		ibnbd_info_rl(dev, "%s I/O failed with err: %d\n",
			      rq_data_dir(rq) == READ ? "read" : "write",
			      errno);
}

static void init_iu_comp(struct ibnbd_iu *iu, struct ibnbd_iu_comp *comp)
{
	init_waitqueue_head(&comp->wait);
	comp->errno = INT_MAX;
	iu->comp = comp;
}

static void deinit_iu_comp(struct ibnbd_iu *iu)
{
	iu->comp = NULL;
}

static void wake_up_iu_comp(struct ibnbd_iu *iu, int errno)
{
	struct ibnbd_iu_comp *comp = iu->comp;

	if (comp) {
		comp->errno = errno;
		wake_up(&comp->wait);
		deinit_iu_comp(iu);
	}
}

static void wait_iu_comp(struct ibnbd_iu_comp *comp)
{
	wait_event(comp->wait, comp->errno != INT_MAX);
}

static void msg_conf(void *priv, int errno)
{
	struct ibnbd_iu *iu = (struct ibnbd_iu *)priv;

	iu->errno = errno;
	schedule_work(&iu->work);
}

enum {
	NO_WAIT = 0,
	WAIT    = 1
};

static int send_usr_msg(struct ibtrs_clt *ibtrs, int dir,
			struct ibnbd_iu *iu, struct kvec *vec, size_t nr,
			size_t len, struct scatterlist *sg, unsigned int sg_len,
			void (*conf)(struct work_struct *work),
			int *errno, bool wait)
{
	struct ibnbd_iu_comp comp;
	int err;

	if (wait)
		init_iu_comp(iu, &comp);
	INIT_WORK(&iu->work, conf);
	err = ibtrs_clt_request(dir, msg_conf, ibtrs, iu->tag,
				iu, vec, nr, len, sg, sg_len);
	if (unlikely(err)) {
		deinit_iu_comp(iu);
	} else if (wait) {
		wait_iu_comp(&comp);
		*errno = comp.errno;
	} else {
		*errno = 0;
	}

	return err;
}

static void msg_close_conf(struct work_struct *work)
{
	struct ibnbd_iu *iu = container_of(work, struct ibnbd_iu, work);
	struct ibnbd_clt_dev *dev = iu->dev;

	wake_up_iu_comp(iu, iu->errno);
	ibnbd_put_iu(dev->sess, iu);
	ibnbd_clt_put_dev(dev);
}

static int send_msg_close(struct ibnbd_clt_dev *dev, u32 device_id, bool wait)
{
	struct ibnbd_clt_session *sess = dev->sess;
	struct ibnbd_msg_close msg;
	struct ibnbd_iu *iu;
	struct kvec vec = {
		.iov_base = &msg,
		.iov_len  = sizeof(msg)
	};
	int err, errno;

	iu = ibnbd_get_iu(sess, IBTRS_USR_CON, IBTRS_TAG_WAIT);
	if (unlikely(!iu))
		return -ENOMEM;

	iu->buf = NULL;
	iu->dev = dev;

	sg_mark_end(&iu->sglist[0]);

	msg.hdr.type	= cpu_to_le16(IBNBD_MSG_CLOSE);
	msg.device_id	= cpu_to_le32(device_id);

	WARN_ON(!ibnbd_clt_get_dev(dev));
	err = send_usr_msg(sess->ibtrs, WRITE, iu, &vec, 1, 0, NULL, 0,
			   msg_close_conf, &errno, wait);
	if (unlikely(err)) {
		ibnbd_clt_put_dev(dev);
		ibnbd_put_iu(sess, iu);
	} else {
		err = errno;
	}

	return err;
}

static void msg_open_conf(struct work_struct *work)
{
	struct ibnbd_iu *iu = container_of(work, struct ibnbd_iu, work);
	struct ibnbd_msg_open_rsp *rsp = iu->buf;
	struct ibnbd_clt_dev *dev = iu->dev;
	int errno = iu->errno;

	if (errno) {
		ibnbd_err(dev, "Opening failed, server responded: %d\n", errno);
	} else {
		errno = process_msg_open_rsp(dev, rsp);
		if (unlikely(errno)) {
			u32 device_id = le32_to_cpu(rsp->device_id);
			/*
			 * If server thinks its fine, but we fail to process
			 * then be nice and send a close to server.
			 */
			(void)send_msg_close(dev, device_id, NO_WAIT);
		}
	}
	kfree(rsp);
	wake_up_iu_comp(iu, errno);
	ibnbd_put_iu(dev->sess, iu);
	ibnbd_clt_put_dev(dev);
}

static void msg_sess_info_conf(struct work_struct *work)
{
	struct ibnbd_iu *iu = container_of(work, struct ibnbd_iu, work);
	struct ibnbd_msg_sess_info_rsp *rsp = iu->buf;
	struct ibnbd_clt_session *sess = iu->sess;

	if (likely(!iu->errno))
		sess->ver = min_t(u8, rsp->ver, IBNBD_PROTO_VER_MAJOR);

	kfree(rsp);
	wake_up_iu_comp(iu, iu->errno);
	ibnbd_put_iu(sess, iu);
	ibnbd_clt_put_sess(sess);
}

static int send_msg_open(struct ibnbd_clt_dev *dev, bool wait)
{
	struct ibnbd_clt_session *sess = dev->sess;
	struct ibnbd_msg_open_rsp *rsp;
	struct ibnbd_msg_open msg;
	struct ibnbd_iu *iu;
	struct kvec vec = {
		.iov_base = &msg,
		.iov_len  = sizeof(msg)
	};
	int err, errno;

	rsp = kzalloc(sizeof(*rsp), GFP_KERNEL);
	if (unlikely(!rsp))
		return -ENOMEM;

	iu = ibnbd_get_iu(sess, IBTRS_USR_CON, IBTRS_TAG_WAIT);
	if (unlikely(!iu)) {
		kfree(rsp);
		return -ENOMEM;
	}

	iu->buf = rsp;
	iu->dev = dev;

	sg_init_one(iu->sglist, rsp, sizeof(*rsp));

	msg.hdr.type	= cpu_to_le16(IBNBD_MSG_OPEN);
	msg.access_mode	= dev->access_mode;
	msg.io_mode	= dev->io_mode;
	strlcpy(msg.dev_name, dev->pathname, sizeof(msg.dev_name));

	WARN_ON(!ibnbd_clt_get_dev(dev));
	err = send_usr_msg(sess->ibtrs, READ, iu,
			   &vec, 1, sizeof(*rsp), iu->sglist, 1,
			   msg_open_conf, &errno, wait);
	if (unlikely(err)) {
		ibnbd_clt_put_dev(dev);
		ibnbd_put_iu(sess, iu);
		kfree(rsp);
	} else {
		err = errno;
	}

	return err;
}

static int send_msg_sess_info(struct ibnbd_clt_session *sess, bool wait)
{
	struct ibnbd_msg_sess_info_rsp *rsp;
	struct ibnbd_msg_sess_info msg;
	struct ibnbd_iu *iu;
	struct kvec vec = {
		.iov_base = &msg,
		.iov_len  = sizeof(msg)
	};
	int err, errno;

	rsp = kzalloc(sizeof(*rsp), GFP_KERNEL);
	if (unlikely(!rsp))
		return -ENOMEM;

	iu = ibnbd_get_iu(sess, IBTRS_USR_CON, IBTRS_TAG_WAIT);
	if (unlikely(!iu)) {
		kfree(rsp);
		return -ENOMEM;
	}

	iu->buf = rsp;
	iu->sess = sess;

	sg_init_one(iu->sglist, rsp, sizeof(*rsp));

	msg.hdr.type = cpu_to_le16(IBNBD_MSG_SESS_INFO);
	msg.ver      = IBNBD_PROTO_VER_MAJOR;

	if (unlikely(!ibnbd_clt_get_sess(sess))) {
		/*
		 * That can happen only in one case, when IBTRS has restablished
		 * the connection and link_ev() is called, but session is almost
		 * dead, last reference on session is put and caller is waiting
		 * for IBTRS to close everything.
		 */
		err = -ENODEV;
		goto put_iu;
	}
	err = send_usr_msg(sess->ibtrs, READ, iu,
			   &vec, 1, sizeof(*rsp), iu->sglist, 1,
			   msg_sess_info_conf, &errno, wait);
	if (unlikely(err)) {
		ibnbd_clt_put_sess(sess);
put_iu:
		ibnbd_put_iu(sess, iu);
		kfree(rsp);
	} else {
		err = errno;
	}

	return err;
}

static void set_dev_states_to_disconnected(struct ibnbd_clt_session *sess)
{
	struct ibnbd_clt_dev *dev;

	mutex_lock(&sess->lock);
	list_for_each_entry(dev, &sess->devs_list, list) {
		ibnbd_err(dev, "Device disconnected.\n");

		mutex_lock(&dev->lock);
		if (dev->dev_state == DEV_STATE_MAPPED)
			dev->dev_state = DEV_STATE_MAPPED_DISCONNECTED;
		mutex_unlock(&dev->lock);
	}
	mutex_unlock(&sess->lock);
}

static void remap_devs(struct ibnbd_clt_session *sess)
{
	struct ibnbd_clt_dev *dev;
	struct ibtrs_attrs attrs;
	int err;

	/*
	 * Careful here: we are called from IBTRS link event directly,
	 * thus we can't send any IBTRS request and wait for response
	 * or IBTRS will not be able to complete request with failure
	 * if something goes wrong (failing of outstanding requests
	 * happens exactly from the context where we are blocking now).
	 *
	 * So to avoid deadlocks each usr message sent from here must
	 * be asynchronous.
	 */

	err = send_msg_sess_info(sess, NO_WAIT);
	if (unlikely(err)) {
		pr_err("send_msg_sess_info(\"%s\"): %d\n", sess->sessname, err);
		return;
	}

	ibtrs_clt_query(sess->ibtrs, &attrs);
	mutex_lock(&sess->lock);
	sess->max_io_size = attrs.max_io_size;

	list_for_each_entry(dev, &sess->devs_list, list) {
		bool skip;

		mutex_lock(&dev->lock);
		skip = (dev->dev_state == DEV_STATE_INIT);
		mutex_unlock(&dev->lock);
		if (skip)
			/*
			 * When device is establishing connection for the first
			 * time - do not remap, it will be closed soon.
			 */
			continue;

		ibnbd_info(dev, "session reconnected, remapping device\n");
		err = send_msg_open(dev, NO_WAIT);
		if (unlikely(err)) {
			ibnbd_err(dev, "send_msg_open(): %d\n", err);
			break;
		}
	}
	mutex_unlock(&sess->lock);
}

static void ibnbd_clt_link_ev(void *priv, enum ibtrs_clt_link_ev ev)
{
	struct ibnbd_clt_session *sess = priv;

	switch (ev) {
	case IBTRS_CLT_LINK_EV_DISCONNECTED:
		set_dev_states_to_disconnected(sess);
		break;
	case IBTRS_CLT_LINK_EV_RECONNECTED:
		remap_devs(sess);
		break;
	default:
		pr_err("Unknown session event received (%d), session: %s\n",
		       ev, sess->sessname);
	}
}

static void ibnbd_init_cpu_qlists(struct ibnbd_cpu_qlist __percpu *cpu_queues)
{
	unsigned int cpu;
	struct ibnbd_cpu_qlist *cpu_q;

	for_each_possible_cpu(cpu) {
		cpu_q = per_cpu_ptr(cpu_queues, cpu);

		cpu_q->cpu = cpu;
		INIT_LIST_HEAD(&cpu_q->requeue_list);
		spin_lock_init(&cpu_q->requeue_lock);
	}
}

static struct blk_mq_ops ibnbd_mq_ops;
static int setup_mq_tags(struct ibnbd_clt_session *sess)
{
	struct blk_mq_tag_set *tags = &sess->tag_set;

	memset(tags, 0, sizeof(*tags));
	tags->ops		= &ibnbd_mq_ops;
	tags->queue_depth	= sess->queue_depth;
	tags->numa_node		= NUMA_NO_NODE;
	tags->flags		= BLK_MQ_F_SHOULD_MERGE |
				  BLK_MQ_F_SG_MERGE     |
				  BLK_MQ_F_TAG_SHARED;
	tags->cmd_size		= sizeof(struct ibnbd_iu);
	tags->nr_hw_queues	= num_online_cpus();

	return blk_mq_alloc_tag_set(tags);
}

static void destroy_mq_tags(struct ibnbd_clt_session *sess)
{
	if (sess->tag_set.tags)
		blk_mq_free_tag_set(&sess->tag_set);
}

static inline void wake_up_ibtrs_waiters(struct ibnbd_clt_session *sess)
{
	/* paired with rmb() in wait_for_ibtrs_connection() */
	smp_wmb();
	sess->ibtrs_ready = true;
	wake_up_all(&sess->ibtrs_waitq);
}

static void close_ibtrs(struct ibnbd_clt_session *sess)
{
	might_sleep();

	if (!IS_ERR_OR_NULL(sess->ibtrs)) {
		ibtrs_clt_close(sess->ibtrs);
		sess->ibtrs = NULL;
		wake_up_ibtrs_waiters(sess);
	}
}

static void free_sess(struct ibnbd_clt_session *sess)
{
	WARN_ON(!list_empty(&sess->devs_list));

	might_sleep();

	close_ibtrs(sess);
	destroy_mq_tags(sess);
	if (!list_empty(&sess->list)) {
		mutex_lock(&sess_lock);
		list_del(&sess->list);
		mutex_unlock(&sess_lock);
	}
	free_percpu(sess->cpu_queues);
	free_percpu(sess->cpu_rr);
	kfree(sess);
}

static struct ibnbd_clt_session *alloc_sess(const char *sessname,
					    const struct ibtrs_addr *paths,
					    size_t path_cnt)
{
	struct ibnbd_clt_session *sess;
	int err, cpu;

	sess = kzalloc_node(sizeof(*sess), GFP_KERNEL, NUMA_NO_NODE);
	if (unlikely(!sess)) {
		pr_err("Failed to create session %s,"
		       " allocating session struct failed\n", sessname);
		return ERR_PTR(-ENOMEM);
	}
	strlcpy(sess->sessname, sessname, sizeof(sess->sessname));
	atomic_set(&sess->busy, 0);
	mutex_init(&sess->lock);
	INIT_LIST_HEAD(&sess->devs_list);
	INIT_LIST_HEAD(&sess->list);
	bitmap_zero(sess->cpu_queues_bm, NR_CPUS);
	init_waitqueue_head(&sess->ibtrs_waitq);
	refcount_set(&sess->refcount, 1);

	sess->cpu_queues = alloc_percpu(struct ibnbd_cpu_qlist);
	if (unlikely(!sess->cpu_queues)) {
		pr_err("Failed to create session to %s,"
		       " alloc of percpu var (cpu_queues) failed\n", sessname);
		err = -ENOMEM;
		goto err;
	}
	ibnbd_init_cpu_qlists(sess->cpu_queues);

	/**
	 * That is simple percpu variable which stores cpu indeces, which are
	 * incremented on each access.  We need that for the sake of fairness
	 * to wake up queues in a round-robin manner.
	 */
	sess->cpu_rr = alloc_percpu(int);
	if (unlikely(!sess->cpu_rr)) {
		pr_err("Failed to create session %s,"
		       " alloc of percpu var (cpu_rr) failed\n", sessname);
		err = -ENOMEM;
		goto err;
	}
	for_each_possible_cpu(cpu)
		*per_cpu_ptr(sess->cpu_rr, cpu) = cpu;

	return sess;

err:
	free_sess(sess);

	return ERR_PTR(err);
}

static int wait_for_ibtrs_connection(struct ibnbd_clt_session *sess)
{
	wait_event(sess->ibtrs_waitq, sess->ibtrs_ready);
	/* paired with wmb() in wake_up_ibtrs_waiters() */
	smp_rmb();
	if (unlikely(IS_ERR_OR_NULL(sess->ibtrs)))
		return -ECONNRESET;

	return 0;
}

static void wait_for_ibtrs_disconnection(struct ibnbd_clt_session *sess)
__releases(&sess_lock)
__acquires(&sess_lock)
{
	DEFINE_WAIT_FUNC(wait, autoremove_wake_function);

	prepare_to_wait(&sess->ibtrs_waitq, &wait, TASK_UNINTERRUPTIBLE);
	if (IS_ERR_OR_NULL(sess->ibtrs)) {
		finish_wait(&sess->ibtrs_waitq, &wait);
		return;
	}
	mutex_unlock(&sess_lock);
	/* After unlock session can be freed, so careful */
	schedule();
	mutex_lock(&sess_lock);
}

static struct ibnbd_clt_session *__find_and_get_sess(const char *sessname)
__releases(&sess_lock)
__acquires(&sess_lock)
{
	struct ibnbd_clt_session *sess;
	int err;

again:
	list_for_each_entry(sess, &sess_list, list) {
		if (strcmp(sessname, sess->sessname))
			continue;

		if (unlikely(sess->ibtrs_ready && IS_ERR_OR_NULL(sess->ibtrs)))
			/*
			 * No IBTRS connection, session is dying.
			 */
			continue;

		if (likely(ibnbd_clt_get_sess(sess))) {
			/*
			 * Alive session is found, wait for IBTRS connection.
			 */
			mutex_unlock(&sess_lock);
			err = wait_for_ibtrs_connection(sess);
			if (unlikely(err))
				ibnbd_clt_put_sess(sess);
			mutex_lock(&sess_lock);

			if (unlikely(err))
				/* Session is dying, repeat the loop */
				goto again;

			return sess;
		} else {
			/*
			 * Ref is 0, session is dying, wait for IBTRS disconnect
			 * in order to avoid session names clashes.
			 */
			wait_for_ibtrs_disconnection(sess);
			/*
			 * IBTRS is disconnected and soon session will be freed,
			 * so repeat a loop.
			 */
			goto again;
		}
	}

	return NULL;
}

static struct ibnbd_clt_session *find_and_get_sess(const char *sessname)
{
	struct ibnbd_clt_session *sess;

	mutex_lock(&sess_lock);
	sess = __find_and_get_sess(sessname);
	mutex_unlock(&sess_lock);

	return sess;
}

static struct ibnbd_clt_session *
find_and_get_or_insert_sess(struct ibnbd_clt_session *sess)
{
	struct ibnbd_clt_session *found;

	mutex_lock(&sess_lock);
	found = __find_and_get_sess(sess->sessname);
	if (!found)
		list_add(&sess->list, &sess_list);
	mutex_unlock(&sess_lock);

	return found;
}

static struct ibnbd_clt_session *
find_and_get_or_create_sess(const char *sessname,
			    const struct ibtrs_addr *paths,
			    size_t path_cnt)
{
	struct ibnbd_clt_session *sess, *found;
	struct ibtrs_attrs attrs;
	int err;

	sess = find_and_get_sess(sessname);
	if (sess)
		return sess;

	sess = alloc_sess(sessname, paths, path_cnt);
	if (unlikely(IS_ERR(sess)))
		return sess;

	found = find_and_get_or_insert_sess(sess);
	if (unlikely(found)) {
		free_sess(sess);

		return found;
	}
	/*
	 * Nothing was found, establish ibtrs connection and proceed further.
	 */
	sess->ibtrs = ibtrs_clt_open(sess, ibnbd_clt_link_ev, sessname,
				     paths, path_cnt, IBTRS_PORT,
				     sizeof(struct ibnbd_iu),
				     RECONNECT_DELAY, BMAX_SEGMENTS,
				     MAX_RECONNECTS);
	if (unlikely(IS_ERR(sess->ibtrs))) {
		err = PTR_ERR(sess->ibtrs);
		goto wake_up_and_put;
	}
	ibtrs_clt_query(sess->ibtrs, &attrs);
	sess->max_io_size = attrs.max_io_size;
	sess->queue_depth = attrs.queue_depth;

	err = setup_mq_tags(sess);
	if (unlikely(err))
		goto close_ibtrs;

	err = send_msg_sess_info(sess, WAIT);
	if (unlikely(err))
		goto close_ibtrs;

	wake_up_ibtrs_waiters(sess);

	return sess;

close_ibtrs:
	close_ibtrs(sess);
put_sess:
	ibnbd_clt_put_sess(sess);

	return ERR_PTR(err);

wake_up_and_put:
	wake_up_ibtrs_waiters(sess);
	goto put_sess;
}

static int ibnbd_client_open(struct block_device *block_device, fmode_t mode)
{
	struct ibnbd_clt_dev *dev = block_device->bd_disk->private_data;

	if (dev->read_only && (mode & FMODE_WRITE))
		return -EPERM;

	if (dev->dev_state == DEV_STATE_UNMAPPED ||
	    !ibnbd_clt_get_dev(dev))
		return -EIO;

	return 0;
}

static void ibnbd_client_release(struct gendisk *gen, fmode_t mode)
{
	struct ibnbd_clt_dev *dev = gen->private_data;

	ibnbd_clt_put_dev(dev);
}

static int ibnbd_client_getgeo(struct block_device *block_device,
			       struct hd_geometry *geo)
{
	u64 size;
	struct ibnbd_clt_dev *dev;

	dev = block_device->bd_disk->private_data;
	size = dev->size * (dev->logical_block_size / KERNEL_SECTOR_SIZE);
	geo->cylinders	= (size & ~0x3f) >> 6;	/* size/64 */
	geo->heads	= 4;
	geo->sectors	= 16;
	geo->start	= 0;

	return 0;
}

static const struct block_device_operations ibnbd_client_ops = {
	.owner		= THIS_MODULE,
	.open		= ibnbd_client_open,
	.release	= ibnbd_client_release,
	.getgeo		= ibnbd_client_getgeo
};

static size_t ibnbd_clt_get_sg_size(struct scatterlist *sglist, u32 len)
{
	struct scatterlist *sg;
	size_t tsize = 0;
	int i;

	for_each_sg(sglist, sg, len, i)
		tsize += sg->length;
	return tsize;
}

static int ibnbd_client_xfer_request(struct ibnbd_clt_dev *dev,
				     struct request *rq,
				     struct ibnbd_iu *iu)
{
	struct ibtrs_clt *ibtrs = dev->sess->ibtrs;
	struct ibtrs_tag *tag = iu->tag;
	struct ibnbd_msg_io msg;
	unsigned int sg_cnt = 0;
	struct kvec vec;
	size_t size;
	int err;

	iu->rq		= rq;
	iu->dev		= dev;
	msg.sector	= cpu_to_le64(blk_rq_pos(rq));
	msg.bi_size	= cpu_to_le32(blk_rq_bytes(rq));
	msg.rw		= cpu_to_le32(rq_to_ibnbd_flags(rq));

	/* We only support discards with single segment for now. See queue limits. */
	if (req_op(rq) != REQ_OP_DISCARD)
		sg_cnt = blk_rq_map_sg(dev->queue, rq, iu->sglist);

	if (sg_cnt == 0)
		/* Do not forget to mark the end */
		sg_mark_end(&iu->sglist[0]);

	msg.hdr.type	= cpu_to_le16(IBNBD_MSG_IO);
	msg.device_id	= cpu_to_le32(dev->device_id);

	vec = (struct kvec) {
		.iov_base = &msg,
		.iov_len  = sizeof(msg)
	};

	size = ibnbd_clt_get_sg_size(iu->sglist, sg_cnt);
	err = ibtrs_clt_request(rq_data_dir(rq), msg_io_conf, ibtrs, tag,
				iu, &vec, 1, size, iu->sglist, sg_cnt);
	if (unlikely(err)) {
		ibnbd_err_rl(dev, "IBTRS failed to transfer IO, err: %d\n",
			     err);
		return err;
	}

	return 0;
}

/**
 * ibnbd_clt_dev_add_to_requeue() - add device to requeue if session is busy
 *
 * Description:
 *     If session is busy, that means someone will requeue us when resources
 *     are freed.  If session is not doing anything - device is not added to
 *     the list and @false is returned.
 */
static inline bool ibnbd_clt_dev_add_to_requeue(struct ibnbd_clt_dev *dev,
						struct ibnbd_queue *q)
{
	struct ibnbd_clt_session *sess = dev->sess;
	struct ibnbd_cpu_qlist *cpu_q;
	unsigned long flags;
	bool added = true;
	bool need_set;

	cpu_q = get_cpu_ptr(sess->cpu_queues);
	spin_lock_irqsave(&cpu_q->requeue_lock, flags);

	if (likely(!test_and_set_bit_lock(0, &q->in_list))) {
		if (WARN_ON(!list_empty(&q->requeue_list)))
			goto unlock;

		need_set = !test_bit(cpu_q->cpu, sess->cpu_queues_bm);
		if (need_set) {
			set_bit(cpu_q->cpu, sess->cpu_queues_bm);
			/* Paired with ibnbd_put_tag().	 Set a bit first
			 * and then observe the busy counter.
			 */
			smp_mb__before_atomic();
		}
		if (likely(atomic_read(&sess->busy))) {
			list_add_tail(&q->requeue_list, &cpu_q->requeue_list);
		} else {
			/* Very unlikely, but possible: busy counter was
			 * observed as zero.  Drop all bits and return
			 * false to restart the queue by ourselves.
			 */
			if (need_set)
				clear_bit(cpu_q->cpu, sess->cpu_queues_bm);
			clear_bit_unlock(0, &q->in_list);
			added = false;
		}
	}
unlock:
	spin_unlock_irqrestore(&cpu_q->requeue_lock, flags);
	put_cpu_ptr(sess->cpu_queues);

	return added;
}

static void ibnbd_clt_dev_kick_mq_queue(struct ibnbd_clt_dev *dev,
					struct blk_mq_hw_ctx *hctx,
					int delay)
{
	struct ibnbd_queue *q = hctx->driver_data;

	if (delay != IBNBD_DELAY_IFBUSY)
		blk_mq_delay_run_hw_queue(hctx, delay);
	else if (unlikely(!ibnbd_clt_dev_add_to_requeue(dev, q)))
		/*
		 * If session is not busy we have to restart
		 * the queue ourselves.
		 */
		blk_mq_delay_run_hw_queue(hctx, IBNBD_DELAY_10ms);
}

static blk_status_t ibnbd_queue_rq(struct blk_mq_hw_ctx *hctx,
				   const struct blk_mq_queue_data *bd)
{
	struct request *rq = bd->rq;
	struct ibnbd_clt_dev *dev = rq->rq_disk->private_data;
	struct ibnbd_iu *iu = blk_mq_rq_to_pdu(rq);
	int err;

	if (unlikely(!ibnbd_clt_dev_is_mapped(dev)))
		return BLK_STS_IOERR;

	iu->tag = ibnbd_get_tag(dev->sess, IBTRS_IO_CON, IBTRS_TAG_NOWAIT);
	if (unlikely(!iu->tag)) {
		ibnbd_clt_dev_kick_mq_queue(dev, hctx, IBNBD_DELAY_IFBUSY);
		return BLK_STS_RESOURCE;
	}

	blk_mq_start_request(rq);
	err = ibnbd_client_xfer_request(dev, rq, iu);
	if (likely(err == 0))
		return BLK_STS_OK;
	if (unlikely(err == -EAGAIN || err == -ENOMEM)) {
		ibnbd_clt_dev_kick_mq_queue(dev, hctx, IBNBD_DELAY_10ms);
		ibnbd_put_tag(dev->sess, iu->tag);
		return BLK_STS_RESOURCE;
	}

	ibnbd_put_tag(dev->sess, iu->tag);
	return BLK_STS_IOERR;
}

static int ibnbd_init_request(struct blk_mq_tag_set *set, struct request *rq,
			      unsigned int hctx_idx, unsigned int numa_node)
{
	struct ibnbd_iu *iu = blk_mq_rq_to_pdu(rq);

	sg_init_table(iu->sglist, BMAX_SEGMENTS);
	return 0;
}

static inline void ibnbd_init_hw_queue(struct ibnbd_clt_dev *dev,
				       struct ibnbd_queue *q,
				       struct blk_mq_hw_ctx *hctx)
{
	INIT_LIST_HEAD(&q->requeue_list);
	q->dev  = dev;
	q->hctx = hctx;
}

static void ibnbd_init_mq_hw_queues(struct ibnbd_clt_dev *dev)
{
	int i;
	struct blk_mq_hw_ctx *hctx;
	struct ibnbd_queue *q;

	queue_for_each_hw_ctx(dev->queue, hctx, i) {
		q = &dev->hw_queues[i];
		ibnbd_init_hw_queue(dev, q, hctx);
		hctx->driver_data = q;
	}
}

static struct blk_mq_ops ibnbd_mq_ops = {
	.queue_rq	= ibnbd_queue_rq,
	.init_request	= ibnbd_init_request,
	.complete	= ibnbd_softirq_done_fn,
};

static int index_to_minor(int index)
{
	return index << IBNBD_PART_BITS;
}

static int minor_to_index(int minor)
{
	return minor >> IBNBD_PART_BITS;
}

static int setup_mq_dev(struct ibnbd_clt_dev *dev)
{
	dev->queue = blk_mq_init_queue(&dev->sess->tag_set);
	if (IS_ERR(dev->queue)) {
		ibnbd_err(dev,
			  "Initializing multiqueue queue failed, err: %ld\n",
			  PTR_ERR(dev->queue));
		return PTR_ERR(dev->queue);
	}
	ibnbd_init_mq_hw_queues(dev);
	return 0;
}

static void setup_request_queue(struct ibnbd_clt_dev *dev)
{
	blk_queue_logical_block_size(dev->queue, dev->logical_block_size);
	blk_queue_physical_block_size(dev->queue, dev->physical_block_size);
	blk_queue_max_hw_sectors(dev->queue, dev->max_hw_sectors);
	blk_queue_max_write_same_sectors(dev->queue,
					 dev->max_write_same_sectors);

	/* we don't support discards to "discontiguous" segments in on request */
	blk_queue_max_discard_segments(dev->queue, 1);

	blk_queue_max_discard_sectors(dev->queue, dev->max_discard_sectors);
	dev->queue->limits.discard_granularity	= dev->discard_granularity;
	dev->queue->limits.discard_alignment	= dev->discard_alignment;
	if (dev->max_discard_sectors)
		blk_queue_flag_set(QUEUE_FLAG_DISCARD, dev->queue);
	if (dev->secure_discard)
		blk_queue_flag_set(QUEUE_FLAG_SECERASE, dev->queue);

	blk_queue_flag_set(QUEUE_FLAG_SAME_COMP, dev->queue);
	blk_queue_flag_set(QUEUE_FLAG_SAME_FORCE, dev->queue);
	/* our hca only support 32 sg cnt, proto use one, so 31 left */
	blk_queue_max_segments(dev->queue, dev->max_segments);
	blk_queue_io_opt(dev->queue, dev->sess->max_io_size);
	blk_queue_virt_boundary(dev->queue, 4095);
	blk_queue_write_cache(dev->queue, true, true);
	dev->queue->queuedata = dev;
}

static void ibnbd_clt_setup_gen_disk(struct ibnbd_clt_dev *dev, int idx)
{
	dev->gd->major		= ibnbd_client_major;
	dev->gd->first_minor	= index_to_minor(idx);
	dev->gd->fops		= &ibnbd_client_ops;
	dev->gd->queue		= dev->queue;
	dev->gd->private_data	= dev;
	snprintf(dev->gd->disk_name, sizeof(dev->gd->disk_name), "ibnbd%d",
		 idx);
	pr_debug("disk_name=%s, capacity=%zu\n",
		 dev->gd->disk_name,
		 dev->nsectors * (dev->logical_block_size / KERNEL_SECTOR_SIZE)
		 );

	set_capacity(dev->gd, dev->nsectors * (dev->logical_block_size /
					       KERNEL_SECTOR_SIZE));

	if (dev->access_mode == IBNBD_ACCESS_RO) {
		dev->read_only = true;
		set_disk_ro(dev->gd, true);
	} else {
		dev->read_only = false;
	}

	if (!dev->rotational)
		blk_queue_flag_set(QUEUE_FLAG_NONROT, dev->queue);
}

static void ibnbd_clt_add_gen_disk(struct ibnbd_clt_dev *dev)
{
	add_disk(dev->gd);
}

static int ibnbd_client_setup_device(struct ibnbd_clt_session *sess,
				     struct ibnbd_clt_dev *dev, int idx)
{
	int err;

	dev->size = dev->nsectors * dev->logical_block_size;

	err = setup_mq_dev(dev);
	if (err)
		return err;

	setup_request_queue(dev);

	dev->gd = alloc_disk_node(1 << IBNBD_PART_BITS,	NUMA_NO_NODE);
	if (!dev->gd) {
		ibnbd_err(dev, "Failed to allocate disk node\n");
		blk_cleanup_queue(dev->queue);
		return -ENOMEM;
	}

	ibnbd_clt_setup_gen_disk(dev, idx);

	return 0;
}

static struct ibnbd_clt_dev *init_dev(struct ibnbd_clt_session *sess,
				      enum ibnbd_access_mode access_mode,
				      enum ibnbd_io_mode io_mode,
				      const char *pathname)
{
	struct ibnbd_clt_dev *dev;
	int ret;

	dev = kzalloc_node(sizeof(*dev), GFP_KERNEL, NUMA_NO_NODE);
	if (!dev)
		return ERR_PTR(-ENOMEM);

	dev->hw_queues = kcalloc(nr_cpu_ids, sizeof(*dev->hw_queues), GFP_KERNEL);
	if (unlikely(!dev->hw_queues)) {
		pr_err("Failed to initialize device '%s' from session"
		       " %s, allocating hw_queues failed.", pathname,
		       sess->sessname);
		ret = -ENOMEM;
		goto out_alloc;
	}

	mutex_lock(&ida_lock);
	ret = ida_simple_get(&index_ida, 0, minor_to_index(1 << MINORBITS),
			     GFP_KERNEL);
	mutex_unlock(&ida_lock);
	if (ret < 0) {
		pr_err("Failed to initialize device '%s' from session %s,"
		       " allocating idr failed, err: %d\n", pathname,
		       sess->sessname, ret);
		goto out_queues;
	}
	dev->clt_device_id	= ret;
	dev->sess		= sess;
	dev->access_mode	= access_mode;
	dev->io_mode		= io_mode;
	strlcpy(dev->pathname, pathname, sizeof(dev->pathname));
	mutex_init(&dev->lock);
	refcount_set(&dev->refcount, 1);
	dev->dev_state = DEV_STATE_INIT;

	/*
	 * Here we called from sysfs entry, thus clt-sysfs is
	 * responsible that session will not disappear.
	 */
	WARN_ON(!ibnbd_clt_get_sess(sess));

	return dev;

out_queues:
	kfree(dev->hw_queues);
out_alloc:
	kfree(dev);
	return ERR_PTR(ret);
}

static bool __exists_dev(const char *pathname)
{
	struct ibnbd_clt_session *sess;
	struct ibnbd_clt_dev *dev;
	bool found = false;

	list_for_each_entry(sess, &sess_list, list) {
		mutex_lock(&sess->lock);
		list_for_each_entry(dev, &sess->devs_list, list) {
			if (!strncmp(dev->pathname, pathname,
				     sizeof(dev->pathname))) {
				found = true;
				break;
			}
		}
		mutex_unlock(&sess->lock);
		if (found)
			break;
	}

	return found;
}

static bool exists_devpath(const char *pathname)
{
	bool found;

	mutex_lock(&sess_lock);
	found = __exists_dev(pathname);
	mutex_unlock(&sess_lock);

	return found;
}

static bool insert_dev_if_not_exists_devpath(const char *pathname,
					     struct ibnbd_clt_session *sess,
					     struct ibnbd_clt_dev *dev)
{
	bool found;

	mutex_lock(&sess_lock);
	found = __exists_dev(pathname);
	if (!found) {
		mutex_lock(&sess->lock);
		list_add_tail(&dev->list, &sess->devs_list);
		mutex_unlock(&sess->lock);
	}
	mutex_unlock(&sess_lock);

	return found;
}

static void delete_dev(struct ibnbd_clt_dev *dev)
{
	struct ibnbd_clt_session *sess = dev->sess;

	mutex_lock(&sess->lock);
	list_del(&dev->list);
	mutex_unlock(&sess->lock);
}

struct ibnbd_clt_dev *ibnbd_clt_map_device(const char *sessname,
					   struct ibtrs_addr *paths,
					   size_t path_cnt,
					   const char *pathname,
					   enum ibnbd_access_mode access_mode,
					   enum ibnbd_io_mode io_mode)
{
	struct ibnbd_clt_session *sess;
	struct ibnbd_clt_dev *dev;
	int ret;

	if (unlikely(exists_devpath(pathname)))
		return ERR_PTR(-EEXIST);

	sess = find_and_get_or_create_sess(sessname, paths, path_cnt);
	if (unlikely(IS_ERR(sess)))
		return ERR_CAST(sess);

	dev = init_dev(sess, access_mode, io_mode, pathname);
	if (unlikely(IS_ERR(dev))) {
		pr_err("map_device: failed to map device '%s' from session %s,"
		       " can't initialize device, err: %ld\n", pathname,
		       sess->sessname, PTR_ERR(dev));
		ret = PTR_ERR(dev);
		goto put_sess;
	}
	if (unlikely(insert_dev_if_not_exists_devpath(pathname, sess, dev))) {
		ret = -EEXIST;
		goto put_dev;
	}
	ret = send_msg_open(dev, WAIT);
	if (unlikely(ret)) {
		ibnbd_err(dev, "map_device: failed, can't open remote device,"
			  " err: %d\n", ret);
		goto del_dev;
	}
	mutex_lock(&dev->lock);
	pr_debug("Opened remote device: session=%s, path='%s'\n",
		 sess->sessname, pathname);
	ret = ibnbd_client_setup_device(sess, dev, dev->clt_device_id);
	if (ret) {
		ibnbd_err(dev, "map_device: Failed to configure device, err: %d\n",
			  ret);
		mutex_unlock(&dev->lock);
		goto del_dev;
	}

	ibnbd_info(dev, "map_device: Device mapped as %s (nsectors: %zu,"
		   " logical_block_size: %d, physical_block_size: %d,"
		   " max_write_same_sectors: %d, max_discard_sectors: %d,"
		   " discard_granularity: %d, discard_alignment: %d, "
		   "secure_discard: %d, max_segments: %d, max_hw_sectors: %d, "
		   "rotational: %d)\n",
		   dev->gd->disk_name, dev->nsectors, dev->logical_block_size,
		   dev->physical_block_size, dev->max_write_same_sectors,
		   dev->max_discard_sectors, dev->discard_granularity,
		   dev->discard_alignment, dev->secure_discard,
		   dev->max_segments, dev->max_hw_sectors, dev->rotational);

	mutex_unlock(&dev->lock);

	ibnbd_clt_add_gen_disk(dev);
	ibnbd_clt_put_sess(sess);

	return dev;

del_dev:
	delete_dev(dev);
put_dev:
	ibnbd_clt_put_dev(dev);
put_sess:
	ibnbd_clt_put_sess(sess);

	return ERR_PTR(ret);
}

static void destroy_gen_disk(struct ibnbd_clt_dev *dev)
{
	del_gendisk(dev->gd);
	/*
	 * Before marking queue as dying (blk_cleanup_queue() does that)
	 * we have to be sure that everything in-flight has gone.
	 * Blink with freeze/unfreeze.
	 */
	blk_mq_freeze_queue(dev->queue);
	blk_mq_unfreeze_queue(dev->queue);
	blk_cleanup_queue(dev->queue);
	put_disk(dev->gd);
}

static void destroy_sysfs(struct ibnbd_clt_dev *dev,
			  const struct attribute *sysfs_self)
{
	ibnbd_clt_remove_dev_symlink(dev);
	if (dev->kobj.state_initialized) {
		if (sysfs_self)
			/* To avoid deadlock firstly commit suicide */
			sysfs_remove_file_self(&dev->kobj, sysfs_self);
		kobject_del(&dev->kobj);
		kobject_put(&dev->kobj);
	}
}

int ibnbd_clt_unmap_device(struct ibnbd_clt_dev *dev, bool force,
			   const struct attribute *sysfs_self)
{
	struct ibnbd_clt_session *sess = dev->sess;
	int refcount, ret = 0;
	bool was_mapped;

	mutex_lock(&dev->lock);
	if (dev->dev_state == DEV_STATE_UNMAPPED) {
		ibnbd_info(dev, "Device is already being unmapped\n");
		ret = -EALREADY;
		goto err;
	}
	refcount = refcount_read(&dev->refcount);
	if (!force && refcount > 1) {
		ibnbd_err(dev, "Closing device failed, device is in use,"
			  " (%d device users)\n", refcount - 1);
		ret = -EBUSY;
		goto err;
	}
	was_mapped = (dev->dev_state == DEV_STATE_MAPPED);
	dev->dev_state = DEV_STATE_UNMAPPED;
	mutex_unlock(&dev->lock);

	delete_dev(dev);
	destroy_sysfs(dev, sysfs_self);
	destroy_gen_disk(dev);
	if (was_mapped && sess->ibtrs)
		send_msg_close(dev, dev->device_id, WAIT);

	ibnbd_info(dev, "Device is unmapped\n");

	/* Likely last reference put */
	ibnbd_clt_put_dev(dev);

	/*
	 * Here device and session can be vanished!
	 */

	return 0;
err:
	mutex_unlock(&dev->lock);

	return ret;
}

int ibnbd_clt_remap_device(struct ibnbd_clt_dev *dev)
{
	int err;

	mutex_lock(&dev->lock);
	if (likely(dev->dev_state == DEV_STATE_MAPPED_DISCONNECTED))
		err = 0;
	else if (dev->dev_state == DEV_STATE_UNMAPPED)
		err = -ENODEV;
	else if (dev->dev_state == DEV_STATE_MAPPED)
		err = -EALREADY;
	else
		err = -EBUSY;
	mutex_unlock(&dev->lock);
	if (likely(!err)) {
		ibnbd_info(dev, "Remapping device.\n");
		err = send_msg_open(dev, WAIT);
		if (unlikely(err))
			ibnbd_err(dev, "remap_device: %d\n", err);
	}

	return err;
}

static void unmap_device_work(struct work_struct *work)
{
	struct ibnbd_clt_dev *dev;

	dev = container_of(work, typeof(*dev), unmap_on_rmmod_work);
	ibnbd_clt_unmap_device(dev, true, NULL);
}

static void ibnbd_destroy_sessions(void)
{
	struct ibnbd_clt_session *sess, *sn;
	struct ibnbd_clt_dev *dev, *tn;

	/* Firstly forbid access through sysfs interface */
	ibnbd_clt_destroy_default_group();
	ibnbd_clt_destroy_sysfs_files();

	/*
	 * Here at this point there is no any concurrent access to sessions
	 * list and devices list:
	 *   1. New session or device can'be be created - session sysfs files
	 *      are removed.
	 *   2. Device or session can't be removed - module reference is taken
	 *      into account in unmap device sysfs callback.
	 *   3. No IO requests inflight - each file open of block_dev increases
	 *      module reference in get_disk().
	 *
	 * But still there can be user requests inflights, which are sent by
	 * asynchronous send_msg_*() functions, thus before unmapping devices
	 * IBTRS session must be explicitly closed.
	 */

	list_for_each_entry_safe(sess, sn, &sess_list, list) {
		WARN_ON(!ibnbd_clt_get_sess(sess));
		close_ibtrs(sess);
		list_for_each_entry_safe(dev, tn, &sess->devs_list, list) {
			/*
			 * Here unmap happens in parallel for only one reason:
			 * blk_cleanup_queue() takes around half a second, so
			 * on huge amount of devices the whole module unload
			 * procedure takes minutes.
			 */
			INIT_WORK(&dev->unmap_on_rmmod_work, unmap_device_work);
			queue_work(unload_wq, &dev->unmap_on_rmmod_work);
		}
		ibnbd_clt_put_sess(sess);
	}
	/* Wait for all scheduled unmap works */
	flush_workqueue(unload_wq);
	WARN_ON(!list_empty(&sess_list));
}

static int __init ibnbd_client_init(void)
{
	int err;

	pr_info("Loading module %s, version %s, proto %s: "
		"(softirq_enable: %d)\n", KBUILD_MODNAME,
		IBNBD_VER_STRING, IBNBD_PROTO_VER_STRING,
		softirq_enable);

	ibnbd_client_major = register_blkdev(ibnbd_client_major, "ibnbd");
	if (ibnbd_client_major <= 0) {
		pr_err("Failed to load module,"
		       " block device registration failed\n");
		err = -EBUSY;
		goto out;
	}

	err = ibnbd_clt_create_sysfs_files();
	if (err) {
		pr_err("Failed to load module,"
		       " creating sysfs device files failed, err: %d\n",
		       err);
		goto out_unregister_blk;
	}

	unload_wq = alloc_workqueue("ibnbd_unload_wq", WQ_MEM_RECLAIM, 0);
	if (!unload_wq) {
		pr_err("Failed to load module, alloc ibnbd_unload_wq failed\n");
		goto out_destroy_sysfs_files;
	}

	return 0;

out_destroy_sysfs_files:
	ibnbd_clt_destroy_sysfs_files();
out_unregister_blk:
	unregister_blkdev(ibnbd_client_major, "ibnbd");
out:
	return err;
}

static void __exit ibnbd_client_exit(void)
{
	pr_info("Unloading module\n");
	ibnbd_destroy_sessions();
	unregister_blkdev(ibnbd_client_major, "ibnbd");
	ida_destroy(&index_ida);
	destroy_workqueue(unload_wq);
	pr_info("Module unloaded\n");
}

module_init(ibnbd_client_init);
module_exit(ibnbd_client_exit);
