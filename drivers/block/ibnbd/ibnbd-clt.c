/*
 * ibnbd_client device driver
 */

#define pr_fmt(fmt) KBUILD_MODNAME " L" __stringify(__LINE__) ": " fmt

#include <linux/module.h>
#include <linux/blkdev.h>
#include <linux/hdreg.h>		/* for hd_geometry */
#include <linux/scatterlist.h>
#include <linux/idr.h>

#include "ibnbd.h"
#include "ibnbd-clt.h"
#include "ibnbd-clt-sysfs.h"

MODULE_AUTHOR("ibnbd@profitbricks.com");
MODULE_DESCRIPTION("InfiniBand Network Block Device Client");
MODULE_VERSION(__stringify(IBNBD_VER));
MODULE_LICENSE("GPL");

static int ibnbd_client_major;
static DEFINE_IDR(g_index_idr);
static DEFINE_RWLOCK(g_index_lock);
static DEFINE_SPINLOCK(sess_lock);
static DEFINE_SPINLOCK(dev_lock);
static LIST_HEAD(session_list);
static LIST_HEAD(devs_list);
static DECLARE_WAIT_QUEUE_HEAD(sess_list_waitq);
static struct ibtrs_clt_ops ops;

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

inline bool ibnbd_clt_dev_is_open(struct ibnbd_clt_dev *dev)
{
	return dev->dev_state == DEV_STATE_OPEN;
}

static void ibnbd_clt_put_dev(struct ibnbd_clt_dev *dev)
{
	if (!atomic_dec_if_positive(&dev->refcount)) {
		write_lock(&g_index_lock);
		idr_remove(&g_index_idr, dev->clt_device_id);
		write_unlock(&g_index_lock);
		kfree(dev->hw_queues);
		kfree(dev->close_compl);
		ibnbd_clt_put_sess(dev->sess);
		kfree(dev);
	}
}

static int ibnbd_clt_get_dev(struct ibnbd_clt_dev *dev)
{
	return atomic_inc_not_zero(&dev->refcount);
}

static struct ibnbd_clt_dev *g_get_dev(int dev_id)
{
	struct ibnbd_clt_dev *dev;

	read_lock(&g_index_lock);
	dev = idr_find(&g_index_idr, dev_id);
	if (!dev)
		dev = ERR_PTR(-ENXIO);
	read_unlock(&g_index_lock);

	return dev;
}

static void ibnbd_clt_set_dev_attr(struct ibnbd_clt_dev *dev,
				   const struct ibnbd_msg_open_rsp *rsp)
{
	dev->device_id			= rsp->device_id;
	dev->nsectors			= rsp->nsectors;
	dev->logical_block_size		= rsp->logical_block_size;
	dev->physical_block_size	= rsp->physical_block_size;
	dev->max_write_same_sectors	= rsp->max_write_same_sectors;
	dev->max_discard_sectors	= rsp->max_discard_sectors;
	dev->discard_zeroes_data	= rsp->discard_zeroes_data;
	dev->discard_granularity	= rsp->discard_granularity;
	dev->discard_alignment		= rsp->discard_alignment;
	dev->secure_discard		= rsp->secure_discard;
	dev->rotational			= rsp->rotational;
	dev->remote_io_mode		= rsp->io_mode;

	if (dev->remote_io_mode == IBNBD_FILEIO) {
		dev->max_hw_sectors = dev->sess->max_io_size /
			rsp->logical_block_size;
		dev->max_segments = BMAX_SEGMENTS;
	} else {
		dev->max_hw_sectors = dev->sess->max_io_size /
			rsp->logical_block_size <
			rsp->max_hw_sectors ?
			dev->sess->max_io_size /
			rsp->logical_block_size : rsp->max_hw_sectors;
		dev->max_segments = rsp->max_segments > BMAX_SEGMENTS ?
				    BMAX_SEGMENTS : rsp->max_segments;
	}
}

static void ibnbd_clt_revalidate_disk(struct ibnbd_clt_dev *dev,
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
}

static void process_msg_sess_info_rsp(struct ibnbd_clt_session *sess,
				      struct ibnbd_msg_sess_info_rsp *msg)
{
	sess->ver = min_t(u8, msg->ver, IBNBD_VERSION);
	pr_debug("Session to %s (%s) using protocol version %d (client version: %d,"
		 " server version: %d)\n", sess->str_addr, sess->hostname, sess->ver,
		 IBNBD_VERSION, msg->ver);
}

static int process_msg_open_rsp(struct ibnbd_clt_session *sess,
				struct ibnbd_msg_open_rsp *rsp)
{
	struct ibnbd_clt_dev *dev;
	int err = 0;

	dev = g_get_dev(rsp->clt_device_id);
	if (IS_ERR(dev)) {
		pr_err("Open-Response message received from session %s"
		       " for unknown device (id: %d)\n", sess->str_addr,
		       rsp->clt_device_id);
		return -ENOENT;
	}

	if (!ibnbd_clt_get_dev(dev)) {
		pr_err("Failed to process Open-Response message from session"
		       " %s, unable to get reference to device (id: %d)",
		       sess->str_addr, rsp->clt_device_id);
		return -ENOENT;
	}

	mutex_lock(&dev->lock);

	if (dev->dev_state == DEV_STATE_UNMAPPED) {
		ibnbd_info(dev, "Ignoring Open-Response message from server for "
			   " unmapped device\n");
		err = -ENOENT;
		goto out;
	}

	if (rsp->result) {
		ibnbd_err(dev, "Server failed to open device for mapping, err:"
			  " %d\n", rsp->result);
		dev->open_errno = rsp->result;
		if (dev->open_compl)
			complete(dev->open_compl);
		goto out;
	}

	if (dev->dev_state == DEV_STATE_CLOSED) {
		/* if the device was remapped and the size changed in the
		 * meantime we need to revalidate it
		 */
		if (dev->nsectors != rsp->nsectors)
			ibnbd_clt_revalidate_disk(dev, (size_t)rsp->nsectors);
		ibnbd_info(dev, "Device online, device remapped successfully\n");
	}

	ibnbd_clt_set_dev_attr(dev, rsp);

	dev->dev_state = DEV_STATE_OPEN;
	if (dev->open_compl)
		complete(dev->open_compl);

out:
	mutex_unlock(&dev->lock);
	ibnbd_clt_put_dev(dev);

	return err;
}

static void process_msg_revalidate(struct ibnbd_clt_session *sess,
				   struct ibnbd_msg_revalidate *msg)
{
	struct ibnbd_clt_dev *dev;

	dev = g_get_dev(msg->clt_device_id);
	if (IS_ERR(dev)) {
		pr_err("Received device revalidation message from session %s"
		       " for non-existent device (id %d)\n", sess->str_addr,
		       msg->clt_device_id);
		return;
	}

	if (!ibnbd_clt_get_dev(dev)) {
		pr_err("Failed to process device revalidation message from"
		       " session %s, unable to get reference to device"
		       " (id: %d)", sess->str_addr, msg->clt_device_id);
		return;
	}

	mutex_lock(&dev->lock);

	if (dev->dev_state == DEV_STATE_UNMAPPED) {
		ibnbd_err(dev, "Received device revalidation message"
			  " for unmapped device\n");
		goto out;
	}

	if (dev->nsectors != msg->nsectors &&
	    dev->dev_state == DEV_STATE_OPEN) {
		ibnbd_clt_revalidate_disk(dev, (size_t)msg->nsectors);
	} else {
		ibnbd_info(dev, "Ignoring device revalidate message, "
			   "current device size is the same as in the "
			   "revalidate message, %llu sectors\n", msg->nsectors);
	}

out:
	mutex_unlock(&dev->lock);
	ibnbd_clt_put_dev(dev);
}

static int send_msg_close(struct ibtrs_clt_sess *sess, u32 device_id)
{
	struct ibnbd_msg_close msg;
	struct kvec vec = {
		.iov_base = &msg,
		.iov_len  = sizeof(msg)
	};

	msg.hdr.type	= IBNBD_MSG_CLOSE;
	msg.device_id	= device_id;

	return ibtrs_clt_send(sess, &vec, 1);
}

static void ibnbd_clt_recv(void *priv, const void *msg, size_t len)
{
	const struct ibnbd_msg_hdr *hdr = msg;
	struct ibnbd_clt_session *sess = priv;

	if (unlikely(WARN_ON(!hdr) || ibnbd_validate_message(msg, len)))
		return;

	print_hex_dump_debug("", DUMP_PREFIX_OFFSET, 8, 1, msg, len, true);

	switch (hdr->type) {
	case IBNBD_MSG_SESS_INFO_RSP: {
		struct ibnbd_msg_sess_info_rsp *rsp =
			(struct ibnbd_msg_sess_info_rsp *)msg;

		process_msg_sess_info_rsp(sess, rsp);
		if (sess->sess_info_compl)
			complete(sess->sess_info_compl);
		break;
	}
	case IBNBD_MSG_OPEN_RSP: {
		int err;
		struct ibnbd_msg_open_rsp *rsp =
			(struct ibnbd_msg_open_rsp *)msg;

		if (process_msg_open_rsp(sess, rsp) && !rsp->result) {
			pr_err("Failed to process open response message from"
			       " server, sending close message for dev id:"
			       " %u\n", rsp->device_id);

			err = send_msg_close(sess->sess, rsp->device_id);
			if (err)
				pr_err("Failed to send close msg for device"
				       " with id: %u, err: %d\n",
				       rsp->device_id, err);
		}

		break;
	}
	case IBNBD_MSG_CLOSE_RSP: {
		struct ibnbd_clt_dev *dev;
		struct ibnbd_msg_close_rsp *rsp =
			(struct ibnbd_msg_close_rsp *)msg;

		dev = g_get_dev(rsp->clt_device_id);
		if (IS_ERR(dev)) {
			pr_err("Close-Response message received from session %s"
			       " for unknown device (id: %u)\n", sess->str_addr,
			       rsp->clt_device_id);
			break;
		}
		if (dev->close_compl && dev->dev_state == DEV_STATE_UNMAPPED)
			complete(dev->close_compl);

		break;
	}
	case IBNBD_MSG_REVAL:
		process_msg_revalidate(sess,
				       (struct ibnbd_msg_revalidate *)msg);
		break;
	default:
		pr_err("IBNBD message with unknown type %d received from"
		       " session %s\n", hdr->type, sess->str_addr);
		break;
	}
}

static void ibnbd_blk_delay_work(struct work_struct *work)
{
	struct ibnbd_clt_dev *dev;

	dev = container_of(work, struct ibnbd_clt_dev, rq_delay_work.work);
	spin_lock_irq(dev->queue->queue_lock);
	blk_start_queue(dev->queue);
	spin_unlock_irq(dev->queue->queue_lock);
}

/**
 * What is the difference between this and original blk_delay_queue() ?
 * Here the stop queue flag is cleared, so we are like MQ.
 */
static void ibnbd_blk_delay_queue(struct ibnbd_clt_dev *dev, unsigned long msecs)
{
	int cpu = get_cpu();

	kblockd_schedule_delayed_work_on(cpu, &dev->rq_delay_work,
					 msecs_to_jiffies(msecs));
	put_cpu();
}

static inline void ibnbd_clt_dev_requeue(struct ibnbd_queue *q)
{
	struct ibnbd_clt_dev *dev = q->dev;

	if (dev->queue_mode == BLK_MQ) {
		if (WARN_ON(!q->hctx))
			return;
		blk_mq_delay_queue(q->hctx, 0);
	} else if (dev->queue_mode == BLK_RQ) {
		ibnbd_blk_delay_queue(q->dev, 0);
	} else {
		WARN(1, "We support requeueing only for RQ or MQ");
	}
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
	return (cpu + 1) % NR_CPUS;
}

/**
 * get_cpu_rr_var() - returns pointer to percpu var containing last cpu requeued
 *
 * It also sets the var to the current cpu if the var was never set before
 * (== -1).
 */
#define get_cpu_rr_var(percpu) ({		\
	int *cpup;				\
						\
	cpup = &get_cpu_var(*percpu);		\
	if (unlikely(*cpup < 0))		\
		*cpup = smp_processor_id();	\
	cpup;					\
})

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
	int cpuv;

	int *uninitialized_var(cpup);

	/*
	 * To keep fairness and not to let other queues starve we always
	 * try to wake up someone else in round-robin manner.  That of course
	 * increases latency but queues always have a chance to be executed.
	 */
	cpup = get_cpu_rr_var(sess->cpu_rr);
	cpuv = (*cpup + 1) % num_online_cpus();
	for (cpu_q = ibnbd_get_cpu_qlist(sess, cpuv); cpu_q;
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
 *     we can put that number of queues (hctxs) to sleep: M x NR_CPUS.
 *     If number of tags N < M x NR_CPUS finally we will get an IO hang.
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

static struct ibtrs_tag *ibnbd_get_tag(struct ibnbd_clt_session *sess, int cpu,
				       size_t tag_bytes, int wait)
{
	struct ibtrs_tag *tag;

	tag = ibtrs_get_tag(sess->sess, cpu, tag_bytes,
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
	ibtrs_put_tag(sess->sess, tag);
	atomic_dec(&sess->busy);
	/* Paired with ibnbd_clt_dev_add_to_requeue().  Decrement first
	 * and then check queue bits.
	 */
	smp_mb__after_atomic();
	ibnbd_requeue_all_if_idle(sess);
}

static struct ibnbd_iu *ibnbd_get_iu(struct ibnbd_clt_session *sess,
				     size_t tag_bytes, int wait)
{
	struct ibnbd_iu *iu;
	struct ibtrs_tag *tag;

	tag = ibnbd_get_tag(sess, -1, tag_bytes,
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

	switch (dev->queue_mode) {
	case BLK_MQ:
		iu = blk_mq_rq_to_pdu(rq);
		ibnbd_put_tag(sess, iu->tag);
		blk_mq_end_request(rq, iu->errno);
		if (rq->rq_flags & RQF_SPECIAL_PAYLOAD)
			__free_page(rq->special_vec.bv_page);
		break;
	case BLK_RQ:
		iu = rq->special;
		blk_end_request_all(rq, iu->errno);
		if (rq->rq_flags & RQF_SPECIAL_PAYLOAD)
			__free_page(rq->special_vec.bv_page);
		break;
	default:
		WARN(true, "dev->queue_mode , contains unexpected"
		     " value: %d. Memory Corruption? Inflight I/O stalled!\n",
		     dev->queue_mode);
		return;
	}
}

static void ibnbd_clt_rdma_ev(void *priv, enum ibtrs_clt_rdma_ev ev, int errno)
{
	struct ibnbd_iu *iu		= (struct ibnbd_iu *)priv;
	struct ibnbd_clt_dev *dev	= iu->dev;
	struct request *rq;
	const int flags = iu->msg.rw;
	bool is_read;

	switch (dev->queue_mode) {
	case BLK_MQ:
		rq = iu->rq;
		is_read = req_op(rq) == READ;
		iu->errno = errno;
		if (softirq_enable) {
			blk_mq_complete_request(rq, errno);
		} else {
			ibnbd_put_tag(dev->sess, iu->tag);
			blk_mq_end_request(rq, errno);

			if (rq->rq_flags & RQF_SPECIAL_PAYLOAD)
				__free_page(rq->special_vec.bv_page);

		}
		break;
	case BLK_RQ:
		rq = iu->rq;
		is_read = req_op(rq) == READ;
		iu->errno = errno;
		if (softirq_enable) {
			blk_complete_request(rq);
		} else {
			blk_end_request_all(rq, errno);
			if (rq->rq_flags & RQF_SPECIAL_PAYLOAD)
				__free_page(rq->special_vec.bv_page);
		}
		break;
	default:
		WARN(true, "dev->queue_mode , contains unexpected"
		     " value: %d. Memory Corruption? Inflight I/O stalled!\n",
		     dev->queue_mode);
		return;
	}

	if (errno)
		ibnbd_info_rl(dev, "%s I/O failed with err: %d, flags: 0x%x\n",
			      is_read ? "read" : "write", errno, flags);
}

static int send_msg_open(struct ibnbd_clt_dev *dev)
{
	int err;
	struct ibnbd_msg_open msg;
	struct kvec vec = {
		.iov_base = &msg,
		.iov_len  = sizeof(msg)
	};

	msg.hdr.type		= IBNBD_MSG_OPEN;
	msg.clt_device_id	= dev->clt_device_id;
	msg.access_mode		= dev->access_mode;
	msg.io_mode		= dev->io_mode;
	strlcpy(msg.dev_name, dev->pathname, sizeof(msg.dev_name));

	err = ibtrs_clt_send(dev->sess->sess, &vec, 1);

	return err;
}

static int send_msg_sess_info(struct ibnbd_clt_session *sess)
{
	struct ibnbd_msg_sess_info msg;
	struct kvec vec = {
		.iov_base = &msg,
		.iov_len  = sizeof(msg)
	};

	msg.hdr.type	= IBNBD_MSG_SESS_INFO;
	msg.ver		= IBNBD_VERSION;

	return ibtrs_clt_send(sess->sess, &vec, 1);
}

int open_remote_device(struct ibnbd_clt_dev *dev)
{
	int err;

	err = send_msg_open(dev);
	if (unlikely(err)) {
		ibnbd_err(dev, "Failed to send open msg, err: %d\n", err);
		return err;
	}

	return 0;
}

static int find_dev_cb(int id, void *ptr, void *data)
{
	struct ibnbd_clt_dev *dev = ptr;
	struct ibnbd_clt_session *sess = data;

	if (dev->sess == sess && dev->dev_state == DEV_STATE_INIT &&
	    dev->open_compl) {
		dev->dev_state = DEV_STATE_INIT_CLOSED;
		dev->open_errno = -ECOMM;
		complete(dev->open_compl);
		ibnbd_err(dev, "Device offline, session disconnected.\n");
	} else if (dev->sess == sess && dev->dev_state == DEV_STATE_UNMAPPED &&
		   dev->close_compl) {
		complete(dev->close_compl);
		ibnbd_err(dev, "Device closed, session disconnected.\n");
	}

	return 0;
}

static void __set_dev_states_closed(struct ibnbd_clt_session *sess)
{
	struct ibnbd_clt_dev *dev;

	list_for_each_entry(dev, &sess->devs_list, list) {
		mutex_lock(&dev->lock);
		dev->dev_state = DEV_STATE_CLOSED;
		dev->open_errno = -ECOMM;
		if (dev->open_compl)
			complete(dev->open_compl);
		ibnbd_err(dev, "Device offline, session disconnected.\n");
		mutex_unlock(&dev->lock);
	}
	read_lock(&g_index_lock);
	idr_for_each(&g_index_idr, find_dev_cb, sess);
	read_unlock(&g_index_lock);
}

static int update_sess_info(struct ibnbd_clt_session *sess)
{
	int err;

	sess->sess_info_compl = kmalloc(sizeof(*sess->sess_info_compl),
					GFP_KERNEL);
	if (!sess->sess_info_compl) {
		pr_err("Failed to allocate memory for completion for session"
		       " %s (%s)\n", sess->str_addr, sess->hostname);
		return -ENOMEM;
	}

	init_completion(sess->sess_info_compl);

	err = send_msg_sess_info(sess);
	if (unlikely(err)) {
		pr_err("Failed to send SESS_INFO message for session %s (%s)\n",
		       sess->str_addr, sess->hostname);
		goto out;
	}

	/* wait for IBNBD_MSG_SESS_INFO_RSP from server */
	wait_for_completion(sess->sess_info_compl);
out:
	kfree(sess->sess_info_compl);
	sess->sess_info_compl = NULL;

	return err;
}

static void reopen_worker(struct work_struct *work)
{
	struct ibnbd_work *w;
	struct ibnbd_clt_session *sess;
	struct ibnbd_clt_dev *dev;
	int err;

	w = container_of(work, struct ibnbd_work, work);
	sess = w->sess;
	kfree(w);

	mutex_lock(&sess->lock);
	if (sess->state == CLT_SESS_STATE_DESTROYED) {
		mutex_unlock(&sess->lock);
		return;
	}
	err = update_sess_info(sess);
	if (unlikely(err))
		goto out;
	list_for_each_entry(dev, &sess->devs_list, list) {
		ibnbd_info(dev, "session reconnected, remapping device\n");
		open_remote_device(dev);
	}
out:
	mutex_unlock(&sess->lock);

	ibnbd_clt_put_sess(sess);
}

static int ibnbd_schedule_reopen(struct ibnbd_clt_session *sess)
{
	struct ibnbd_work *w;

	w = kmalloc(sizeof(*w), GFP_KERNEL);
	if (!w) {
		pr_err("Failed to allocate memory to schedule reopen of"
		       " devices for session %s\n", sess->str_addr);
		return -ENOMEM;
	}

	if (WARN_ON(!ibnbd_clt_get_sess(sess))) {
		kfree(w);
		return -ENOENT;
	}

	w->sess = sess;
	INIT_WORK(&w->work, reopen_worker);
	schedule_work(&w->work);

	return 0;
}

static void ibnbd_clt_sess_ev(void *priv, enum ibtrs_clt_sess_ev ev, int errno)
{
	struct ibnbd_clt_session *sess = priv;
	struct ibtrs_attrs attrs;

	switch (ev) {
	case IBTRS_CLT_SESS_EV_DISCONNECTED:
		if (sess->sess_info_compl)
			complete(sess->sess_info_compl);
		mutex_lock(&sess->lock);
		if (sess->state == CLT_SESS_STATE_DESTROYED) {
			mutex_unlock(&sess->lock);
			return;
		}
		sess->state = CLT_SESS_STATE_DISCONNECTED;
		__set_dev_states_closed(sess);
		mutex_unlock(&sess->lock);
		break;
	case IBTRS_CLT_SESS_EV_RECONNECT:
		mutex_lock(&sess->lock);
		if (sess->state == CLT_SESS_STATE_DESTROYED) {
			/* This may happen if the session started to be closed
			 * before the reconnect event arrived. In this case, we
			 * just return and the session will be closed later
			 */
			mutex_unlock(&sess->lock);
			return;
		}
		sess->state = CLT_SESS_STATE_READY;

		mutex_unlock(&sess->lock);
		memset(&attrs, 0, sizeof(attrs));
		ibtrs_clt_query(sess->sess, &attrs);
		strlcpy(sess->hostname, attrs.hostname, sizeof(sess->hostname));
		sess->max_io_size = attrs.max_io_size;
		ibnbd_schedule_reopen(sess);
		break;
	case IBTRS_CLT_SESS_EV_MAX_RECONN_EXCEEDED:
		pr_info("Reconnect attempts exceeded for session %s\n",
			sess->str_addr);
		break;
	default:
		pr_err("Unknown session event received (%d), session: (%s)\n",
		       ev, sess->str_addr);
	}
}

static int ibnbd_cmp_sock_addr(const struct sockaddr_storage *a,
			       const struct sockaddr_storage *b)
{
	if (a->ss_family == b->ss_family) {
		switch (a->ss_family) {
		case AF_INET:
			return memcmp(&((struct sockaddr_in *)a)->sin_addr,
				      &((struct sockaddr_in *)b)->sin_addr,
				      sizeof(struct in_addr));
		case AF_INET6:
			return memcmp(&((struct sockaddr_in6 *)a)->sin6_addr,
				      &((struct sockaddr_in6 *)b)->sin6_addr,
				      sizeof(struct in6_addr));
		case AF_IB:
			return memcmp(&((struct sockaddr_ib *)a)->sib_addr,
				      &((struct sockaddr_ib *)b)->sib_addr,
				      sizeof(struct ib_addr));
		default:
			pr_err("Unknown address family: %d\n", a->ss_family);
			return -EINVAL;
		}
	} else {
		return -1;
	}
}

struct ibnbd_clt_session *
ibnbd_clt_find_sess(const struct sockaddr_storage *addr)
{
	struct ibnbd_clt_session *sess;

	spin_lock(&sess_lock);
	list_for_each_entry(sess, &session_list, list)
		if (!ibnbd_cmp_sock_addr(&sess->addr, addr)) {
			spin_unlock(&sess_lock);
			return sess;
		}
	spin_unlock(&sess_lock);

	return NULL;
}

static void ibnbd_init_cpu_qlists(struct ibnbd_cpu_qlist __percpu *cpu_queues)
{
	unsigned int cpu;
	struct ibnbd_cpu_qlist *cpu_q;

	for_each_online_cpu(cpu) {
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
	blk_mq_free_tag_set(&sess->tag_set);
}

struct ibnbd_clt_session *ibnbd_create_session(const struct sockaddr_storage *addr)
{
	struct ibnbd_clt_session *sess;
	struct ibtrs_attrs attrs;
	char str_addr[IBTRS_ADDRLEN];
	int err;
	int cpu;

	err = ibtrs_addr_to_str(addr, str_addr, sizeof(str_addr));
	if (err < 0) {
		pr_err("Can't create session, invalid address\n");
		return ERR_PTR(err);
	}

	pr_debug("Establishing session to %s\n", str_addr);

	if (ibnbd_clt_find_sess(addr)) {
		pr_err("Can't create session, session to %s already exists\n",
		       str_addr);
		return ERR_PTR(-EEXIST);
	}

	sess = kzalloc_node(sizeof(*sess), GFP_KERNEL, NUMA_NO_NODE);
	if (unlikely(!sess)) {
		pr_err("Failed to create session to %s,"
		       " allocating session struct failed\n", str_addr);
		return ERR_PTR(-ENOMEM);
	}
	sess->cpu_queues = alloc_percpu(struct ibnbd_cpu_qlist);
	if (unlikely(!sess->cpu_queues)) {
		pr_err("Failed to create session to %s,"
		       " alloc of percpu var (cpu_queues) failed\n", str_addr);
		kvfree(sess);
		return ERR_PTR(-ENOMEM);
	}
	ibnbd_init_cpu_qlists(sess->cpu_queues);

	/**
	 * That is simple percpu variable which stores cpu indeces, which are
	 * incremented on each access.  We need that for the sake of fairness
	 * to wake up queues in a round-robin manner.
	 */
	sess->cpu_rr = alloc_percpu(int);
	if (unlikely(!sess->cpu_rr)) {
		pr_err("Failed to create session to %s,"
		       " alloc of percpu var (cpu_rr) failed\n", str_addr);
		free_percpu(sess->cpu_queues);
		kfree(sess);
		return ERR_PTR(-ENOMEM);
	}
	for_each_online_cpu(cpu) {
		*per_cpu_ptr(sess->cpu_rr, cpu) = -1;
	}

	memset(&attrs, 0, sizeof(attrs));
	memcpy(&sess->addr, addr, sizeof(sess->addr));
	strlcpy(sess->str_addr, str_addr, sizeof(sess->str_addr));

	spin_lock(&sess_lock);
	list_add(&sess->list, &session_list);
	spin_unlock(&sess_lock);

	atomic_set(&sess->busy, 0);
	mutex_init(&sess->lock);
	INIT_LIST_HEAD(&sess->devs_list);
	bitmap_zero(sess->cpu_queues_bm, NR_CPUS);
	kref_init(&sess->refcount);
	sess->state = CLT_SESS_STATE_DISCONNECTED;

	sess->sess = ibtrs_clt_open(addr, sizeof(struct ibnbd_iu), sess,
				    RECONNECT_DELAY, BMAX_SEGMENTS,
				    MAX_RECONNECTS);
	if (!IS_ERR(sess->sess)) {
		mutex_lock(&sess->lock);
		sess->state = CLT_SESS_STATE_READY;
		mutex_unlock(&sess->lock);
	} else {
		err = PTR_ERR(sess->sess);
		goto out_free;
	}

	ibtrs_clt_query(sess->sess, &attrs);
	strlcpy(sess->hostname, attrs.hostname, sizeof(sess->hostname));
	sess->max_io_size = attrs.max_io_size;
	sess->queue_depth = attrs.queue_depth;

	err = setup_mq_tags(sess);
	if (unlikely(err))
		goto close_sess;

	err = update_sess_info(sess);
	if (unlikely(err))
		goto destroy_tags;

	return sess;

destroy_tags:
	destroy_mq_tags(sess);
close_sess:
	ibtrs_clt_close(sess->sess);
out_free:
	spin_lock(&sess_lock);
	list_del(&sess->list);
	spin_unlock(&sess_lock);
	free_percpu(sess->cpu_queues);
	free_percpu(sess->cpu_rr);
	kfree(sess);
	return ERR_PTR(err);
}

static void ibnbd_clt_destroy_session(struct ibnbd_clt_session *sess)
{
	mutex_lock(&sess->lock);
	sess->state = CLT_SESS_STATE_DESTROYED;

	if (!list_empty(&sess->devs_list)) {
		mutex_unlock(&sess->lock);
		pr_warn("Device list is not empty,"
			" closing session to %s failed\n", sess->str_addr);
		return;
	}
	mutex_unlock(&sess->lock);
	ibtrs_clt_close(sess->sess);

	destroy_mq_tags(sess);
	spin_lock(&sess_lock);
	list_del(&sess->list);
	spin_unlock(&sess_lock);
	wake_up(&sess_list_waitq);

	free_percpu(sess->cpu_queues);
	free_percpu(sess->cpu_rr);
	kfree(sess);
}

void ibnbd_clt_sess_release(struct kref *ref)
{
	struct ibnbd_clt_session *sess;

	sess = container_of(ref, struct ibnbd_clt_session, refcount);
	ibnbd_clt_destroy_session(sess);
}

static int ibnbd_client_open(struct block_device *block_device, fmode_t mode)
{
	struct ibnbd_clt_dev *dev = block_device->bd_disk->private_data;

	if (dev->read_only && (mode & FMODE_WRITE))
		return -EPERM;

	if (dev->dev_state == DEV_STATE_UNMAPPED ||
	    !ibnbd_clt_get_dev(dev))
		return -EIO;

	pr_debug("OPEN, name=%s, open_cnt=%d\n", dev->gd->disk_name,
		 atomic_read(&dev->refcount) - 1);

	return 0;
}

static void ibnbd_client_release(struct gendisk *gen, fmode_t mode)
{
	struct ibnbd_clt_dev *dev = gen->private_data;

	pr_debug("RELEASE, name=%s, open_cnt %d\n", dev->gd->disk_name,
		 atomic_read(&dev->refcount) - 1);

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

static inline int ibnbd_clt_setup_discard(struct request *rq)
{
	struct page *page;

	page = alloc_page(GFP_ATOMIC | __GFP_ZERO);
	if (!page)
		return -ENOMEM;
	rq->special_vec.bv_page = page;
	rq->special_vec.bv_offset = 0;
	rq->special_vec.bv_len = PAGE_SIZE;
	rq->rq_flags |= RQF_SPECIAL_PAYLOAD;
	return 0;
}

static int ibnbd_client_xfer_request(struct ibnbd_clt_dev *dev,
				     struct request *rq,
				     struct ibnbd_iu *iu)
{
	int err;

	unsigned int sg_cnt;
	size_t size;
	struct kvec vec;
	struct ibtrs_clt_sess *sess = dev->sess->sess;
	struct ibtrs_tag *tag = iu->tag;
	struct scatterlist *sg = iu->sglist;

	if (req_op(rq) == REQ_OP_DISCARD) {
		err = ibnbd_clt_setup_discard(rq);
		if (err)
			return err;
	}
	sg_cnt = blk_rq_nr_phys_segments(rq);

	if (sg_cnt == 0)
		sg_mark_end(&sg[0]);
	else
		sg_mark_end(&sg[sg_cnt - 1]);

	iu->rq		= rq;
	iu->dev		= dev;
	iu->msg.sector	= blk_rq_pos(rq);
	iu->msg.bi_size = blk_rq_bytes(rq);
	iu->msg.rw	= rq_cmd_to_ibnbd_io_flags(rq);

	sg_cnt = blk_rq_map_sg(dev->queue, rq, sg);

	iu->msg.hdr.type	= IBNBD_MSG_IO;
	iu->msg.device_id	= dev->device_id;

	size = ibnbd_clt_get_sg_size(sg, sg_cnt);
	vec = (struct kvec) {
		.iov_base = &iu->msg,
		.iov_len  = sizeof(iu->msg)
	};

	if (req_op(rq) == READ)
		err = ibtrs_clt_request_rdma_write(sess, tag, iu, &vec, 1, size,
						   sg, sg_cnt);
	else
		err = ibtrs_clt_rdma_write(sess, tag, iu, &vec, 1, size, sg,
					   sg_cnt);
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

	if (WARN_ON(dev->queue_mode != BLK_MQ))
		return;
	blk_mq_stop_hw_queue(hctx);

	if (delay != IBNBD_DELAY_IFBUSY)
		blk_mq_delay_queue(hctx, delay);
	else if (unlikely(!ibnbd_clt_dev_add_to_requeue(dev, q)))
		/* If session is not busy we have to restart
		 * the queue ourselves.
		 */
		blk_mq_delay_queue(hctx, IBNBD_DELAY_10ms);
}

static void ibnbd_clt_dev_kick_queue(struct ibnbd_clt_dev *dev, int delay)
{
	if (WARN_ON(dev->queue_mode != BLK_RQ))
		return;
	blk_stop_queue(dev->queue);

	if (delay != IBNBD_DELAY_IFBUSY)
		ibnbd_blk_delay_queue(dev, delay);
	else if (unlikely(!ibnbd_clt_dev_add_to_requeue(dev, dev->hw_queues)))
		/* If session is not busy we have to restart
		 * the queue ourselves.
		 */
		ibnbd_blk_delay_queue(dev, IBNBD_DELAY_10ms);
}

static int ibnbd_queue_rq(struct blk_mq_hw_ctx *hctx,
			  const struct blk_mq_queue_data *bd)
{
	struct request *rq = bd->rq;
	struct ibnbd_clt_dev *dev = rq->rq_disk->private_data;
	struct ibnbd_iu *iu = blk_mq_rq_to_pdu(rq);
	int err;

	if (unlikely(!ibnbd_clt_dev_is_open(dev)))
		return BLK_MQ_RQ_QUEUE_ERROR;

	iu->tag = ibnbd_get_tag(dev->sess, hctx->next_cpu, blk_rq_bytes(rq),
				IBTRS_TAG_NOWAIT);
	if (unlikely(!iu->tag)) {
		ibnbd_clt_dev_kick_mq_queue(dev, hctx, IBNBD_DELAY_IFBUSY);
		return BLK_MQ_RQ_QUEUE_BUSY;
	}

	blk_mq_start_request(rq);
	err = ibnbd_client_xfer_request(dev, rq, iu);
	if (likely(err == 0))
		return BLK_MQ_RQ_QUEUE_OK;
	if (unlikely(err == -EAGAIN || err == -ENOMEM)) {
		ibnbd_clt_dev_kick_mq_queue(dev, hctx, IBNBD_DELAY_10ms);
		ibnbd_put_tag(dev->sess, iu->tag);
		return BLK_MQ_RQ_QUEUE_BUSY;
	}

	ibnbd_put_tag(dev->sess, iu->tag);
	return BLK_MQ_RQ_QUEUE_ERROR;
}

static int ibnbd_init_request(void *data, struct request *rq,
			      unsigned int hctx_idx, unsigned int request_idx,
			      unsigned int numa_node)
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

static int ibnbd_rq_prep_fn(struct request_queue *q, struct request *rq)
{
	struct ibnbd_clt_dev *dev = q->queuedata;
	struct ibnbd_iu *iu;

	iu = ibnbd_get_iu(dev->sess, blk_rq_bytes(rq), IBTRS_TAG_NOWAIT);
	if (likely(iu)) {
		rq->special = iu;
		rq->rq_flags |= RQF_DONTPREP;

		return BLKPREP_OK;
	}

	ibnbd_clt_dev_kick_queue(dev, IBNBD_DELAY_IFBUSY);
	return BLKPREP_DEFER;
}

static void ibnbd_rq_unprep_fn(struct request_queue *q, struct request *rq)
{
	struct ibnbd_clt_dev *dev = q->queuedata;

	if (WARN_ON(!rq->special))
		return;
	ibnbd_put_iu(dev->sess, rq->special);
	rq->special = NULL;
	rq->rq_flags &= ~RQF_DONTPREP;
}

static void ibnbd_clt_request(struct request_queue *q)
__must_hold(q->queue_lock)
{
	int err;
	struct request *req;
	struct ibnbd_iu *iu;
	struct ibnbd_clt_dev *dev = q->queuedata;

	while ((req = blk_fetch_request(q)) != NULL) {
		spin_unlock_irq(q->queue_lock);

		if (unlikely(!ibnbd_clt_dev_is_open(dev))) {
			err = -EIO;
			goto next;
		}

		iu = req->special;
		if (WARN_ON(!iu)) {
			err = -EIO;
			goto next;
		}

		sg_init_table(iu->sglist, dev->max_segments);
		err = ibnbd_client_xfer_request(dev, req, iu);
next:
		if (unlikely(err == -EAGAIN || err == -ENOMEM)) {
			ibnbd_rq_unprep_fn(q, req);
			spin_lock_irq(q->queue_lock);
			blk_requeue_request(q, req);
			ibnbd_clt_dev_kick_queue(dev, IBNBD_DELAY_10ms);
			break;
		} else if (err) {
			blk_end_request_all(req, err);
		}

		spin_lock_irq(q->queue_lock);
	}
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

static int setup_rq_dev(struct ibnbd_clt_dev *dev)
{
	dev->queue = blk_init_queue(ibnbd_clt_request, NULL);
	if (IS_ERR_OR_NULL(dev->queue)) {
		if (IS_ERR(dev->queue)) {
			ibnbd_err(dev, "Initializing request queue failed, "
				  "err: %ld\n", PTR_ERR(dev->queue));
			return PTR_ERR(dev->queue);
		}
		ibnbd_err(dev, "Initializing request queue failed\n");
		return -ENOMEM;
	}

	blk_queue_prep_rq(dev->queue, ibnbd_rq_prep_fn);
	blk_queue_softirq_done(dev->queue, ibnbd_softirq_done_fn);
	blk_queue_unprep_rq(dev->queue, ibnbd_rq_unprep_fn);

	return 0;
}

static void setup_request_queue(struct ibnbd_clt_dev *dev)
{
	blk_queue_logical_block_size(dev->queue, dev->logical_block_size);
	blk_queue_physical_block_size(dev->queue, dev->physical_block_size);
	blk_queue_max_hw_sectors(dev->queue, dev->max_hw_sectors);
	blk_queue_max_write_same_sectors(dev->queue,
					 dev->max_write_same_sectors);

	blk_queue_max_discard_sectors(dev->queue, dev->max_discard_sectors);
	dev->queue->limits.discard_zeroes_data	= dev->discard_zeroes_data;
	dev->queue->limits.discard_granularity	= dev->discard_granularity;
	dev->queue->limits.discard_alignment	= dev->discard_alignment;
	if (dev->max_discard_sectors)
		queue_flag_set_unlocked(QUEUE_FLAG_DISCARD, dev->queue);
	if (dev->secure_discard)
		queue_flag_set_unlocked(QUEUE_FLAG_SECERASE, dev->queue);

	queue_flag_set_unlocked(QUEUE_FLAG_SAME_COMP, dev->queue);
	queue_flag_set_unlocked(QUEUE_FLAG_SAME_FORCE, dev->queue);
	/* our hca only support 32 sg cnt, proto use one, so 31 left */
	blk_queue_max_segments(dev->queue, dev->max_segments);
	blk_queue_io_opt(dev->queue, dev->sess->max_io_size);
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
	pr_debug("disk_name=%s, capacity=%zu, queue_mode=%s\n",
		 dev->gd->disk_name,
		 dev->nsectors * (dev->logical_block_size / KERNEL_SECTOR_SIZE),
		 ibnbd_queue_mode_str(dev->queue_mode));

	set_capacity(dev->gd, dev->nsectors * (dev->logical_block_size /
					       KERNEL_SECTOR_SIZE));

	if (dev->access_mode == IBNBD_ACCESS_RO) {
		dev->read_only = true;
		set_disk_ro(dev->gd, true);
	} else {
		dev->read_only = false;
	}

	if (!dev->rotational)
		queue_flag_set_unlocked(QUEUE_FLAG_NONROT, dev->queue);
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

	switch (dev->queue_mode) {
	case BLK_MQ:
		err = setup_mq_dev(dev);
		break;
	case BLK_RQ:
		err = setup_rq_dev(dev);
		break;
	default:
		err = -EINVAL;
	}

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
				      enum ibnbd_queue_mode queue_mode,
				      const char *pathname)
{
	int ret;
	struct ibnbd_clt_dev *dev;
	size_t nr;

	dev = kzalloc_node(sizeof(*dev), GFP_KERNEL, NUMA_NO_NODE);
	if (!dev) {
		pr_err("Failed to initialize device '%s' from session %s,"
		       " allocating device structure failed\n", pathname,
		       sess->str_addr);
		return ERR_PTR(-ENOMEM);
	}

	nr = (queue_mode == BLK_MQ ? num_online_cpus() :
	      queue_mode == BLK_RQ ? 1 : 0);
	if (nr) {
		dev->hw_queues = kcalloc(nr, sizeof(*dev->hw_queues),
					 GFP_KERNEL);
		if (unlikely(!dev->hw_queues)) {
			pr_err("Failed to initialize device '%s' from session"
			       " %s, allocating hw_queues failed.", pathname,
			       sess->str_addr);
			ret = -ENOMEM;
			goto out_alloc;
		}
		/* for MQ mode we will init all hw queues after the
		 * request queue is created
		 */
		if (queue_mode == BLK_RQ)
			ibnbd_init_hw_queue(dev, dev->hw_queues, NULL);
	}

	idr_preload(GFP_KERNEL);
	write_lock(&g_index_lock);
	ret = idr_alloc(&g_index_idr, dev, 0, minor_to_index(1 << MINORBITS),
			GFP_ATOMIC);
	write_unlock(&g_index_lock);
	idr_preload_end();
	if (ret < 0) {
		pr_err("Failed to initialize device '%s' from session %s,"
		       " allocating idr failed, err: %d\n", pathname,
		       sess->str_addr, ret);
		goto out_queues;
	}

	dev->clt_device_id	= ret;
	dev->close_compl	= kmalloc(sizeof(*dev->close_compl),
					  GFP_KERNEL);
	if (!dev->close_compl) {
		pr_err("Failed to initialize device '%s' from session %s,"
		       " allocating close completion failed, err: %d\n",
		       pathname, sess->str_addr, ret);
		ret = -ENOMEM;
		goto out_idr;
	}
	init_completion(dev->close_compl);
	dev->sess		= sess;
	dev->access_mode	= access_mode;
	dev->queue_mode		= queue_mode;

	strlcpy(dev->pathname, pathname, sizeof(dev->pathname));

	INIT_DELAYED_WORK(&dev->rq_delay_work, ibnbd_blk_delay_work);
	mutex_init(&dev->lock);
	atomic_set(&dev->refcount, 1);
	dev->dev_state = DEV_STATE_INIT;

	return dev;

out_idr:
	write_lock(&g_index_lock);
	idr_remove(&g_index_idr, dev->clt_device_id);
	write_unlock(&g_index_lock);
out_queues:
	kfree(dev->hw_queues);
out_alloc:
	kfree(dev);
	return ERR_PTR(ret);
}

bool ibnbd_clt_dev_is_mapped(const char *pathname)
{
	struct ibnbd_clt_dev *dev;

	spin_lock(&dev_lock);
	list_for_each_entry(dev, &devs_list, g_list)
		if (!strncmp(dev->pathname, pathname, sizeof(dev->pathname))) {
			spin_unlock(&dev_lock);
			return true;
		}
	spin_unlock(&dev_lock);

	return false;
}

static struct ibnbd_clt_dev *
__find_sess_dev(const struct ibnbd_clt_session *sess,
		const char *pathname)
{
	struct ibnbd_clt_dev *dev;

	list_for_each_entry(dev, &sess->devs_list, list)
		if (!strncmp(dev->pathname, pathname, sizeof(dev->pathname)))
			return dev;

	return NULL;
}

struct ibnbd_clt_dev *
ibnbd_client_add_device(struct ibnbd_clt_session *sess,
			const char *pathname,
			enum ibnbd_access_mode access_mode,
			enum ibnbd_queue_mode queue_mode,
			enum ibnbd_io_mode io_mode)
{
	int ret;
	struct ibnbd_clt_dev *dev;
	struct completion *open_compl;

	pr_debug("Add remote device: server=%s, path='%s', access_mode=%d,"
		 " queue_mode=%d\n", sess->str_addr, pathname, access_mode,
		 queue_mode);

	mutex_lock(&sess->lock);

	if (sess->state != CLT_SESS_STATE_READY) {
		mutex_unlock(&sess->lock);
		pr_err("map_device: failed to map device '%s' from session %s,"
		       " session is not connected\n", pathname, sess->str_addr);
		return ERR_PTR(-ENOENT);
	}

	if (__find_sess_dev(sess, pathname)) {
		mutex_unlock(&sess->lock);
		pr_err("map_device: failed to map device '%s' from session %s,"
		       " device with same path is already mapped\n", pathname,
		       sess->str_addr);
		return ERR_PTR(-EEXIST);
	}

	mutex_unlock(&sess->lock);
	dev = init_dev(sess, access_mode, queue_mode, pathname);
	if (IS_ERR(dev)) {
		pr_err("map_device: failed to map device '%s' from session %s,"
		       " can't initialize device, err: %ld\n", pathname,
		       sess->str_addr, PTR_ERR(dev));
		return dev;
	}

	ibnbd_clt_get_sess(sess);

	open_compl = kmalloc(sizeof(*open_compl), GFP_KERNEL);
	if (!open_compl) {
		ibnbd_err(dev, "map_device: failed, Can't allocate memory for"
			  " completion\n");
		ret = -ENOMEM;
		goto out;
	}
	init_completion(open_compl);
	dev->open_compl = open_compl;
	dev->io_mode = io_mode;

	ret = open_remote_device(dev);
	if (ret) {
		ibnbd_err(dev, "map_device: failed, can't open remote device,"
			  " err: %d\n", ret);
		kfree(open_compl);
		dev->open_compl = NULL;
		ret = -EINVAL;
		goto out;
	}
	wait_for_completion(dev->open_compl);
	mutex_lock(&dev->lock);

	kfree(open_compl);
	dev->open_compl = NULL;

	if (!ibnbd_clt_dev_is_open(dev)) {
		mutex_unlock(&dev->lock);
		ret = dev->open_errno;
		ibnbd_err(dev, "map_device: failed err: %d\n", ret);
		goto out;
	}

	mutex_lock(&sess->lock);
	list_add(&dev->list, &sess->devs_list);
	mutex_unlock(&sess->lock);

	spin_lock(&dev_lock);
	list_add(&dev->g_list, &devs_list);
	spin_unlock(&dev_lock);

	pr_debug("Opened remote device: server=%s, path='%s'\n", sess->str_addr,
		 pathname);
	ret = ibnbd_client_setup_device(sess, dev, dev->clt_device_id);
	if (ret) {
		ibnbd_err(dev, "map_device: Failed to configure device, err: %d\n",
			  ret);
		mutex_unlock(&dev->lock);
		ret = -EINVAL;
		goto out_close;
	}

	ibnbd_info(dev, "map_device: Device mapped as %s (nsectors: %zu,"
		   " logical_block_size: %d, physical_block_size: %d,"
		   " max_write_same_sectors: %d, max_discard_sectors: %d,"
		   " discard_zeroes_data: %d, discard_granularity: %d,"
		   " discard_alignment: %d, secure_discard: %d, max_segments: %d,"
		   " max_hw_sectors: %d, rotational: %d)\n", dev->gd->disk_name,
		   dev->nsectors, dev->logical_block_size, dev->physical_block_size,
		   dev->max_write_same_sectors, dev->max_discard_sectors,
		   dev->discard_zeroes_data, dev->discard_granularity,
		   dev->discard_alignment, dev->secure_discard,
		   dev->max_segments, dev->max_hw_sectors, dev->rotational);

	mutex_unlock(&dev->lock);

	ibnbd_clt_add_gen_disk(dev);

	return dev;

out_close:
	if (!WARN_ON(ibnbd_close_device(dev, true)))
		wait_for_completion(dev->close_compl);
out:
	ibnbd_clt_put_dev(dev);
	return ERR_PTR(ret);
}

void ibnbd_destroy_gen_disk(struct ibnbd_clt_dev *dev)
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

	ibnbd_clt_put_dev(dev);
}

static int __close_device(struct ibnbd_clt_dev *dev, bool force)
__must_hold(&dev->sess->lock)
{
	enum ibnbd_clt_dev_state prev_state;
	int refcount, ret = 0;

	mutex_lock(&dev->lock);

	if (dev->dev_state == DEV_STATE_UNMAPPED) {
		ibnbd_info(dev, "Device is already being unmapped\n");
		ret = -EALREADY;
		goto out;
	}

	refcount = atomic_read(&dev->refcount);
	if (!force && refcount > 1) {
		ibnbd_err(dev, "Closing device failed, device is in use,"
			  " (%d device users)\n", refcount - 1);
		ret = -EBUSY;
		goto out;
	}

	prev_state = dev->dev_state;
	dev->dev_state = DEV_STATE_UNMAPPED;

	list_del(&dev->list);

	spin_lock(&dev_lock);
	list_del(&dev->g_list);
	spin_unlock(&dev_lock);

	ibnbd_clt_remove_dev_symlink(dev);
	mutex_unlock(&dev->lock);

	mutex_unlock(&dev->sess->lock);
	if (prev_state == DEV_STATE_OPEN && dev->sess->sess) {
		if (send_msg_close(dev->sess->sess, dev->device_id))
			complete(dev->close_compl);
	} else {
		complete(dev->close_compl);
	}

	mutex_lock(&dev->sess->lock);
	if (dev->gd)
		ibnbd_info(dev, "Device is unmapped\n");
	else
		ibnbd_info(dev, "Device is unmapped\n");
	return 0;
out:
	mutex_unlock(&dev->lock);
	return ret;
}

int ibnbd_close_device(struct ibnbd_clt_dev *dev, bool force)
{
	int ret;

	mutex_lock(&dev->sess->lock);
	ret = __close_device(dev, force);
	mutex_unlock(&dev->sess->lock);

	return ret;
}

static void ibnbd_destroy_sessions(void)
{
	struct ibnbd_clt_session *sess, *sn;
	struct ibnbd_clt_dev *dev, *tn;
	int ret;

	list_for_each_entry_safe(sess, sn, &session_list, list) {
		if (!ibnbd_clt_get_sess(sess))
			continue;
		mutex_lock(&sess->lock);
		sess->state = CLT_SESS_STATE_DESTROYED;
		list_for_each_entry_safe(dev, tn, &sess->devs_list, list) {
			if (!kobject_get(&dev->kobj))
				continue;
			ret = __close_device(dev, true);
			if (ret)
				ibnbd_wrn(dev, "Closing device failed, err: %d\n",
					  ret);
			else
				wait_for_completion(dev->close_compl);
			ibnbd_clt_schedule_dev_destroy(dev);
			kobject_put(&dev->kobj);
		}
		mutex_unlock(&sess->lock);
		ibnbd_clt_put_sess(sess);
	}
}

static int __init ibnbd_client_init(void)
{
	int err;

	pr_info("Loading module ibnbd_client, version: "
		__stringify(IBNBD_VER) " (softirq_enable: %d)\n",
		softirq_enable);

	ibnbd_client_major = register_blkdev(ibnbd_client_major, "ibnbd");
	if (ibnbd_client_major <= 0) {
		pr_err("Failed to load module,"
		       " block device registration failed\n");
		err = -EBUSY;
		goto out;
	}

	ops.owner	= THIS_MODULE;
	ops.recv	= ibnbd_clt_recv;
	ops.rdma_ev	= ibnbd_clt_rdma_ev;
	ops.sess_ev	= ibnbd_clt_sess_ev;
	err = ibtrs_clt_register(&ops);
	if (err) {
		pr_err("Failed to load module, IBTRS registration failed, "
		       "err: %d\n", err);
		goto out_unregister_blk;
	}
	err = ibnbd_clt_create_sysfs_files();
	if (err) {
		pr_err("Failed to load module,"
		       " creating sysfs device files failed, err: %d\n",
		       err);
		goto out_unregister;
	}

	return 0;

out_unregister:
	ibtrs_clt_unregister(&ops);
out_unregister_blk:
	unregister_blkdev(ibnbd_client_major, "ibnbd");
out:
	return err;
}

static void __exit ibnbd_client_exit(void)
{
	pr_info("Unloading module\n");
	ibnbd_clt_destroy_default_group();
	flush_scheduled_work();
	ibnbd_destroy_sessions();
	wait_event(sess_list_waitq, list_empty(&session_list));
	ibnbd_clt_destroy_sysfs_files();
	ibtrs_clt_unregister(&ops);
	unregister_blkdev(ibnbd_client_major, "ibnbd");
	idr_destroy(&g_index_idr);
	pr_info("Module unloaded\n");
}

module_init(ibnbd_client_init);
module_exit(ibnbd_client_exit);
