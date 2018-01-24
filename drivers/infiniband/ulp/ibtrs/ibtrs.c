/*
 * InfiniBand Transport Layer
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

#include <linux/module.h>
#include <linux/inet.h>

#include "ibtrs-pri.h"
#include "ibtrs-log.h"

MODULE_AUTHOR("ibnbd@profitbricks.com");
MODULE_DESCRIPTION("IBTRS Core");
MODULE_VERSION(IBTRS_VER_STRING);
MODULE_LICENSE("GPL");

static LIST_HEAD(device_list);
static DEFINE_MUTEX(device_list_mutex);

struct ibtrs_iu *ibtrs_iu_alloc(u32 tag, size_t size, gfp_t gfp_mask,
				struct ib_device *dma_dev,
				enum dma_data_direction direction,
				void (*done)(struct ib_cq *cq,
					     struct ib_wc *wc))
{
	struct ibtrs_iu *iu;

	iu = kmalloc(sizeof(*iu), gfp_mask);
	if (unlikely(!iu))
		return NULL;

	iu->buf = kzalloc(size, gfp_mask);
	if (unlikely(!iu->buf))
		goto err1;

	iu->dma_addr = ib_dma_map_single(dma_dev, iu->buf, size, direction);
	if (unlikely(ib_dma_mapping_error(dma_dev, iu->dma_addr)))
		goto err2;

	iu->cqe.done  = done;
	iu->size      = size;
	iu->direction = direction;
	iu->tag       = tag;

	return iu;

err2:
	kfree(iu->buf);
err1:
	kfree(iu);

	return NULL;
}
EXPORT_SYMBOL_GPL(ibtrs_iu_alloc);

void ibtrs_iu_free(struct ibtrs_iu *iu, enum dma_data_direction dir,
		   struct ib_device *ibdev)
{
	if (!iu)
		return;

	ib_dma_unmap_single(ibdev, iu->dma_addr, iu->size, dir);
	kfree(iu->buf);
	kfree(iu);
}
EXPORT_SYMBOL_GPL(ibtrs_iu_free);

int ibtrs_iu_post_recv(struct ibtrs_con *con, struct ibtrs_iu *iu)
{
	struct ibtrs_sess *sess = con->sess;
	struct ib_recv_wr wr, *bad_wr;
	struct ib_sge list;

	list.addr   = iu->dma_addr;
	list.length = iu->size;
	list.lkey   = sess->ib_dev->lkey;

	if (WARN_ON(list.length == 0)) {
		ibtrs_wrn(con, "Posting receive work request failed,"
			  " sg list is empty\n");
		return -EINVAL;
	}

	wr.next    = NULL;
	wr.wr_cqe  = &iu->cqe;
	wr.sg_list = &list;
	wr.num_sge = 1;

	return ib_post_recv(con->qp, &wr, &bad_wr);
}
EXPORT_SYMBOL_GPL(ibtrs_iu_post_recv);

int ibtrs_post_recv_empty(struct ibtrs_con *con, struct ib_cqe *cqe)
{
	struct ib_recv_wr wr, *bad_wr;

	wr.next    = NULL;
	wr.wr_cqe  = cqe;
	wr.sg_list = NULL;
	wr.num_sge = 0;

	return ib_post_recv(con->qp, &wr, &bad_wr);
}
EXPORT_SYMBOL_GPL(ibtrs_post_recv_empty);

int ibtrs_iu_post_send(struct ibtrs_con *con, struct ibtrs_iu *iu, size_t size)
{
	struct ibtrs_sess *sess = con->sess;
	struct ib_send_wr wr, *bad_wr;
	struct ib_sge list;

	if ((WARN_ON(size == 0)))
		return -EINVAL;

	list.addr   = iu->dma_addr;
	list.length = size;
	list.lkey   = sess->ib_dev->lkey;

	memset(&wr, 0, sizeof(wr));
	wr.next       = NULL;
	wr.wr_cqe     = &iu->cqe;
	wr.sg_list    = &list;
	wr.num_sge    = 1;
	wr.opcode     = IB_WR_SEND;
	wr.send_flags = IB_SEND_SIGNALED;

	return ib_post_send(con->qp, &wr, &bad_wr);
}
EXPORT_SYMBOL_GPL(ibtrs_iu_post_send);

int ibtrs_iu_post_rdma_write_imm(struct ibtrs_con *con, struct ibtrs_iu *iu,
				 struct ib_sge *sge, unsigned int num_sge,
				 u32 rkey, u64 rdma_addr, u32 imm_data,
				 enum ib_send_flags flags)
{
	struct ib_send_wr *bad_wr;
	struct ib_rdma_wr wr;
	int i;

	wr.wr.next	  = NULL;
	wr.wr.wr_cqe	  = &iu->cqe;
	wr.wr.sg_list	  = sge;
	wr.wr.num_sge	  = num_sge;
	wr.rkey		  = rkey;
	wr.remote_addr	  = rdma_addr;
	wr.wr.opcode	  = IB_WR_RDMA_WRITE_WITH_IMM;
	wr.wr.ex.imm_data = cpu_to_be32(imm_data);
	wr.wr.send_flags  = flags;

	/*
	 * If one of the sges has 0 size, the operation will fail with an
	 * length error
	 */
	for (i = 0; i < num_sge; i++)
		if (WARN_ON(sge[i].length == 0))
			return -EINVAL;

	return ib_post_send(con->qp, &wr.wr, &bad_wr);
}
EXPORT_SYMBOL_GPL(ibtrs_iu_post_rdma_write_imm);

int ibtrs_post_rdma_write_imm_empty(struct ibtrs_con *con, struct ib_cqe *cqe,
				    u32 imm_data, enum ib_send_flags flags)
{
	struct ib_send_wr wr, *bad_wr;

	memset(&wr, 0, sizeof(wr));
	wr.wr_cqe	= cqe;
	wr.send_flags	= flags;
	wr.opcode	= IB_WR_RDMA_WRITE_WITH_IMM;
	wr.ex.imm_data	= cpu_to_be32(imm_data);

	return ib_post_send(con->qp, &wr, &bad_wr);
}
EXPORT_SYMBOL_GPL(ibtrs_post_rdma_write_imm_empty);

static void qp_event_handler(struct ib_event *ev, void *ctx)
{
	struct ibtrs_con *con = ctx;

	switch (ev->event) {
	case IB_EVENT_COMM_EST:
		ibtrs_info(con, "QP event %s (%d) received\n",
			   ib_event_msg(ev->event), ev->event);
		rdma_notify(con->cm_id, IB_EVENT_COMM_EST);
		break;
	default:
		ibtrs_info(con, "Unhandled QP event %s (%d) received\n",
			   ib_event_msg(ev->event), ev->event);
		break;
	}
}

static int ibtrs_query_device(struct ibtrs_ib_dev *ib_dev)
{
	struct ib_udata uhw = {.outlen = 0, .inlen = 0};

	memset(&ib_dev->attrs, 0, sizeof(ib_dev->attrs));

	return ib_dev->dev->query_device(ib_dev->dev, &ib_dev->attrs, &uhw);
}

static int ibtrs_ib_dev_init(struct ibtrs_ib_dev *d, struct ib_device *dev)
{
	int err;

	d->pd = ib_alloc_pd(dev, IB_PD_UNSAFE_GLOBAL_RKEY);
	if (IS_ERR(d->pd))
		return PTR_ERR(d->pd);
	d->dev = dev;
	d->lkey = d->pd->local_dma_lkey;
	d->rkey = d->pd->unsafe_global_rkey;

	err = ibtrs_query_device(d);
	if (unlikely(err))
		ib_dealloc_pd(d->pd);

	return err;
}

static void ibtrs_ib_dev_destroy(struct ibtrs_ib_dev *d)
{
	if (d->pd) {
		ib_dealloc_pd(d->pd);
		d->pd = NULL;
		d->dev = NULL;
		d->lkey = 0;
		d->rkey = 0;
	}
}

struct ibtrs_ib_dev *ibtrs_ib_dev_find_get(struct rdma_cm_id *cm_id)
{
	struct ibtrs_ib_dev *dev;
	int err;

	mutex_lock(&device_list_mutex);
	list_for_each_entry(dev, &device_list, entry) {
		if (dev->dev->node_guid == cm_id->device->node_guid &&
		    kref_get_unless_zero(&dev->ref))
			goto out_unlock;
	}
	dev = kzalloc(sizeof(*dev), GFP_KERNEL);
	if (unlikely(!dev))
		goto out_err;

	kref_init(&dev->ref);
	err = ibtrs_ib_dev_init(dev, cm_id->device);
	if (unlikely(err))
		goto out_free;
	list_add(&dev->entry, &device_list);
out_unlock:
	mutex_unlock(&device_list_mutex);

	return dev;

out_free:
	kfree(dev);
out_err:
	mutex_unlock(&device_list_mutex);

	return NULL;
}
EXPORT_SYMBOL_GPL(ibtrs_ib_dev_find_get);

static void ibtrs_ib_dev_free(struct kref *ref)
{
	struct ibtrs_ib_dev *dev;

	dev = container_of(ref, struct ibtrs_ib_dev, ref);

	mutex_lock(&device_list_mutex);
	list_del(&dev->entry);
	mutex_unlock(&device_list_mutex);
	ibtrs_ib_dev_destroy(dev);
	kfree(dev);
}

void ibtrs_ib_dev_put(struct ibtrs_ib_dev *dev)
{
	kref_put(&dev->ref, ibtrs_ib_dev_free);
}
EXPORT_SYMBOL_GPL(ibtrs_ib_dev_put);

static int create_cq(struct ibtrs_con *con, int cq_vector, u16 cq_size,
		     enum ib_poll_context poll_ctx)
{
	struct rdma_cm_id *cm_id = con->cm_id;
	struct ib_cq *cq;

	cq = ib_alloc_cq(cm_id->device, con, cq_size * 2 + 1,
			 cq_vector, poll_ctx);
	if (unlikely(IS_ERR(cq))) {
		ibtrs_err(con, "Creating completion queue failed, errno: %ld\n",
			  PTR_ERR(cq));
		return PTR_ERR(cq);
	}
	con->cq = cq;

	return 0;
}

static int create_qp(struct ibtrs_con *con, struct ib_pd *pd,
		     u16 wr_queue_size, u32 max_send_sge)
{
	struct ib_qp_init_attr init_attr = {NULL};
	struct rdma_cm_id *cm_id = con->cm_id;
	int ret;

	init_attr.cap.max_send_wr = wr_queue_size;
	init_attr.cap.max_recv_wr = wr_queue_size;
	init_attr.cap.max_recv_sge = 2;
	init_attr.event_handler = qp_event_handler;
	init_attr.qp_context = con;
	init_attr.cap.max_send_sge = max_send_sge;

	init_attr.qp_type = IB_QPT_RC;
	init_attr.send_cq = con->cq;
	init_attr.recv_cq = con->cq;
	init_attr.sq_sig_type = IB_SIGNAL_REQ_WR;

	ret = rdma_create_qp(cm_id, pd, &init_attr);
	if (unlikely(ret)) {
		ibtrs_err(con, "Creating QP failed, err: %d\n", ret);
		return ret;
	}
	con->qp = cm_id->qp;

	return ret;
}

int ibtrs_cq_qp_create(struct ibtrs_sess *sess, struct ibtrs_con *con,
		       u32 max_send_sge, int cq_vector, u16 cq_size,
		       u16 wr_queue_size, enum ib_poll_context poll_ctx)
{
	int err;

	err = create_cq(con, cq_vector, cq_size, poll_ctx);
	if (unlikely(err))
		return err;

	err = create_qp(con, sess->ib_dev->pd, wr_queue_size, max_send_sge);
	if (unlikely(err)) {
		ib_free_cq(con->cq);
		con->cq = NULL;
		return err;
	}
	con->sess = sess;

	return 0;
}
EXPORT_SYMBOL_GPL(ibtrs_cq_qp_create);

void ibtrs_cq_qp_destroy(struct ibtrs_con *con)
{
	if (con->qp) {
		rdma_destroy_qp(con->cm_id);
		con->qp = NULL;
	}
	if (con->cq) {
		ib_free_cq(con->cq);
		con->cq = NULL;
	}
}
EXPORT_SYMBOL_GPL(ibtrs_cq_qp_destroy);

static void schedule_hb(struct ibtrs_sess *sess)
{
	queue_delayed_work(sess->hb_wq, &sess->hb_dwork,
			   msecs_to_jiffies(sess->hb_interval_ms));
}

void ibtrs_send_hb_ack(struct ibtrs_sess *sess)
{
	struct ibtrs_con *usr_con = sess->con[0];
	u32 imm;
	int err;

	imm = ibtrs_to_imm(IBTRS_HB_ACK_IMM, 0);
	err = ibtrs_post_rdma_write_imm_empty(usr_con, sess->hb_cqe,
					      imm, IB_SEND_SIGNALED);
	if (unlikely(err)) {
		sess->hb_err_handler(usr_con, err);
		return;
	}
}
EXPORT_SYMBOL_GPL(ibtrs_send_hb_ack);

static void hb_work(struct work_struct *work)
{
	struct ibtrs_con *usr_con;
	struct ibtrs_sess *sess;
	u32 imm;
	int err;

	sess = container_of(to_delayed_work(work), typeof(*sess), hb_dwork);
	usr_con = sess->con[0];

	if (sess->hb_missed_cnt > sess->hb_missed_max) {
		sess->hb_err_handler(usr_con, -ETIMEDOUT);
		return;
	}
	if (sess->hb_missed_cnt++) {
		/* Reschedule work without sending hb */
		schedule_hb(sess);
		return;
	}
	imm = ibtrs_to_imm(IBTRS_HB_MSG_IMM, 0);
	err = ibtrs_post_rdma_write_imm_empty(usr_con, sess->hb_cqe,
					      imm, IB_SEND_SIGNALED);
	if (unlikely(err)) {
		sess->hb_err_handler(usr_con, err);
		return;
	}

	schedule_hb(sess);
}

void ibtrs_init_hb(struct ibtrs_sess *sess, struct ib_cqe *cqe,
		   unsigned int interval_ms, unsigned int missed_max,
		   ibtrs_hb_handler_t *err_handler,
		   struct workqueue_struct *wq)
{
	sess->hb_cqe = cqe;
	sess->hb_interval_ms = interval_ms;
	sess->hb_err_handler = err_handler;
	sess->hb_wq = wq;
	sess->hb_missed_max = missed_max;
	sess->hb_missed_cnt = 0;
	INIT_DELAYED_WORK(&sess->hb_dwork, hb_work);
}
EXPORT_SYMBOL_GPL(ibtrs_init_hb);

void ibtrs_start_hb(struct ibtrs_sess *sess)
{
	schedule_hb(sess);
}
EXPORT_SYMBOL_GPL(ibtrs_start_hb);

void ibtrs_stop_hb(struct ibtrs_sess *sess)
{
	cancel_delayed_work_sync(&sess->hb_dwork);
	sess->hb_missed_cnt = 0;
	sess->hb_missed_max = 0;
}
EXPORT_SYMBOL_GPL(ibtrs_stop_hb);

static int ibtrs_str_ipv4_to_sockaddr(const char *addr, size_t len,
				      short port, struct sockaddr *dst)
{
	struct sockaddr_in *dst_sin = (struct sockaddr_in *)dst;
	int ret;

	ret = in4_pton(addr, len, (u8 *)&dst_sin->sin_addr.s_addr,
		       '\0', NULL);
	if (ret == 0)
		return -EINVAL;

	dst_sin->sin_family = AF_INET;
	dst_sin->sin_port = htons(port);

	return 0;
}

static int ibtrs_str_ipv6_to_sockaddr(const char *addr, size_t len,
				      short port, struct sockaddr *dst)
{
	struct sockaddr_in6 *dst_sin6 = (struct sockaddr_in6 *)dst;
	int ret;

	ret = in6_pton(addr, len, dst_sin6->sin6_addr.s6_addr,
		       '\0', NULL);
	if (ret != 1)
		return -EINVAL;

	dst_sin6->sin6_family = AF_INET6;
	dst_sin6->sin6_port = htons(port);

	return 0;
}

static int ibtrs_str_gid_to_sockaddr(const char *addr, size_t len,
				     short port, struct sockaddr *dst)
{
	struct sockaddr_ib *dst_ib = (struct sockaddr_ib *)dst;
	int ret;

	/* We can use some of the I6 functions since GID is a valid
	 * IPv6 address format
	 */
	ret = in6_pton(addr, len, dst_ib->sib_addr.sib_raw, '\0', NULL);
	if (ret == 0)
		return -EINVAL;

	dst_ib->sib_family = AF_IB;
	/*
	 * Use the same TCP server port number as the IB service ID
	 * on the IB port space range
	 */
	dst_ib->sib_sid = cpu_to_be64(RDMA_IB_IP_PS_IB | port);
	dst_ib->sib_sid_mask = cpu_to_be64(0xffffffffffffffffULL);
	dst_ib->sib_pkey = cpu_to_be16(0xffff);

	return 0;
}

/**
 * ibtrs_str_to_sockaddr() - Convert ibtrs address string to sockaddr
 * @addr	String representation of an addr (IPv4, IPv6 or IB GID):
 *              - "ip:192.168.1.1"
 *              - "ip:fe80::200:5aee:feaa:20a2"
 *              - "gid:fe80::200:5aee:feaa:20a2"
 * @len         String address length
 * @port	Destination port
 * @dst		Destination sockaddr structure
 *
 * Returns 0 if conversion successful. Non-zero on error.
 */
static int ibtrs_str_to_sockaddr(const char *addr, size_t len,
				 short port, struct sockaddr *dst)
{
	if (strncmp(addr, "gid:", 4) == 0) {
		return ibtrs_str_gid_to_sockaddr(addr + 4, len - 4, port, dst);
	} else if (strncmp(addr, "ip:", 3) == 0) {
		if (ibtrs_str_ipv4_to_sockaddr(addr + 3, len - 3, port, dst))
			return ibtrs_str_ipv6_to_sockaddr(addr + 3, len - 3,
							  port, dst);
		else
			return 0;
	}
	return -EPROTONOSUPPORT;
}

int ibtrs_addr_to_sockaddr(const char *str, size_t len, short port,
			   struct ibtrs_addr *addr)
{
	const char *d;
	int ret;

	d = strchr(str, ',');
	if (d) {
		if (ibtrs_str_to_sockaddr(str, d - str, 0, addr->src))
			return -EINVAL;
		d += 1;
		len -= d - str;
		str  = d;

	} else {
		addr->src = NULL;
	}
	ret = ibtrs_str_to_sockaddr(str, len, port, addr->dst);

	return ret;
}
EXPORT_SYMBOL(ibtrs_addr_to_sockaddr);
