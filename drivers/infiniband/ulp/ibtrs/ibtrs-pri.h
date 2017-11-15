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
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions, and the following disclaimer,
 *    without modification.
 * 2. Redistributions in binary form must reproduce at minimum a disclaimer
 *    substantially similar to the "NO WARRANTY" disclaimer below
 *    ("Disclaimer") and any redistribution must be conditioned upon
 *    including a substantially similar Disclaimer requirement for further
 *    binary redistribution.
 * 3. Neither the names of the above-listed copyright holders nor the names
 *    of any contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * Alternatively, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") version 2 as published by the Free
 * Software Foundation.
 *
 * NO WARRANTY
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDERS OR CONTRIBUTORS BE LIABLE FOR SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGES.
 */

#ifndef IBTRS_PRI_H
#define IBTRS_PRI_H

#include <linux/uio.h>
#include <linux/types.h>
#include <linux/uuid.h>
#include <rdma/rdma_cm.h>
#include <rdma/ib_cm.h>
#include <linux/list.h>
#include <linux/dma-direction.h>
#include <rdma/ib.h>
#include <rdma/ib_verbs.h>
#include <linux/time.h>
#include <linux/ktime.h>
#include <linux/timekeeping.h>

#define IBTRS_VER_MAJOR 1
#define IBTRS_VER_MINOR 0
#define IBTRS_VER_STRING __stringify(IBTRS_VER_MAJOR) "." \
			 __stringify(IBTRS_VER_MINOR)

enum {
	USRTX_CNT = 64,
	USR_CON_BUF_SIZE = USRTX_CNT * 2, /* double bufs for ACK's */

	MIN_RTR_CNT = 1,
	MAX_RTR_CNT = 7,

	MAX_PATHS_NUM = 1,

	/*
	 * With the current size of the tag allocated on the client, 4K
	 * is the maximum number of tags we can allocate.  This number is
	 * also used on the client to allocate the IU for the user connection
	 * to receive the RDMA addresses from the server.
	 */
	MAX_SESS_QUEUE_DEPTH = 4096,

	IO_MSG_SIZE = 24,
	IB_IMM_SIZE_BITS = 32,

	IBTRS_ACK_IMM = UINT_MAX,
	IBTRS_HB_IMM  = UINT_MAX - 1,

	IBTRS_HB_TIMEOUT_MS = 5000,

	IBTRS_MAGIC = 0x1BBD,
	IBTRS_VERSION = (IBTRS_VER_MAJOR << 8) | IBTRS_VER_MINOR,
};

struct ibtrs_ib_dev {
	struct list_head	entry;
	struct kref		ref;
	struct ib_pd		*pd;
	struct ib_device	*dev;
	struct ib_device_attr	attrs;
	u32			lkey;
	u32			rkey;
};

struct ibtrs_con {
	struct ibtrs_sess	*sess;
	struct ib_qp		*qp;
	struct ib_cq		*cq;
	struct rdma_cm_id	*cm_id;
	unsigned		cid;
};

typedef void (ibtrs_hb_handler_t)(struct ibtrs_con *con, int err);

struct ibtrs_sess {
	struct sockaddr_storage dst_addr;
	struct sockaddr_storage src_addr;
	char			sessname[NAME_MAX];
	uuid_t			uuid;
	struct ibtrs_con	**con;
	unsigned int		con_num;
	unsigned int		recon_cnt;
	struct ibtrs_ib_dev	*ib_dev;
	int			ib_dev_ref;
	struct ibtrs_iu         **usrrx_ring;
	bool			usrtx_freed;
	spinlock_t		usrtx_lock;
	struct completion	usrtx_comp;
	atomic_t		usrtx_cnt;
	struct list_head	usrtx_iu_list;
	struct ibtrs_con	*hb_con;
	struct ib_cqe		*hb_cqe;
	ibtrs_hb_handler_t	*hb_err_handler;
	struct delayed_work	hb_dwork;
	unsigned		hb_timeout_ms;
};

struct ibtrs_iu {
	struct list_head        list;
	struct ib_cqe           cqe;
	dma_addr_t              dma_addr;
	void                    *buf;
	size_t                  size;
	enum dma_data_direction direction;
	u32			tag;
};

/**
 * enum ibtrs_msg_types - IBTRS message types.
 * @IBTRS_MSG_INFO_REQ:		Client additional info request to the server
 * @IBTRS_MSG_INFO_RSP:		Server additional info response to the client
 * @IBTRS_MSG_RDMA_WRITE:	Client writes data per RDMA to Server
 * @IBTRS_MSG_REQ_RDMA_WRITE:	Client requests data transfer per RDMA
 * @IBTRS_MSG_USER:		Data transfer per Infiniband message
 */
enum ibtrs_msg_types {
	IBTRS_MSG_INFO_REQ,
	IBTRS_MSG_INFO_RSP,
	IBTRS_MSG_RDMA_WRITE,
	IBTRS_MSG_REQ_RDMA_WRITE,
	IBTRS_MSG_USER,
};

/**
 * struct ibtrs_msg_conn_req - Client connection request to the server
 * @magic:	   IBTRS magic
 * @version:	   IBTRS protocol version
 * @cid:	   Current connection id
 * @cid_num:	   Number of connections per session
 * @recon_cnt:	   Reconnections counter
 * @uuid:	   Client UUID
 *
 * NOTE: max size 56 bytes, see man rdma_connect().
 */
struct ibtrs_msg_conn_req {
	u8		__cma_version; /* Is set to 0 by cma.c in case of
					* AF_IB, do not touch that. */
	u8		__ip_version;  /* On sender side that should be
					* set to 0, or cma_save_ip_info()
					* extract garbage and will fail. */
	__le16		magic;
	__le16		version;
	__le16		cid;
	__le16		cid_num;
	__le16		recon_cnt;
	uuid_t		uuid;
	u8		reserved[28];
};

/**
 * struct ibtrs_msg_conn_rsp - Server connection response to the client
 * @magic:	   IBTRS magic
 * @version:	   IBTRS protocol version
 * @errno:	   If rdma_accept() then 0, if rdma_reject() indicates error
 * @queue_depth:   max inflight messages (queue-depth) in this session
 * @rkey:	   remote key to allow client to access buffers
 * @max_io_size:   max io size server supports
 * @max_req_size:  max infiniband message size server supports
 * @uuid:	   Server UUID
 *
 * NOTE: size is 56 bytes, max possible is 136 bytes, see man rdma_accept().
 */
struct ibtrs_msg_conn_rsp {
	__le16		magic;
	__le16		version;
	__le16		errno;
	__le16		queue_depth;
	__le32		rkey;
	__le32		max_io_size;
	__le32		max_req_size;
	uuid_t		uuid;
	u8		reserved[20];
};

/**
 * struct ibtrs_msg_info_req
 * @type:		@IBTRS_MSG_INFO_REQ
 * @sessname:		Session name chosen by client
 */
struct ibtrs_msg_info_req {
	__le16		type;
	u8		sessname[NAME_MAX];
	u8		reserved[15];
};

/**
 * struct ibtrs_msg_info_rsp
 * @type:		@IBTRS_MSG_INFO_RSP
 * @addr_num:		Number of rdma addresses
 * @addr:		RDMA addresses of buffers
 */
struct ibtrs_msg_info_rsp {
	__le16		type;
	__le16		addr_num;
	u8		reserved[4];
	__le64		addr[];
};

/*
 *  Data Layout in RDMA-Bufs:
 *
 * +---------RDMA-BUF--------+
 * |         Slice N	     |
 * | +---------------------+ |
 * | |      I/O data       | |
 * | |---------------------| |
 * | |      IBNBD MSG	   | |
 * | |---------------------| |
 * | |	    IBTRS MSG	   | |
 * | +---------------------+ |
 * +-------------------------+
 * |	     Slice N+1	     |
 * | +---------------------+ |
 * | |       I/O data	   | |
 * | |---------------------| |
 * | |	     IBNBD MSG     | |
 * | |---------------------| |
 * | |       IBTRS MSG     | |
 * | +---------------------+ |
 * +-------------------------+
 */

/**
 * struct ibtrs_msg_user - Data exchanged a Infiniband message
 * @type:		@IBTRS_MSG_USER
 * @psize:		Payload size
 * @payl:		Payload data
 */
struct ibtrs_msg_user {
	__le16			type;
	__le16			psize;
	u8			payl[];
};

/**
 * struct ibtrs_sg_desc - RDMA-Buffer entry description
 * @addr:	Address of RDMA destination buffer
 * @key:	Authorization rkey to write to the buffer
 * @len:	Size of the buffer
 */
struct ibtrs_sg_desc {
	__le64			addr;
	__le32			key;
	__le32			len;
};

/**
 * struct ibtrs_msg_req_rdma_write - RDMA data transfer request from client
 * @hdr:		message header
 * @sg_cnt:		number of @desc entries
 * @desc:		RDMA bufferst where the server can write the result to
 */
struct ibtrs_msg_req_rdma_write {
	__le16			type;
	__le16			__padding;
	__le32			sg_cnt;
	struct ibtrs_sg_desc    desc[];
};

/**
 * struct_msg_rdma_write - Message transferred to server with RDMA-Write
 */
struct ibtrs_msg_rdma_write {
	__le16			type;
};

/* ibtrs-iu.c */

struct ibtrs_iu *ibtrs_iu_alloc(u32 tag, size_t size, gfp_t t,
				struct ib_device *dev, enum dma_data_direction,
				void (*done)(struct ib_cq *cq, struct ib_wc *wc));
void ibtrs_iu_free(struct ibtrs_iu *iu, enum dma_data_direction dir,
		   struct ib_device *dev);

void ibtrs_iu_usrtx_init_list(struct ibtrs_sess *sess);
int ibtrs_iu_usrtx_alloc_list(struct ibtrs_sess *sess, unsigned max_req_size,
			      void (*done)(struct ib_cq *cq, struct ib_wc *wc));
void ibtrs_iu_usrtx_free_list(struct ibtrs_sess *sess);
struct ibtrs_iu *ibtrs_iu_usrtx_get(struct ibtrs_sess *sess);
void ibtrs_iu_usrtx_return(struct ibtrs_sess *sess, struct ibtrs_iu *iu);
void ibtrs_iu_usrtx_put(struct ibtrs_sess *sess);

void ibtrs_iu_usrrx_init_list(struct ibtrs_sess *sess);
int ibtrs_iu_usrrx_alloc_list(struct ibtrs_sess *sess, size_t max_req_size,
			      void (*done)(struct ib_cq *cq, struct ib_wc *wc));
void ibtrs_iu_usrrx_free_list(struct ibtrs_sess *sess);

/* ibtrs.c */

int ibtrs_iu_post_recv(struct ibtrs_con *con, struct ibtrs_iu *iu);
int ibtrs_iu_post_send(struct ibtrs_con *con, struct ibtrs_iu *iu, size_t size);
int ibtrs_iu_post_rdma_write_imm(struct ibtrs_con *con, struct ibtrs_iu *iu,
				 struct ib_sge *sge, unsigned int num_sge,
				 u32 rkey, u64 rdma_addr, u32 imm_data,
				 enum ib_send_flags flags);

int ibtrs_post_recv_empty(struct ibtrs_con *con, struct ib_cqe *cqe);
int ibtrs_post_rdma_write_imm_empty(struct ibtrs_con *con, struct ib_cqe *cqe,
				    u32 imm_data, enum ib_send_flags flags);

struct ibtrs_ib_dev *ibtrs_ib_dev_find_get(struct rdma_cm_id *cm_id);
void ibtrs_ib_dev_put(struct ibtrs_ib_dev *dev);

int ibtrs_cq_qp_create(struct ibtrs_sess *ibtrs_sess, struct ibtrs_con *con,
		       u32 max_send_sge, int cq_vector, u16 cq_size,
		       u16 wr_queue_size, enum ib_poll_context poll_ctx);
void ibtrs_cq_qp_destroy(struct ibtrs_con *con);

void ibtrs_start_hb(struct ibtrs_con *con, struct ib_cqe *cqe,
		    unsigned timeout_ms, ibtrs_hb_handler_t *err_handler);
void ibtrs_stop_hb(struct ibtrs_sess *sess);

#define XX(a) case (a): return #a
static inline const char *ib_wc_opcode_str(enum ib_wc_opcode opcode)
{
	switch (opcode) {
	XX(IB_WC_SEND);
	XX(IB_WC_RDMA_WRITE);
	XX(IB_WC_RDMA_READ);
	XX(IB_WC_COMP_SWAP);
	XX(IB_WC_FETCH_ADD);
	/* recv-side); inbound completion */
	XX(IB_WC_RECV);
	XX(IB_WC_RECV_RDMA_WITH_IMM);
	default: return "IB_WC_OPCODE_UNKNOWN";
	}
}

static inline void sockaddr_to_str(const struct sockaddr *addr,
				   char *buf, size_t len)
{
	switch (addr->sa_family) {
	case AF_IB:
		scnprintf(buf, len, "gid:%pI6",
			  &((struct sockaddr_ib *)addr)->sib_addr.sib_raw);
		return;
	case AF_INET:
		scnprintf(buf, len, "ip:%pI4",
			  &((struct sockaddr_in *)addr)->sin_addr);
		return;
	case AF_INET6:
		scnprintf(buf, len, "ip:%pI6c",
			  &((struct sockaddr_in6 *)addr)->sin6_addr);
		return;
	}
	scnprintf(buf, len, "<invalid address family>");
	pr_err("Invalid address family\n");
}

/**
 * kvec_length() - Total number of bytes covered by an kvec.
 */
static inline size_t kvec_length(const struct kvec *vec, size_t nr)
{
	size_t seg, ret = 0;

	for (seg = 0; seg < nr; seg++)
		ret += vec[seg].iov_len;
	return ret;
}

/**
 * copy_from_kvec() - Copy kvec to the buffer.
 */
static inline void copy_from_kvec(void *data, const struct kvec *vec,
				  size_t copy)
{
	size_t seg, len;

	for (seg = 0; copy; seg++) {
		len = min(vec[seg].iov_len, copy);
		memcpy(data, vec[seg].iov_base, len);
		data += len;
		copy -= len;
	}
}

#define STAT_STORE_FUNC(type, store, reset)				\
static ssize_t store##_store(struct kobject *kobj,			\
			     struct kobj_attribute *attr,		\
			     const char *buf, size_t count)		\
{									\
	int ret = -EINVAL;						\
	type *sess = container_of(kobj, type, kobj_stats);		\
									\
	if (sysfs_streq(buf, "1"))					\
		ret = reset(&sess->stats, true);			\
	else if (sysfs_streq(buf, "0"))					\
		ret = reset(&sess->stats, false);			\
	if (ret)							\
		return ret;						\
									\
	return count;							\
}

#define STAT_SHOW_FUNC(type, show, print)				\
static ssize_t show##_show(struct kobject *kobj,			\
			   struct kobj_attribute *attr,			\
			   char *page)					\
{									\
	type *sess = container_of(kobj, type, kobj_stats);		\
									\
	return print(&sess->stats, page, PAGE_SIZE);			\
}

#define STAT_ATTR(type, stat, print, reset)				\
STAT_STORE_FUNC(type, stat, reset)					\
STAT_SHOW_FUNC(type, stat, print)					\
static struct kobj_attribute stat##_attr =				\
		__ATTR(stat, 0644,					\
		       stat##_show,					\
		       stat##_store)

#endif /* IBTRS_PRI_H */
