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

#ifndef IBTRS_PRI_H
#define IBTRS_PRI_H

#include <linux/uuid.h>
#include <rdma/rdma_cm.h>
#include <rdma/ib_verbs.h>
#include <rdma/ib.h>

#include "ibtrs.h"

#define IBTRS_VER_MAJOR 1
#define IBTRS_VER_MINOR 0
#define IBTRS_VER_STRING __stringify(IBTRS_VER_MAJOR) "." \
			 __stringify(IBTRS_VER_MINOR)

enum ibtrs_imm_consts {
	MAX_IMM_TYPE_BITS = 4,
	MAX_IMM_TYPE_MASK = ((1 << MAX_IMM_TYPE_BITS) - 1),
	MAX_IMM_PAYL_BITS = 28,
	MAX_IMM_PAYL_MASK = ((1 << MAX_IMM_PAYL_BITS) - 1),

	IBTRS_IO_REQ_IMM = 0, /* client to server */
	IBTRS_IO_RSP_IMM = 1, /* server to client */
	IBTRS_HB_MSG_IMM = 2,
	IBTRS_HB_ACK_IMM = 3,
};

enum {
	SERVICE_CON_QUEUE_DEPTH = 512,

	MIN_RTR_CNT = 1,
	MAX_RTR_CNT = 7,

	MAX_PATHS_NUM = 128,

	/*
	 * With the current size of the tag allocated on the client, 4K
	 * is the maximum number of tags we can allocate.  This number is
	 * also used on the client to allocate the IU for the user connection
	 * to receive the RDMA addresses from the server.
	 */
	MAX_SESS_QUEUE_DEPTH = 4096,
	/*
	 * Size of user message atached to a request (@vec, @nr) is limited
	 * by the IO_MSG_SIZE. max_req_size allocated by the server should
	 * cover both: the user message and the ibtrs message attached
	 * to an IO. ibtrs_msg_req_rdma_write attached to a read has variable
	 * size: max number of descriptors we can send is limited by
	 * max_desc = (max_req_size - IO_MSG_SIZE) / sizeof(desc)
	 */
	IO_MSG_SIZE = 512,

	IBTRS_HB_INTERVAL_MS = 5000,
	IBTRS_HB_MISSED_MAX = 5,

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
	struct list_head	entry;
	struct sockaddr_storage dst_addr;
	struct sockaddr_storage src_addr;
	char			sessname[NAME_MAX];
	uuid_t			uuid;
	struct ibtrs_con	**con;
	unsigned int		con_num;
	unsigned int		recon_cnt;
	struct ibtrs_ib_dev	*ib_dev;
	int			ib_dev_ref;
	struct ib_cqe		*hb_cqe;
	ibtrs_hb_handler_t	*hb_err_handler;
	struct workqueue_struct *hb_wq;
	struct delayed_work	hb_dwork;
	unsigned		hb_interval_ms;
	unsigned		hb_missed_cnt;
	unsigned		hb_missed_max;
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
 * @IBTRS_MSG_WRITE:		Client writes data per RDMA to server
 * @IBTRS_MSG_READ:		Client requests data transfer from server
 * @IBTRS_MSG_USER:		Data transfer per Infiniband message
 */
enum ibtrs_msg_types {
	IBTRS_MSG_INFO_REQ,
	IBTRS_MSG_INFO_RSP,
	IBTRS_MSG_WRITE,
	IBTRS_MSG_READ,
	IBTRS_MSG_USER,
};

/**
 * struct ibtrs_msg_conn_req - Client connection request to the server
 * @magic:	   IBTRS magic
 * @version:	   IBTRS protocol version
 * @cid:	   Current connection id
 * @cid_num:	   Number of connections per session
 * @recon_cnt:	   Reconnections counter
 * @sess_uuid:	   UUID of a session (path)
 * @paths_uuid:	   UUID of a group of sessions (paths)
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
	uuid_t		sess_uuid;
	uuid_t		paths_uuid;
	u8		reserved[12];
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
 * struct ibtrs_msg_rdma_read - RDMA data transfer request from client
 * @type:		always @IBTRS_MSG_READ
 * @usr_len:		length of user payload
 * @sg_cnt:		number of @desc entries
 * @desc:		RDMA bufferst where the server can write the result to
 */
struct ibtrs_msg_rdma_read {
	__le16			type;
	__le16			usr_len;
	__le32			sg_cnt;
	struct ibtrs_sg_desc    desc[];
};

/**
 * struct_msg_rdma_write - Message transferred to server with RDMA-Write
 * @type:		always @IBTRS_MSG_WRITE
 * @usr_len:		length of user payload
 */
struct ibtrs_msg_rdma_write {
	__le16			type;
	__le16			usr_len;
};

/* ibtrs.c */

struct ibtrs_iu *ibtrs_iu_alloc(u32 tag, size_t size, gfp_t t,
				struct ib_device *dev, enum dma_data_direction,
				void (*done)(struct ib_cq *cq, struct ib_wc *wc));
void ibtrs_iu_free(struct ibtrs_iu *iu, enum dma_data_direction dir,
		   struct ib_device *dev);
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

void ibtrs_init_hb(struct ibtrs_sess *sess, struct ib_cqe *cqe,
		   unsigned interval_ms, unsigned missed_max,
		   ibtrs_hb_handler_t *err_handler,
		   struct workqueue_struct *wq);
void ibtrs_start_hb(struct ibtrs_sess *sess);
void ibtrs_stop_hb(struct ibtrs_sess *sess);
void ibtrs_send_hb_ack(struct ibtrs_sess *sess);

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

static inline int sockaddr_cmp(const struct sockaddr *a,
			       const struct sockaddr *b)
{
	switch (a->sa_family) {
	case AF_IB:
		return memcmp(&((struct sockaddr_ib *)a)->sib_addr,
			      &((struct sockaddr_ib *)b)->sib_addr,
			      sizeof(struct ib_addr));
	case AF_INET:
		return memcmp(&((struct sockaddr_in *)a)->sin_addr,
			      &((struct sockaddr_in *)b)->sin_addr,
			      sizeof(struct in_addr));
	case AF_INET6:
		return memcmp(&((struct sockaddr_in6 *)a)->sin6_addr,
			      &((struct sockaddr_in6 *)b)->sin6_addr,
			      sizeof(struct in6_addr));
	default:
		return -ENOENT;
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

static inline u32 ibtrs_to_imm(u32 type, u32 payload)
{
	BUILD_BUG_ON(32 != MAX_IMM_PAYL_BITS + MAX_IMM_TYPE_BITS);
	return ((type & MAX_IMM_TYPE_MASK) << MAX_IMM_PAYL_BITS) |
		(payload & MAX_IMM_PAYL_MASK);
}

static inline void ibtrs_from_imm(u32 imm, u32 *type, u32 *payload)
{
	*payload = (imm & MAX_IMM_PAYL_MASK);
	*type = (imm >> MAX_IMM_PAYL_BITS);
}

static inline u32 ibtrs_to_io_req_imm(u32 addr)
{
	return ibtrs_to_imm(IBTRS_IO_REQ_IMM, addr);
}

static inline u32 ibtrs_to_io_rsp_imm(u32 msg_id, int errno)
{
	u32 payload;

	/* 9 bits for errno, 19 bits for msg_id */
	payload = (abs(errno) & 0x1ff) << 19 | (msg_id & 0x7ffff);
	return ibtrs_to_imm(IBTRS_IO_RSP_IMM, payload);
}

static inline void ibtrs_from_io_rsp_imm(u32 payload, u32 *msg_id, int *errno)
{
	/* 9 bits for errno, 19 bits for msg_id */
	*msg_id = (payload & 0x7ffff);
	*errno = -(int)((payload >> 19) & 0x1ff);
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
