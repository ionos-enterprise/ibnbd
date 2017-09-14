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

#define USR_MSG_CNT 64
#define USR_CON_BUF_SIZE (USR_MSG_CNT * 2) /* double bufs for ACK's */

#define MIN_RTR_CNT 1
#define MAX_RTR_CNT 7

/*
 * With the current size of the tag allocated on the client, 4K is the maximum
 * number of tags we can allocate.  This number is also used on the client to
 * allocate the IU for the user connection to receive the RDMA addresses from
 * the server.
 */
#define MAX_SESS_QUEUE_DEPTH 4096

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

struct ibtrs_ib_dev {
	struct list_head	entry;
	struct kref		ref;
	struct ib_pd		*pd;
	struct ib_mr		*mr;
	struct ib_device	*dev;
};

struct ibtrs_addr {
	struct sockaddr_storage sockaddr;
	char	hostname[MAXHOSTNAMELEN];
};

struct ibtrs_sess {
	struct ibtrs_addr	addr;
	uuid_le			uuid;
	struct ibtrs_ib_dev	*ib_dev;
	struct ibtrs_iu         *dummy_rx_iu;
	struct ibtrs_iu         **usr_rx_ring;
	bool			usr_freed;
	spinlock_t		usr_lock;
	struct completion	usr_comp;
	atomic_t		usr_msg_cnt;
	struct list_head	usr_iu_list;
};

struct ibtrs_con {
	struct ibtrs_sess	*sess;
	struct ib_qp		*qp;
	struct ib_cq		*cq;
	struct rdma_cm_id	*cm_id;
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

#define IO_MSG_SIZE 24
#define IB_IMM_SIZE_BITS 32

#define IBTRS_ACK_IMM UINT_MAX

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

enum {
	IBTRS_MAGIC   = 0x1BBD,
	IBTRS_VER_1_0 = 0x0100,
};

#define IBTRS_CURRENT_VER IBTRS_VER_1_0

/**
 * struct ibtrs_msg_conn_req - Client connection request to the server
 * @magic:	   IBTRS magic
 * @version:	   IBTRS protocol version
 * @cid:	   Current connection id
 * @cid_num:	   Number of connections per session
 * @uuid:	   Client UUID
 *
 * NOTE: max size 56 bytes, see man rdma_connect().
 */
struct ibtrs_msg_conn_req {
	__le16		magic;
	__le16		version;
	__le16		cid;
	__le16		cid_num;
	u8		uuid[16];
	u8		reserved[32];
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
	u8		uuid[16];
	u8		reserved[20];
};

/**
 * struct ibtrs_msg_info_req
 * @type:		@IBTRS_MSG_INFO_REQ
 * @hostname:		Client host name
 */
struct ibtrs_msg_info_req {
	__le16		type;
	u8		hostname[MAXHOSTNAMELEN];
	u8		reserved[14];
};

/**
 * struct ibtrs_msg_info_rsp
 * @type:		@IBTRS_MSG_INFO_RSP
 * @addr_num:		Number of rdma addresses
 * @hostname:		Server host name
 * @addr:		RDMA addresses of buffers
 */
struct ibtrs_msg_info_rsp {
	__le16		type;
	__le16		addr_num;
	u8		hostname[MAXHOSTNAMELEN];
	u8		reserved[12];
	__le64		addr[];
};

/**
 * struct ibtrs_msg_hdr - Common header of all IBTRS messages
 * @type:	Message type, valid values see: enum ibtrs_msg_types
 * @tsize:	Total size of transferred data
 */
struct ibtrs_msg_hdr {
	u8			__padding1;
	u8			type;
	u16			__padding2;
	u32			tsize;
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
 * @hdr:		message header
 * @payl:		Payload from user user module
 */
struct ibtrs_msg_user {
	struct ibtrs_msg_hdr	hdr;
	u8			payl[];
};

/**
 * struct ibtrs_sg_desc - RDMA-Buffer entry description
 * @addr:	Address of RDMA destination buffer
 * @key:	Authorization rkey to write to the buffer
 * @len:	Size of the buffer
 */
struct ibtrs_sg_desc {
	u64			addr;
	u32			key;
	u32			len;
};

/**
 * struct ibtrs_msg_req_rdma_write - RDMA data transfer request from client
 * @hdr:		message header
 * @sg_cnt:		number of @desc entries
 * @desc:		RDMA bufferst where the server can write the result to
 */
struct ibtrs_msg_req_rdma_write {
	struct ibtrs_msg_hdr	hdr;
	u32			__padding;
	u32			sg_cnt;
	struct ibtrs_sg_desc    desc[];
};

/**
 * struct_msg_rdma_write - Message transferred to server with RDMA-Write
 * @hdr:		message header
 */
struct ibtrs_msg_rdma_write {
	struct ibtrs_msg_hdr	hdr;
};

/* ibtrs-proto.c */

/* XXX CHECK */
int ibtrs_validate_message(const struct ibtrs_msg_hdr *hdr);

/* ibtrs-iu.c */

int ibtrs_usr_msg_alloc_list(struct ibtrs_sess *sess, struct ibtrs_ib_dev *dev,
			     unsigned max_req_size);
void ibtrs_usr_msg_free_list(struct ibtrs_sess *sess, struct ibtrs_ib_dev *dev);
struct ibtrs_iu *ibtrs_usr_msg_get(struct ibtrs_sess *sess);
void ibtrs_usr_msg_return_iu(struct ibtrs_sess *sess, struct ibtrs_iu *iu);
void ibtrs_usr_msg_put(struct ibtrs_sess *sess);
struct ibtrs_iu *ibtrs_iu_alloc(u32 tag, size_t size, gfp_t t,
				struct ib_device *dev,
				enum dma_data_direction);
void ibtrs_iu_free(struct ibtrs_iu *iu, enum dma_data_direction dir,
		   struct ib_device *dev);
int ibtrs_iu_alloc_sess_rx_bufs(struct ibtrs_sess *sess, size_t max_req_size);
void ibtrs_iu_free_sess_rx_bufs(struct ibtrs_sess *sess);

/* ibtrs.c */

int ibtrs_post_send(struct ib_qp *qp, struct ib_mr *mr,
		    struct ibtrs_iu *iu, u32 size);

int ibtrs_post_rdma_write_imm(struct ib_qp *qp, struct ib_cqe *cqe,
			      struct ib_sge *sge, unsigned int num_sge,
			      u32 rkey, u64 rdma_addr, u32 imm_data,
			      enum ib_send_flags flags);

int ibtrs_post_rdma_write_imm_empty(struct ib_qp *qp, struct ib_cqe *cqe,
				    u32 imm_data, enum ib_send_flags flags);

struct ibtrs_ib_dev *ibtrs_ib_dev_find_get(struct rdma_cm_id *cm_id);
void ibtrs_ib_dev_put(struct ibtrs_ib_dev *dev);

int ibtrs_cq_qp_create(struct ibtrs_sess *ibtrs_sess, struct ibtrs_con *con,
		       struct rdma_cm_id *cm_id, u32 max_send_sge,
		       int cq_vector, u16 cq_size, u16 wr_queue_size,
		       struct ibtrs_ib_dev *ibdev,
		       enum ib_poll_context poll_ctx);
void ibtrs_cq_qp_destroy(struct ibtrs_con *con);

static inline void sockaddr_to_str(const struct sockaddr_storage *addr,
				   char *buf, size_t len)
{
	switch (addr->ss_family) {
	case AF_IB:
		scnprintf(buf, len, "gid:%pI6",
			  &((struct sockaddr_ib *)addr)->sib_addr.sib_raw);
		return;
	case AF_INET:
		scnprintf(buf, len, "ip:%pI4",
			  &((struct sockaddr_in *)addr)->sin_addr);
		return;
	case AF_INET6:
		/* workaround for ip4 client addr being set to INET6 family.
		 * This should fix it:
		 * yotamke@mellanox.com: [PATCH for-next] RDMA/CMA: Mark
		 * IPv4 addresses correctly when the listener is IPv6]
		 * http://permalink.gmane.org/gmane.linux.drivers.rdma/22395
		 *
		 * The first byte of ip6 address can't be 0. If it is, assume
		 * structure addr actually contains ip4 address.
		 */
		if (!((struct sockaddr_in6 *)addr)->sin6_addr.s6_addr[0]) {
			scnprintf(buf, len, "ip:%pI4",
				  &((struct sockaddr_in *)addr)->sin_addr);
			return;
		}
		/* end of workaround*/
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
		ret = reset(sess, true);				\
	else if (sysfs_streq(buf, "0"))					\
		ret = reset(sess, false);				\
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
	return print(sess, page, PAGE_SIZE);				\
}

#define STAT_ATTR(type, stat, print, reset)				\
STAT_STORE_FUNC(type, stat, reset)					\
STAT_SHOW_FUNC(type, stat, print)					\
static struct kobj_attribute stat##_attr =				\
		__ATTR(stat, 0644,					\
		       stat##_show,					\
		       stat##_store)

#endif /* IBTRS_PRI_H */
