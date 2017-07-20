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

#define WC_ARRAY_SIZE 16
#define IB_APM_TIMEOUT 16 /* 4.096 * 2 ^ 16 = 260 msec */

#define USR_MSG_CNT 64
#define USR_CON_BUF_SIZE (USR_MSG_CNT * 2) /* double bufs for ACK's */

#define DEFAULT_HEARTBEAT_TIMEOUT_MS 20000
#define MIN_HEARTBEAT_TIMEOUT_MS 5000
#define HEARTBEAT_INTV_MS 500
#define HEARTBEAT_INTV_JIFFIES msecs_to_jiffies(HEARTBEAT_INTV_MS)

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
	struct ib_pd		*pd;
	struct ib_mr		*mr;
	struct ib_device	*dev;
};

struct ibtrs_ib_path {
	union ib_gid    p_sgid;
	union ib_gid    p_dgid;
};

struct ibtrs_addr {
	struct sockaddr_storage sockaddr;
	char	hostname[MAXHOSTNAMELEN];
};

struct ibtrs_sess {
	struct list_head	list;
	struct ibtrs_addr	addr;
};

struct ibtrs_con {
	struct ibtrs_sess	*sess;
	struct ib_qp		*qp;
	struct ib_cq		*cq;
	struct ib_send_wr	beacon;      /* XXX die ASAP */
	struct ib_cqe		beacon_cqe;  /* XXX die ASAP */
	struct rdma_cm_id	*cm_id;
	struct ibtrs_ib_path	pri_path;
	struct ibtrs_ib_path	cur_path;
};

struct ibtrs_iu {
	struct list_head        list;
	struct ib_cqe           cqe;
	dma_addr_t              dma_addr;
	void                    *buf;
	size_t                  size;
	enum dma_data_direction direction;
	bool			is_msg;
	u32			tag;
};

struct ibtrs_heartbeat {
	atomic64_t	send_ts_ns;
	atomic64_t	recv_ts_ns;
	u32		timeout_ms;
};

#define IBTRS_VERSION 2
#define IBTRS_UUID_SIZE 16
#define IO_MSG_SIZE 24
#define IB_IMM_SIZE_BITS 32

#define IBTRS_HB_IMM  UINT_MAX
#define IBTRS_ACK_IMM (UINT_MAX-1)

#define GCC_DIAGNOSTIC_AWARE ((__GNUC__ > 6))
#if GCC_DIAGNOSTIC_AWARE
#pragma GCC diagnostic push
#pragma GCC diagnostic warning "-Wpadded"
#endif

/**
 * enum ibtrs_msg_types - IBTRS message types. DO NOT REMOVE OR REORDER!!!
 * @IBTRS_MSG_SESS_OPEN:	Client requests new session on Server
 * @IBTRS_MSG_SESS_OPEN_RESP:	Server informs Client about session parameters
 * @IBTRS_MSG_CON_OPEN:		Client requests new connection to server
 * @IBTRS_MSG_RDMA_WRITE:	Client writes data per RDMA to Server
 * @IBTRS_MSG_REQ_RDMA_WRITE:	Client requests data transfer per RDMA
 * @IBTRS_MSG_USER:		Data transfer per Infiniband message
 * @IBTRS_MSG_ERR:		Fatal Error happened
 * @IBTRS_MSG_SESS_INFO:	Client requests about session info
 */
enum ibtrs_msg_types {
	IBTRS_MSG_SESS_OPEN,
	IBTRS_MSG_SESS_OPEN_RESP,
	IBTRS_MSG_CON_OPEN,
	IBTRS_MSG_RDMA_WRITE,
	IBTRS_MSG_REQ_RDMA_WRITE,
	IBTRS_MSG_USER,
	IBTRS_MSG_ERROR,
	IBTRS_MSG_SESS_INFO,
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

#define IBTRS_HDR_LEN sizeof(struct ibtrs_msg_hdr)

/**
 * struct ibtrs_msg_session_open - Opens a new session between client and server
 * @hdr:	message header
 * @uuid:	client host identifier, unique until module reload
 * @ver:	IBTRS protocol version
 * @con_cnt:    number of connections in this session
 * @reserved:   reserved fields for future usage, 28 bytes is maximum for
 *		all IPv6/IPv4 session
 *
 * DO NOT CHANGE members before ver.
 */
struct ibtrs_msg_sess_open {
	struct ibtrs_msg_hdr	hdr;
	u8			uuid[IBTRS_UUID_SIZE];
	u8			ver;
	u8			con_cnt;
	u8			reserved[30];
};

/**
 * struct ibtrs_msg_sess_info
 * @hdr:		message header
 * @hostname:		client host name
 */
struct ibtrs_msg_sess_info {
	struct ibtrs_msg_hdr	hdr;
	u8                      hostname[MAXHOSTNAMELEN];
};

#define MSG_SESS_INFO_SIZE sizeof(struct ibtrs_msg_sess_info)

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

#define IBTRS_MSG_RESV_LEN 128
/**
 * struct ibtrs_msg_sess_open_resp - Servers response to %IBTRS_MSG_SESS_OPEN
 * @hdr:	message header
 * @ver:	IBTRS protocol version
 * @cnt:	Number of rdma addresses in this message
 * @rkey:	remote key to allow client to access buffers
 * @hostname:   hostname of local host
 * @reserved:    reserved fields for future usage
 * @max_inflight_msg:  max inflight messages (queue-depth) in this session
 * @max_io_size:   max io size server supports
 * @max_req_size:   max infiniband message size server supports
 * @addr:	rdma addresses of buffers
 */
struct ibtrs_msg_sess_open_resp {
	struct ibtrs_msg_hdr	hdr;
	u32			ver;
	u16			cnt;
	u16			max_inflight_msg;
	u32			rkey;
	u32			max_io_size;
	u32			max_req_size;
	u32			padding;
	u8                      hostname[MAXHOSTNAMELEN];
	u8			reserved[IBTRS_MSG_RESV_LEN];
	u64			addr[];
};

#define IBTRS_MSG_SESS_OPEN_RESP_LEN(cnt) \
	(sizeof(struct ibtrs_msg_sess_open_resp) + sizeof(u64) * cnt)
/**
 * struct ibtrs_msg_con_open - Opens a new connection between client and server
 * @hdr:		message header
 * @uuid:		client host identifier, unique until module reload
 */
struct ibtrs_msg_con_open {
	struct ibtrs_msg_hdr	hdr;
	u8			uuid[IBTRS_UUID_SIZE];
};

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

#define IBTRS_SG_DESC_LEN sizeof(struct ibtrs_sg_desc)

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

/**
 * struct ibtrs_msg_error - Error message
 * @hdr:		message header
 * @errno:		Errno number describing the error
 */
struct ibtrs_msg_error {
	struct ibtrs_msg_hdr	hdr;
	s32			errno;
	u32			__padding;
};

#if GCC_DIAGNOSTIC_AWARE
#pragma GCC diagnostic pop
#endif

int ibtrs_validate_message(const struct ibtrs_msg_hdr *hdr);

void fill_ibtrs_msg_sess_open(struct ibtrs_msg_sess_open *msg, u8 con_cnt,
			      const uuid_le *uuid);

void fill_ibtrs_msg_con_open(struct ibtrs_msg_con_open *msg,
			     const uuid_le *uuid);

void fill_ibtrs_msg_sess_info(struct ibtrs_msg_sess_info *msg,
			      const char *hostname);

void ibtrs_heartbeat_init(struct ibtrs_heartbeat *h, u32 timeout_ms);
void ibtrs_heartbeat_set_timeout_ms(struct ibtrs_heartbeat *h, u32 timeout_ms);
void ibtrs_heartbeat_set_send_ts(struct ibtrs_heartbeat *h);
void ibtrs_heartbeat_set_recv_ts(struct ibtrs_heartbeat *h);
s64 ibtrs_heartbeat_send_ts_diff_ms(const struct ibtrs_heartbeat *h);
s64 ibtrs_heartbeat_recv_ts_diff_ms(const struct ibtrs_heartbeat *h);
int ibtrs_heartbeat_timeout_validate(int timeout);

void ibtrs_iu_put(struct list_head *iu_list, struct ibtrs_iu *iu);
struct ibtrs_iu *ibtrs_iu_get(struct list_head *iu_list);

struct ibtrs_iu *ibtrs_iu_alloc(u32 tag, size_t size, gfp_t t,
				struct ib_device *dev,
				enum dma_data_direction, bool is_msg);

void ibtrs_iu_free(struct ibtrs_iu *iu, enum dma_data_direction dir,
		   struct ib_device *dev);

int ibtrs_post_beacon(struct ibtrs_con *con);

int ibtrs_post_send(struct ib_qp *qp, struct ib_mr *mr,
		    struct ibtrs_iu *iu, u32 size);

int ibtrs_post_rdma_write_imm(struct ib_qp *qp, struct ib_cqe *cqe,
			      struct ib_sge *sge, unsigned int num_sge,
			      u32 rkey, u64 rdma_addr, u32 imm_data,
			      enum ib_send_flags flags);

int ibtrs_post_rdma_write_imm_empty(struct ib_qp *qp, struct ib_cqe *cqe,
				    u32 imm_data, enum ib_send_flags flags);

int ibtrs_ib_dev_init(struct ibtrs_ib_dev *ibdev, struct ib_device *dev);
void ibtrs_ib_dev_destroy(struct ibtrs_ib_dev *ibdev);

int ibtrs_cq_qp_create(struct ibtrs_sess *ibtrs_sess, struct ibtrs_con *con,
		       struct rdma_cm_id *cm_id, u32 max_send_sge,
		       int cq_vector, u16 cq_size, u16 wr_queue_size,
		       struct ibtrs_ib_dev *ibdev,
		       enum ib_poll_context poll_ctx);
void ibtrs_cq_qp_destroy(struct ibtrs_con *con);

int ibtrs_request_cq_notifications(struct ibtrs_con *con);

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
