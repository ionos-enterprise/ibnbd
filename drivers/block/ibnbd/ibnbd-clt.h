#ifndef _IBNBD_CLT_H
#define _IBNBD_CLT_H
#include <linux/blkdev.h>
#include <linux/wait.h>			/* for wait_queue_head_t */
#include <linux/in.h>			/* for sockaddr_in */
#include <linux/inet.h>			/* for sockaddr_in */
#include <linux/blk-mq.h>
#include <rdma/ibtrs_clt.h>	/* for ibtrs api */
#include <rdma/ibtrs.h>

#include "ibnbd-clt-log.h"
#include "ibnbd.h"
#include "ibnbd-proto.h"


#define IP_PREFIX "ip:"
#define IP_PREFIX_LEN strlen(IP_PREFIX)
#define GID_PREFIX "gid:"
#define GID_PREFIX_LEN strlen(GID_PREFIX)

#define BMAX_SEGMENTS 31
#define RECONNECT_DELAY 30
#define MAX_RECONNECTS -1

enum ibnbd_dev_state {
	DEV_STATE_INIT,
	DEV_STATE_INIT_CLOSED,
	DEV_STATE_CLOSED,
	DEV_STATE_UNMAPPED,
	DEV_STATE_OPEN
};

enum ibnbd_queue_mode {
	BLK_MQ,
	BLK_RQ
};

struct ibnbd_iu {
	struct request		*rq;
	struct ibtrs_tag	*tag;
	struct ibnbd_dev	*dev;
	struct ibnbd_msg_io	msg;
	int			errno;
	struct scatterlist	sglist[BMAX_SEGMENTS];
};

struct ibnbd_cpu_qlist {
	struct list_head	requeue_list;
	spinlock_t		requeue_lock;
	unsigned int		cpu;
};

enum sess_state {
	SESS_STATE_READY,
	SESS_STATE_DISCONNECTED,
	SESS_STATE_DESTROYED,
};

struct ibnbd_session {
	struct list_head        list;
	struct ibtrs_session    *sess;
	struct ibnbd_cpu_qlist	__percpu
				*cpu_queues;
	DECLARE_BITMAP(cpu_queues_bm, NR_CPUS);
	int	__percpu	*cpu_rr; /* per-cpu var for CPU round-robin */
	atomic_t		busy;
	int			queue_depth;
	u32			max_io_size;
	struct blk_mq_tag_set	tag_set;
	struct mutex		lock; /* protects state and devs_list */
	struct list_head        devs_list; /* list of struct ibnbd_dev */
	struct kref		refcount;
	struct sockaddr_storage addr;
	char			str_addr[IBTRS_ADDRLEN];
	char			hostname[MAXHOSTNAMELEN];
	enum sess_state		state;
	u8			ver; /* protocol version */
	struct completion	*sess_info_compl;
};

struct ibnbd_work {
	struct work_struct	work;
	struct ibnbd_session	*sess;
};

/**
 * Submission queues.
 */
struct ibnbd_queue {
	struct list_head	requeue_list;
	unsigned long		in_list;
	struct ibnbd_dev	*dev;
	struct blk_mq_hw_ctx	*hctx;
};

struct ibnbd_dev {
	struct list_head        g_list;
	struct ibnbd_session	*sess;
	struct request_queue	*queue;
	struct ibnbd_queue	*hw_queues;
	struct delayed_work	rq_delay_work;
	u32			device_id;
	u32			clt_device_id;
	struct completion	*open_compl;	/* completion for open msg */
	int			open_errno;
	struct mutex		lock;
	enum ibnbd_dev_state	dev_state;
	enum ibnbd_queue_mode	queue_mode;
	enum ibnbd_io_mode	io_mode; /* user requested */
	enum ibnbd_io_mode	remote_io_mode; /* server really used */
	/* local Idr index - used to track minor number allocations. */
	char			pathname[NAME_MAX];
	enum ibnbd_access_mode	access_mode;
	bool			read_only;
	bool			rotational;
	u32			max_hw_sectors;
	u32			max_write_same_sectors;
	u32			max_discard_sectors;
	u32			discard_zeroes_data;
	u32			discard_granularity;
	u32			discard_alignment;
	u16			secure_discard;
	u16			physical_block_size;
	u16			logical_block_size;
	u16			max_segments;
	size_t			nsectors;
	u64			size;		/* device size in bytes */
	struct list_head        list;
	struct gendisk		*gd;
	struct kobject		kobj;
	char			blk_symlink_name[NAME_MAX];
	struct completion	*close_compl;
	atomic_t		refcount;
};

static inline const char *ibnbd_queue_mode_str(enum ibnbd_queue_mode mode)
{
	switch (mode) {
	case BLK_RQ:
		return "rq";
	case BLK_MQ:
		return "mq";
	default:
		return "unknown";
	}
}

int ibnbd_close_device(struct ibnbd_dev *dev, bool force);
struct ibnbd_session *ibnbd_create_session(const struct sockaddr_storage *addr);
struct ibnbd_session *ibnbd_clt_find_sess(const struct sockaddr_storage *addr);
void ibnbd_clt_sess_release(struct kref *ref);
struct ibnbd_dev *ibnbd_client_add_device(struct ibnbd_session *sess,
					  const char *pathname,
					  enum ibnbd_access_mode access_mode,
					  enum ibnbd_queue_mode queue_mode,
					  enum ibnbd_io_mode io_mode);
void ibnbd_destroy_gen_disk(struct ibnbd_dev *dev);
int ibnbd_addr_to_str(const struct sockaddr_storage *addr,
		      char *buf, size_t len);
bool ibnbd_clt_dev_is_open(struct ibnbd_dev *dev);
bool ibnbd_clt_dev_is_mapped(const char *pathname);
int open_remote_device(struct ibnbd_dev *dev);

const char *ibnbd_clt_get_io_mode(const struct ibnbd_dev *dev);

#define ERR_DEVS(sess, fmt, ...)	\
({	struct ibnbd_dev *dev;		\
					\
	mutex_lock(&sess->lock);	\
	list_for_each_entry(dev, &sess->devs_list, list) \
		pr_err("ibnbd L%d <%s@%s> ERR:" fmt, \
			__LINE__, dev->pathname, dev->sess->str_addr,\
			##__VA_ARGS__); \
	mutex_unlock(&sess->lock);	\
})

#define INFO_DEVS(sess, fmt, ...)	\
({	struct ibnbd_dev *dev;		\
					\
	mutex_lock(&sess->lock);	\
	list_for_each_entry(dev, &sess->devs_list, list) \
		pr_info("ibnbd <%s@%s> ERR:" fmt, \
			dev->pathname, dev->sess->str_addr,\
			##__VA_ARGS__);	\
	mutex_unlock(&sess->lock);	\
})
#endif /* _IBNBD_CLT_H */
