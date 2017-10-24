#ifndef IBTRS_CLT_H
#define IBTRS_CLT_H

#include <linux/uuid.h>

#include "ibtrs-pri.h"

/**
 * enum ibtrs_clt_state - Client states.
 */
enum ibtrs_clt_state {
	IBTRS_CLT_CONNECTING,
	IBTRS_CLT_CONNECTING_ERR,
	IBTRS_CLT_RECONNECTING,
	IBTRS_CLT_CONNECTED,
	IBTRS_CLT_CLOSING,
	IBTRS_CLT_CLOSED,
};

static inline const char *ibtrs_clt_state_str(enum ibtrs_clt_state state)
{
	switch (state) {
	case IBTRS_CLT_CONNECTING:
		return "IBTRS_CLT_CONNECTING";
	case IBTRS_CLT_CONNECTING_ERR:
		return "IBTRS_CLT_CONNECTING_ERR";
	case IBTRS_CLT_RECONNECTING:
		return "IBTRS_CLT_RECONNECTING";
	case IBTRS_CLT_CONNECTED:
		return "IBTRS_CLT_CONNECTED";
	case IBTRS_CLT_CLOSING:
		return "IBTRS_CLT_CLOSING";
	case IBTRS_CLT_CLOSED:
		return "IBTRS_CLT_CLOSED";
	default:
		return "UNKNOWN";
	}
}

enum ibtrs_fast_reg {
	IBTRS_FAST_MEM_NONE,
	IBTRS_FAST_MEM_FR,
	IBTRS_FAST_MEM_FMR
};

struct ibtrs_stats_reconnects {
	u32 successful_cnt;
	u32 fail_cnt;
};

struct ibtrs_stats_wc_comp {
	u32 cnt;
	u64 total_cnt;
};

struct ibtrs_stats_cpu_migration {
	atomic_t *from;
	int *to;
};

struct ibtrs_clt_stats_rdma_stats {
	u64 cnt_read;
	u64 size_total_read;
	u64 cnt_write;
	u64 size_total_write;

	u16 inflight;
};

#define MIN_LOG_SG 2
#define MAX_LOG_SG 5
#define MAX_LIN_SG BIT(MIN_LOG_SG)
#define SG_DISTR_LEN (MAX_LOG_SG - MIN_LOG_SG + MAX_LIN_SG + 1)

struct ibtrs_clt_stats_rdma_lat_entry {
	u64 read;
	u64 write;
};

#define MAX_LOG_LATENCY	16
#define MIN_LOG_LATENCY	0

struct ibtrs_clt_stats_user_ib_msgs {
	u32 recv_msg_cnt;
	u32 sent_msg_cnt;
	u64 recv_size;
	u64 sent_size;
};

struct ibtrs_clt_stats {
	struct ibtrs_stats_cpu_migration	cpu_migr;
	struct ibtrs_clt_stats_rdma_stats	*rdma_stats;
	u64					*sg_list_total;
	u64					**sg_list_distr;
	struct ibtrs_stats_reconnects		reconnects;
	struct ibtrs_clt_stats_rdma_lat_entry	**rdma_lat_distr;
	struct ibtrs_clt_stats_rdma_lat_entry	*rdma_lat_max;
	struct ibtrs_clt_stats_user_ib_msgs	user_ib_msgs;
	struct ibtrs_stats_wc_comp		*wc_comp;
};

struct ibtrs_clt_sess {
	struct ibtrs_sess	s;
	wait_queue_head_t	state_wq;
	enum ibtrs_clt_state	state;
	struct mutex		init_mutex;
	struct ibtrs_clt_con	*con;
	struct ibtrs_iu		**io_tx_ius;

	struct rdma_req		*reqs;
	struct ib_fmr_pool	*fmr_pool;
	size_t			pdu_sz;
	struct ibtrs_clt_ops	ops;
	struct delayed_work	reconnect_dwork;
	struct work_struct	close_work;
	bool			enable_rdma_lat;
	s16			max_reconnect_attempts;
	u8			reconnect_delay_sec;
	void			*tags;
	unsigned long		*tags_map;
	wait_queue_head_t	tags_wait;
	u64			*srv_rdma_addr;
	u32			srv_rdma_buf_rkey;
	u32			max_io_size;
	u32			max_req_size;
	u32			chunk_size;
	u32			max_desc;
	u32			queue_depth;
	u16			user_queue_depth;
	enum ibtrs_fast_reg	fast_reg_mode;
	u64			mr_page_mask;
	u32			mr_page_size;
	u32			mr_max_size;
	u32			max_pages_per_mr;
	int			max_sge;
	struct sockaddr_storage peer_addr;
	struct sockaddr_storage self_addr;
	struct kobject		kobj;
	struct kobject		kobj_stats;
	struct ibtrs_clt_stats  stats;
};

#define TAG_SIZE(sess) (sizeof(struct ibtrs_tag) + (sess)->pdu_sz)
#define GET_TAG(sess, idx) ((sess)->tags + TAG_SIZE(sess) * idx)

/**
 * ibtrs_clt_reconnect() - Reconnect the session
 * @sess: Session handler
 */
int ibtrs_clt_reconnect(struct ibtrs_clt_sess *sess);

void ibtrs_clt_set_max_reconnect_attempts(struct ibtrs_clt_sess *sess,
					  s16 value);

s16 ibtrs_clt_get_max_reconnect_attempts(const struct ibtrs_clt_sess *sess);
int ibtrs_clt_get_user_queue_depth(struct ibtrs_clt_sess *sess);
int ibtrs_clt_set_user_queue_depth(struct ibtrs_clt_sess *sess, u16 queue_depth);
int ibtrs_clt_reset_sg_list_distr_stats(struct ibtrs_clt_sess *sess,
					bool enable);
int ibtrs_clt_stats_sg_list_distr_to_str(struct ibtrs_clt_sess *sess,
					 char *buf, size_t len);
int ibtrs_clt_reset_rdma_lat_distr_stats(struct ibtrs_clt_sess *sess,
					 bool enable);
ssize_t ibtrs_clt_stats_rdma_lat_distr_to_str(struct ibtrs_clt_sess *sess,
					      char *page, size_t len);
int ibtrs_clt_reset_cpu_migr_stats(struct ibtrs_clt_sess *sess, bool enable);
int ibtrs_clt_stats_migration_cnt_to_str(struct ibtrs_clt_sess *sess, char *buf,
					 size_t len);
int ibtrs_clt_reset_reconnects_stat(struct ibtrs_clt_sess *sess, bool enable);
int ibtrs_clt_stats_reconnects_to_str(struct ibtrs_clt_sess *sess, char *buf,
				      size_t len);
int ibtrs_clt_reset_user_ib_msgs_stats(struct ibtrs_clt_sess *sess, bool enable);
int ibtrs_clt_stats_user_ib_msgs_to_str(struct ibtrs_clt_sess *sess, char *buf,
					size_t len);
int ibtrs_clt_reset_wc_comp_stats(struct ibtrs_clt_sess *sess, bool enable);
int ibtrs_clt_stats_wc_completion_to_str(struct ibtrs_clt_sess *sess, char *buf,
					 size_t len);
int ibtrs_clt_reset_rdma_stats(struct ibtrs_clt_sess *sess, bool enable);
ssize_t ibtrs_clt_stats_rdma_to_str(struct ibtrs_clt_sess *sess,
				    char *page, size_t len);
bool ibtrs_clt_sess_is_connected(const struct ibtrs_clt_sess *sess);
int ibtrs_clt_reset_all_stats(struct ibtrs_clt_sess *sess, bool enable);
ssize_t ibtrs_clt_reset_all_help(struct ibtrs_clt_sess *sess,
				 char *page, size_t len);

/* ibtrs-clt-sysfs.c */

int ibtrs_clt_create_sysfs_files(void);
void ibtrs_clt_destroy_sysfs_files(void);
int ibtrs_clt_create_sess_files(struct ibtrs_clt_sess *sess);
void ibtrs_clt_destroy_sess_files(struct ibtrs_clt_sess *sess);

#endif /* IBTRS_CLT_H */
