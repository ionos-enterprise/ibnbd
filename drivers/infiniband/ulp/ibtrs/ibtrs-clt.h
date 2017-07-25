#ifndef IBTRS_CLT_H
#define IBTRS_CLT_H

#include "ibtrs-pri.h"

enum ssm_state {
	_SSM_STATE_MIN,
	SSM_STATE_IDLE,
	SSM_STATE_IDLE_RECONNECT,
	SSM_STATE_WF_INFO,
	SSM_STATE_WF_INFO_RECONNECT,
	SSM_STATE_OPEN,
	SSM_STATE_OPEN_RECONNECT,
	SSM_STATE_CONNECTED,
	SSM_STATE_RECONNECT,
	SSM_STATE_RECONNECT_IMM,
	SSM_STATE_CLOSE_DESTROY,
	SSM_STATE_CLOSE_RECONNECT,
	SSM_STATE_CLOSE_RECONNECT_IMM,
	SSM_STATE_DISCONNECTED,
	SSM_STATE_DESTROYED,
	_SSM_STATE_MAX
};

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
	u32 max_wc_cnt;
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
	struct ibtrs_sess	sess;
	wait_queue_head_t	state_wq;
	enum ssm_state		state;
	struct ibtrs_clt_con	*con;
	struct ibtrs_ib_dev	ib_dev;
	struct ibtrs_iu		*info_rx_iu;
	struct ibtrs_iu		*info_tx_iu;
	struct ibtrs_iu		*dummy_rx_iu;
	struct ibtrs_iu		**usr_rx_ring;
	struct ibtrs_iu		**io_tx_ius;

	spinlock_t              u_msg_ius_lock;
	struct list_head	u_msg_ius_list;

	struct rdma_req		*reqs;
	struct ib_fmr_pool	*fmr_pool;
	atomic_t		ib_dev_initialized;
	bool			io_bufs_initialized;
	size_t			pdu_sz;
	void			*priv;
	struct delayed_work	heartbeat_dwork;
	struct delayed_work	reconnect_dwork;
	struct ibtrs_heartbeat	heartbeat;
	atomic_t		refcount;
	u8			active_cnt;
	bool			enable_rdma_lat;
	u8			ver;
	u8			connected_cnt;
	u32			retry_cnt;
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
	struct completion	*destroy_completion;
	struct kobject		kobj;
	struct kobject		kobj_stats;
	struct ibtrs_clt_stats  stats;
	wait_queue_head_t	mu_iu_wq;
	wait_queue_head_t	mu_buf_wq;
	atomic_t		peer_usr_msg_bufs;
	bool			device_removed;
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

int ibtrs_clt_create_sess_files(struct kobject *kobj, struct kobject *kobj_sess,
				const char *ip);

void ibtrs_clt_destroy_sess_files(struct kobject *kobj,
				  struct kobject *kobj_sess);


#endif /* IBTRS_CLT_H */
