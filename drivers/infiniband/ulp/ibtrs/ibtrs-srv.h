#ifndef IBTRS_SRV_H
#define IBTRS_SRV_H

#include "ibtrs-pri.h"

enum ssm_state {
	SSM_STATE_IDLE,
	SSM_STATE_CONNECTED,
	SSM_STATE_CLOSING,
	SSM_STATE_CLOSED
};

/*
 * Describes the rdma buffer managed by client and used for his rdma writes
 * Rdma info has to be sent in OPEN_RESP message to the client.
 */
struct ibtrs_rcv_buf {
	dma_addr_t	rdma_addr;
	void		*buf;
};

/* to indicate that memory chunk was not allocated from a N-order contiguous
 * pages area
 */
#define IBTRS_MEM_CHUNK_NOORDER -1

struct ibtrs_mem_chunk {
	struct list_head	list;
	int			order;
	void			*addr;
};

struct ibtrs_rcv_buf_pool {
	struct list_head	list;
	struct list_head	chunk_list;
	struct ibtrs_rcv_buf	*rcv_bufs;
};

struct ibtrs_stats_wc_comp {
	atomic_t	max_wc_cnt;
	atomic64_t	calls;
	atomic64_t	total_wc_cnt;
};

struct ibtrs_srv_stats_rdma_stats {
	atomic64_t	cnt_read;
	atomic64_t	size_total_read;
	atomic64_t	cnt_write;
	atomic64_t	size_total_write;

	atomic_t	inflight;
	atomic64_t	inflight_total;
};

struct ibtrs_srv_stats_user_ib_msgs {
	atomic64_t recv_msg_cnt;
	atomic64_t sent_msg_cnt;
	atomic64_t recv_size;
	atomic64_t sent_size;
};

struct ibtrs_srv_stats {
	struct ibtrs_srv_stats_rdma_stats	rdma_stats;
	struct ibtrs_srv_stats_user_ib_msgs	user_ib_msgs;
	atomic_t				apm_cnt;
	struct ibtrs_stats_wc_comp		wc_comp;
};

struct ibtrs_srv_sess {
	struct ibtrs_sess	sess;
	struct ibtrs_srv_ctx	*ctx;
	struct list_head	ctx_list;
	enum ssm_state		state;
	struct kref		kref;
	struct workqueue_struct *sm_wq;	/* event processing */
	struct ibtrs_srv_dev	*dev; /* ib dev with mempool */
	struct mutex            lock; /* to protect con_list */
	int			cur_cq_vector;
	struct list_head        con_list;
	struct ibtrs_iu		*rdma_info_iu;
	struct ibtrs_iu		*dummy_rx_iu;
	struct ibtrs_iu		**usr_rx_ring;
	struct ibtrs_srv_op	**ops_ids;
	unsigned int		est_cnt; /* number of established connections */
	unsigned int		active_cnt; /* number of active (not closed)
					     * connections
					     */
	u8			con_cnt;
	bool			state_in_sysfs;
	bool			session_announced_to_user;
	struct ibtrs_rcv_buf_pool *rcv_buf_pool;
	wait_queue_head_t	bufs_wait;
	u8			off_len; /* number of bits for offset in
					  * one client buffer.
					  * 32 - ilog2(sess->queue_depth)
					  */
	u32			off_mask; /* mask to get offset in client buf
					   * out of the imm field
					   */
	u16			queue_depth;
	u16			wq_size;
	uuid_le			uuid;
	struct ibtrs_heartbeat	heartbeat;
	struct delayed_work	check_heartbeat_dwork;
	struct delayed_work	send_heartbeat_dwork;
	void			*priv;
	struct kobject		kobj;
	struct kobject		kobj_stats;
	struct ibtrs_srv_stats	stats;
};

void ibtrs_srv_queue_close(struct ibtrs_srv_sess *sess);

int ibtrs_srv_current_hca_port_to_str(struct ibtrs_srv_sess *sess,
				      char *buf, size_t len);
const char *ibtrs_srv_get_sess_hca_name(struct ibtrs_srv_sess *sess);
int ibtrs_srv_reset_rdma_stats(struct ibtrs_srv_sess *sess, bool enable);
ssize_t ibtrs_srv_stats_rdma_to_str(struct ibtrs_srv_sess *sess,
				    char *page, size_t len);
int ibtrs_srv_reset_user_ib_msgs_stats(struct ibtrs_srv_sess *sess, bool enable);
int ibtrs_srv_stats_user_ib_msgs_to_str(struct ibtrs_srv_sess *sess, char *buf,
					size_t len);
int ibtrs_srv_reset_wc_completion_stats(struct ibtrs_srv_sess *sess,
					bool enable);
int ibtrs_srv_stats_wc_completion_to_str(struct ibtrs_srv_sess *sess, char *buf,
					 size_t len);
int ibtrs_srv_reset_all_stats(struct ibtrs_srv_sess *sess, bool enable);
ssize_t ibtrs_srv_reset_all_help(struct ibtrs_srv_sess *sess,
				 char *page, size_t len);
int ibtrs_srv_sess_get(struct ibtrs_srv_sess *sess);

void ibtrs_srv_sess_put(struct ibtrs_srv_sess *sess);

/* ibtrs-srv-sysfs.c */

int ibtrs_srv_create_sysfs_files(void);

void ibtrs_srv_destroy_sysfs_files(void);

int ibtrs_srv_create_sess_files(struct ibtrs_srv_sess *sess);

#endif /* IBTRS_SRV_H */
