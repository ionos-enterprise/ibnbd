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
 *          Swapnil Ingle <swapnil.ingle@profitbricks.com>
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

#ifndef IBTRS_CLT_H
#define IBTRS_CLT_H

#include <linux/device.h>
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
	IBTRS_CLT_DEAD,
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
	case IBTRS_CLT_DEAD:
		return "IBTRS_CLT_DEAD";
	default:
		return "UNKNOWN";
	}
}

enum ibtrs_mp_policy {
	MP_POLICY_RR,
	MP_POLICY_MIN_INFLIGHT,
};

struct ibtrs_clt_stats_reconnects {
	int successful_cnt;
	int fail_cnt;
};

struct ibtrs_clt_stats_wc_comp {
	u32 cnt;
	u64 total_cnt;
};

struct ibtrs_clt_stats_cpu_migr {
	atomic_t from;
	int to;
};

struct ibtrs_clt_stats_rdma {
	struct {
		u64 cnt;
		u64 size_total;
	} dir[2];

	u64 failover_cnt;
};

struct ibtrs_clt_stats_rdma_lat {
	u64 read;
	u64 write;
};

#define MIN_LOG_SG 2
#define MAX_LOG_SG 5
#define MAX_LIN_SG BIT(MIN_LOG_SG)
#define SG_DISTR_SZ (MAX_LOG_SG - MIN_LOG_SG + MAX_LIN_SG + 2)

#define MAX_LOG_LAT 16
#define MIN_LOG_LAT 0
#define LOG_LAT_SZ (MAX_LOG_LAT - MIN_LOG_LAT + 2)

struct ibtrs_clt_stats_pcpu {
	struct ibtrs_clt_stats_cpu_migr		cpu_migr;
	struct ibtrs_clt_stats_rdma		rdma;
	u64					sg_list_total;
	u64					sg_list_distr[SG_DISTR_SZ];
	struct ibtrs_clt_stats_rdma_lat		rdma_lat_distr[LOG_LAT_SZ];
	struct ibtrs_clt_stats_rdma_lat		rdma_lat_max;
	struct ibtrs_clt_stats_wc_comp		wc_comp;
};

struct ibtrs_clt_stats {
	bool					enable_rdma_lat;
	struct ibtrs_clt_stats_pcpu    __percpu	*pcpu_stats;
	struct ibtrs_clt_stats_reconnects	reconnects;
	atomic_t				inflight;
};

struct ibtrs_clt_con {
	struct ibtrs_con	c;
	unsigned		cpu;
	atomic_t		io_cnt;
	int			cm_err;
};

/**
 * ibtrs_tag - tags the memory allocation for future RDMA operation
 */
struct ibtrs_tag {
	enum ibtrs_clt_con_type con_type;
	unsigned int cpu_id;
	unsigned int mem_id;
	unsigned int mem_off;
};

struct ibtrs_clt_io_req {
	struct list_head        list;
	struct ibtrs_iu		*iu;
	struct scatterlist	*sglist; /* list holding user data */
	unsigned int		sg_cnt;
	unsigned int		sg_size;
	unsigned int		data_len;
	unsigned int		usr_len;
	void			*priv;
	bool			in_use;
	struct ibtrs_clt_con	*con;
	struct ibtrs_sg_desc	*desc;
	struct ib_sge		*sge;
	struct ibtrs_tag	*tag;
	enum dma_data_direction dir;
	ibtrs_conf_fn		*conf;
	unsigned long		start_jiffies;

	struct ib_mr		*mr;
	struct ib_cqe		inv_cqe;
	struct completion	inv_comp;
	int			inv_errno;
	bool			need_inv_comp;
	bool			need_inv;
};

struct ibtrs_rbuf {
	u64 addr;
	u32 rkey;
};

struct ibtrs_clt_sess {
	struct ibtrs_sess	s;
	struct ibtrs_clt	*clt;
	wait_queue_head_t	state_wq;
	enum ibtrs_clt_state	state;
	atomic_t		connected_cnt;
	struct mutex		init_mutex;
	struct ibtrs_clt_io_req	*reqs;
	struct delayed_work	reconnect_dwork;
	struct work_struct	close_work;
	unsigned		reconnect_attempts;
	bool			established;
	struct ibtrs_rbuf	*rbufs;
	size_t			max_io_size;
	u32			max_hdr_size;
	u32			chunk_size;
	size_t			queue_depth;
	u32			max_pages_per_mr;
	int			max_sge;
	struct kobject		kobj;
	struct kobject		kobj_stats;
	struct ibtrs_clt_stats  stats;
	/* cache hca_port and hca_name to display in sysfs */
	u8			hca_port;
	char                    hca_name[IB_DEVICE_NAME_MAX];
	struct list_head __percpu
				*mp_skip_entry;
};

struct ibtrs_clt {
	struct list_head   /* __rcu */ paths_list;
	size_t			       paths_num;
	struct ibtrs_clt_sess
		      __percpu * __rcu *pcpu_path;

	bool			opened;
	uuid_t			paths_uuid;
	int			paths_up;
	struct mutex		paths_mutex;
	struct mutex		paths_ev_mutex;
	char			sessname[NAME_MAX];
	short			port;
	unsigned		max_reconnect_attempts;
	unsigned		reconnect_delay_sec;
	unsigned		max_segments;
	void			*tags;
	unsigned long		*tags_map;
	size_t			queue_depth;
	size_t			max_io_size;
	wait_queue_head_t	tags_wait;
	size_t			pdu_sz;
	void			*priv;
	link_clt_ev_fn		*link_ev;
	struct device		dev;
	struct kobject		kobj_paths;
	enum ibtrs_mp_policy	mp_policy;
};

static inline struct ibtrs_clt_con *to_clt_con(struct ibtrs_con *c)
{
	return container_of(c, struct ibtrs_clt_con, c);
}

static inline struct ibtrs_clt_sess *to_clt_sess(struct ibtrs_sess *s)
{
	return container_of(s, struct ibtrs_clt_sess, s);
}

/* See ibtrs-log.h */
#define TYPES_TO_SESSNAME(obj)						\
	LIST(CASE(obj, struct ibtrs_clt_sess *, s.sessname),		\
	     CASE(obj, struct ibtrs_clt *, sessname))

#define TAG_SIZE(clt) (sizeof(struct ibtrs_tag) + (clt)->pdu_sz)
#define GET_TAG(clt, idx) ((clt)->tags + TAG_SIZE(clt) * idx)

int ibtrs_clt_reconnect_from_sysfs(struct ibtrs_clt_sess *sess);
int ibtrs_clt_disconnect_from_sysfs(struct ibtrs_clt_sess *sess);
int ibtrs_clt_create_path_from_sysfs(struct ibtrs_clt *clt,
				     struct ibtrs_addr *addr);
int ibtrs_clt_remove_path_from_sysfs(struct ibtrs_clt_sess *sess,
				     const struct attribute *sysfs_self);

void ibtrs_clt_set_max_reconnect_attempts(struct ibtrs_clt *clt, int value);
int ibtrs_clt_get_max_reconnect_attempts(const struct ibtrs_clt *clt);

/* ibtrs-clt-stats.c */

int ibtrs_clt_init_stats(struct ibtrs_clt_stats *stats);
void ibtrs_clt_free_stats(struct ibtrs_clt_stats *stats);

void ibtrs_clt_decrease_inflight(struct ibtrs_clt_stats *s);
void ibtrs_clt_inc_failover_cnt(struct ibtrs_clt_stats *s);

void ibtrs_clt_update_rdma_lat(struct ibtrs_clt_stats *s, bool read,
			       unsigned long ms);
void ibtrs_clt_update_wc_stats(struct ibtrs_clt_con *con);
void ibtrs_clt_update_all_stats(struct ibtrs_clt_io_req *req, int dir);

int ibtrs_clt_reset_sg_list_distr_stats(struct ibtrs_clt_stats *stats,
					bool enable);
int ibtrs_clt_stats_sg_list_distr_to_str(struct ibtrs_clt_stats *stats,
					 char *buf, size_t len);
int ibtrs_clt_reset_rdma_lat_distr_stats(struct ibtrs_clt_stats *stats,
					 bool enable);
ssize_t ibtrs_clt_stats_rdma_lat_distr_to_str(struct ibtrs_clt_stats *stats,
					      char *page, size_t len);
int ibtrs_clt_reset_cpu_migr_stats(struct ibtrs_clt_stats *stats, bool enable);
int ibtrs_clt_stats_migration_cnt_to_str(struct ibtrs_clt_stats *stats, char *buf,
					 size_t len);
int ibtrs_clt_reset_reconnects_stat(struct ibtrs_clt_stats *stats, bool enable);
int ibtrs_clt_stats_reconnects_to_str(struct ibtrs_clt_stats *stats, char *buf,
				      size_t len);
int ibtrs_clt_reset_wc_comp_stats(struct ibtrs_clt_stats *stats, bool enable);
int ibtrs_clt_stats_wc_completion_to_str(struct ibtrs_clt_stats *stats, char *buf,
					 size_t len);
int ibtrs_clt_reset_rdma_stats(struct ibtrs_clt_stats *stats, bool enable);
ssize_t ibtrs_clt_stats_rdma_to_str(struct ibtrs_clt_stats *stats,
				    char *page, size_t len);
bool ibtrs_clt_sess_is_connected(const struct ibtrs_clt_sess *sess);
int ibtrs_clt_reset_all_stats(struct ibtrs_clt_stats *stats, bool enable);
ssize_t ibtrs_clt_reset_all_help(struct ibtrs_clt_stats *stats,
				 char *page, size_t len);

/* ibtrs-clt-sysfs.c */

int ibtrs_clt_create_sysfs_root_folders(struct ibtrs_clt *clt);
int ibtrs_clt_create_sysfs_root_files(struct ibtrs_clt *clt);
void ibtrs_clt_destroy_sysfs_root_folders(struct ibtrs_clt *clt);
void ibtrs_clt_destroy_sysfs_root_files(struct ibtrs_clt *clt);

int ibtrs_clt_create_sess_files(struct ibtrs_clt_sess *sess);
void ibtrs_clt_destroy_sess_files(struct ibtrs_clt_sess *sess,
				  const struct attribute *sysfs_self);

#endif /* IBTRS_CLT_H */
