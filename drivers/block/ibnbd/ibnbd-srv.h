#ifndef _IBNBD_SRV_H
#define _IBNBD_SRV_H

#include <linux/types.h>
#include <linux/idr.h>
#include <linux/kref.h>
#include <rdma/ibtrs.h>

#include "ibnbd.h"
#include "ibnbd-proto.h"
#include "ibnbd-log.h"

enum ibnbd_srv_sess_state {
	SRV_SESS_STATE_CONNECTED,
	SRV_SESS_STATE_DISCONNECTED
};

struct ibnbd_srv_session {
	struct list_head        list; /* for the global sess_list */
	struct ibtrs_srv_sess   *ibtrs_sess;
	char			str_addr[IBTRS_ADDRLEN];
	char			hostname[MAXHOSTNAMELEN];
	int			queue_depth;
	enum ibnbd_srv_sess_state state;
	struct bio_set		*sess_bio_set;

	rwlock_t                index_lock ____cacheline_aligned;
	struct idr              index_idr;
	struct mutex		lock; /* protects sess_dev_list */
	struct list_head        sess_dev_list; /* list of struct ibnbd_srv_sess_dev */
	u8			ver; /* IBNBD protocol version */
};

struct ibnbd_srv_dev {
	struct list_head                list; /* global dev_list */

	struct kobject                  dev_kobj;
	struct kobject                  dev_clients_kobj;

	struct kref                     kref;
	char				id[NAME_MAX];

	struct mutex			lock; /* protects sess_dev_list and open_write_cnt */
	struct list_head		sess_dev_list; /* list of struct ibnbd_srv_sess_dev */
	int				open_write_cnt;
	enum ibnbd_io_mode		mode;
};

struct ibnbd_srv_sess_dev {
	struct list_head		dev_list; /* for struct ibnbd_srv_dev->sess_dev_list */
	struct list_head		sess_list; /* for struct ibnbd_srv_session->sess_dev_list */

	struct ibnbd_dev		*ibnbd_dev;
	struct ibnbd_srv_session        *sess;
	struct ibnbd_srv_dev		*dev;
	struct kobject                  kobj;
	struct completion		*sysfs_release_compl;

	u32                             device_id;
	u32                             clt_device_id;
	fmode_t                         open_flags;
	struct kref			kref;
	struct completion               *destroy_comp;
	char				pathname[NAME_MAX];
	size_t				nsectors;
	bool                            is_visible;
};

int ibnbd_srv_revalidate_dev(struct ibnbd_srv_dev *dev);

#endif
