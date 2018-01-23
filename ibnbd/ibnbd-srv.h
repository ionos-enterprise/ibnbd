/*
 * InfiniBand Network Block Driver
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

#ifndef IBNBD_SRV_H
#define IBNBD_SRV_H

#include <linux/types.h>
#include <linux/idr.h>
#include <linux/kref.h>
#include <rdma/ibtrs.h>

#include "ibnbd.h"
#include "ibnbd-proto.h"
#include "ibnbd-log.h"

struct ibnbd_srv_session {
	struct list_head        list; /* for the global sess_list */
	struct ibtrs_srv	*ibtrs;
	char			sessname[NAME_MAX];
	int			queue_depth;
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
	struct kobject                  dev_sessions_kobj;

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
	fmode_t                         open_flags;
	struct kref			kref;
	struct completion               *destroy_comp;
	char				pathname[NAME_MAX];
	bool                            is_visible;
};

int ibnbd_srv_revalidate_dev(struct ibnbd_srv_dev *dev);

#endif /* IBNBD_SRV_H */
