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
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions, and the following disclaimer,
 *    without modification.
 * 2. Redistributions in binary form must reproduce at minimum a disclaimer
 *    substantially similar to the "NO WARRANTY" disclaimer below
 *    ("Disclaimer") and any redistribution must be conditioned upon
 *    including a substantially similar Disclaimer requirement for further
 *    binary redistribution.
 * 3. Neither the names of the above-listed copyright holders nor the names
 *    of any contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * Alternatively, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") version 2 as published by the Free
 * Software Foundation.
 *
 * NO WARRANTY
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDERS OR CONTRIBUTORS BE LIABLE FOR SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGES.
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

enum ibnbd_srv_sess_state {
	SRV_SESS_STATE_CONNECTED,
	SRV_SESS_STATE_DISCONNECTED
};

struct ibnbd_srv_session {
	struct list_head        list; /* for the global sess_list */
	struct ibtrs_srv_sess   *ibtrs_sess;
	char			sessname[MAXHOSTNAMELEN];
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
	u32                             clt_device_id;
	fmode_t                         open_flags;
	struct kref			kref;
	struct completion               *destroy_comp;
	char				pathname[NAME_MAX];
	size_t				nsectors;
	bool                            is_visible;
};

int ibnbd_srv_revalidate_dev(struct ibnbd_srv_dev *dev);

#endif /* IBNBD_SRV_H */
