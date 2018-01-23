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

#ifndef IBNBD_SRV_SYFS_H
#define IBNBD_SRV_SYFS_H

int ibnbd_srv_create_dev_sysfs(struct ibnbd_srv_dev *dev,
			       struct block_device *bdev,
			       const char *dir_name);

void ibnbd_srv_destroy_dev_sysfs(struct ibnbd_srv_dev *dev);

int ibnbd_srv_create_dev_session_sysfs(struct ibnbd_srv_sess_dev *sess_dev);

void ibnbd_srv_destroy_dev_session_sysfs(struct ibnbd_srv_sess_dev *sess_dev);

int ibnbd_srv_create_sysfs_files(void);

void ibnbd_srv_destroy_sysfs_files(void);

#endif /* IBNBD_SRV_SYFS_H */
