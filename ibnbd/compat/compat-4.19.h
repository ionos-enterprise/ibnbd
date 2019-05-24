/*
 * Copyright (c) Roman Pen, ProfitBricks GmbH.
 *
 * Copyright (c) 2018 - 2019 1&1 IONOS Cloud GmbH. All rights reserved.
 * Authors: Roman Penyaev <rpenyaev@suse.com>
 *          Jinpu Wang <jinpu.wang@cloud.ionos.com>
 *          Danil Kipnis <danil.kipnis@cloud.ionos.com>
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

#ifndef LINUX_4_19_COMPAT_H
#define LINUX_4_19_COMPAT_H

/*
 * linux/sysfs.h
 */
#define sysfs_remove_file_self ORIGINAL_sysfs_remove_file_self
#include <linux/sysfs.h>
#include <linux/device.h>
#undef sysfs_remove_file_self

static inline
void sysfs_remove_file_self(struct kobject *kobj,
			    const struct attribute *attr)
{
       struct device_attribute dattr = {
               .attr.name = attr->name
       };
       struct device *device;

       /*
        * Unfortunately original sysfs_remove_file_self() is not exported,
        * so consider this as a hack to call self removal of a sysfs entry
        * just using another "door".
        */

       device = container_of(kobj, typeof(*device), kobj);
       device_remove_file_self(device, &dattr);
}

#endif /* LINUX_4_19_COMPAT_H */
