// SPDX-License-Identifier: GPL-2.0-or-later
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
 * Copyright (c) 2018 - 2019 1&1 IONOS Cloud GmbH. All rights reserved.
 * Authors: Roman Penyaev <roman.penyaev@profitbricks.com>
 *          Jack Wang <jinpu.wang@cloud.ionos.com>
 *          Danil Kipnis <danil.kipnis@cloud.ionos.com>
 */

#undef pr_fmt
#define pr_fmt(fmt) KBUILD_MODNAME " L" __stringify(__LINE__) ": " fmt

#include <uapi/linux/limits.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/stat.h>
#include <linux/genhd.h>
#include <linux/list.h>
#include <linux/moduleparam.h>
#include <linux/device.h>

#include "ibnbd-srv.h"

static struct device *ibnbd_dev;
static struct class *ibnbd_dev_class;
static struct kobject *ibnbd_devs_kobj;

static struct kobj_type ktype = {
	.sysfs_ops	= &kobj_sysfs_ops,
};

int ibnbd_srv_create_dev_sysfs(struct ibnbd_srv_dev *dev,
			       struct block_device *bdev,
			       const char *dir_name)
{
	struct kobject *bdev_kobj;
	int ret;

	ret = kobject_init_and_add(&dev->dev_kobj, &ktype,
				   ibnbd_devs_kobj, dir_name);
	if (ret)
		return ret;

	ret = kobject_init_and_add(&dev->dev_sessions_kobj,
				   &ktype,
				   &dev->dev_kobj, "sessions");
	if (ret)
		goto err;

	bdev_kobj = &disk_to_dev(bdev->bd_disk)->kobj;
	ret = sysfs_create_link(&dev->dev_kobj, bdev_kobj, "block_dev");
	if (ret)
		goto err2;

	return 0;

err2:
	kobject_del(&dev->dev_sessions_kobj);
	kobject_put(&dev->dev_sessions_kobj);
err:
	kobject_del(&dev->dev_kobj);
	kobject_put(&dev->dev_kobj);
	return ret;
}

void ibnbd_srv_destroy_dev_sysfs(struct ibnbd_srv_dev *dev)
{
	sysfs_remove_link(&dev->dev_kobj, "block_dev");
	kobject_del(&dev->dev_sessions_kobj);
	kobject_put(&dev->dev_sessions_kobj);
	kobject_del(&dev->dev_kobj);
	kobject_put(&dev->dev_kobj);
}

static ssize_t read_only_show(struct kobject *kobj,
					     struct kobj_attribute *attr,
					     char *page)
{
	struct ibnbd_srv_sess_dev *sess_dev;

	sess_dev = container_of(kobj, struct ibnbd_srv_sess_dev, kobj);

	return scnprintf(page, PAGE_SIZE, "%s\n",
			 (sess_dev->open_flags & FMODE_WRITE) ? "0" : "1");
}

static struct kobj_attribute ibnbd_srv_dev_session_ro_attr =
	__ATTR_RO(read_only);

static ssize_t access_mode_show(struct kobject *kobj,
				struct kobj_attribute *attr,
				char *page)
{
	struct ibnbd_srv_sess_dev *sess_dev;

	sess_dev = container_of(kobj, struct ibnbd_srv_sess_dev, kobj);

	return scnprintf(page, PAGE_SIZE, "%s\n",
			 ibnbd_access_mode_str(sess_dev->access_mode));
}

static struct kobj_attribute ibnbd_srv_dev_session_access_mode_attr =
	__ATTR_RO(access_mode);

static ssize_t mapping_path_show(struct kobject *kobj,
				 struct kobj_attribute *attr, char *page)
{
	struct ibnbd_srv_sess_dev *sess_dev;

	sess_dev = container_of(kobj, struct ibnbd_srv_sess_dev, kobj);

	return scnprintf(page, PAGE_SIZE, "%s\n", sess_dev->pathname);
}

static struct kobj_attribute ibnbd_srv_dev_session_mapping_path_attr =
	__ATTR_RO(mapping_path);

static struct attribute *ibnbd_srv_default_dev_sessions_attrs[] = {
	&ibnbd_srv_dev_session_access_mode_attr.attr,
	&ibnbd_srv_dev_session_ro_attr.attr,
	&ibnbd_srv_dev_session_mapping_path_attr.attr,
	NULL,
};

static struct attribute_group ibnbd_srv_default_dev_session_attr_group = {
	.attrs = ibnbd_srv_default_dev_sessions_attrs,
};

void ibnbd_srv_destroy_dev_session_sysfs(struct ibnbd_srv_sess_dev *sess_dev)
{
	DECLARE_COMPLETION_ONSTACK(sysfs_compl);

	sysfs_remove_group(&sess_dev->kobj,
			   &ibnbd_srv_default_dev_session_attr_group);

	sess_dev->sysfs_release_compl = &sysfs_compl;
	kobject_del(&sess_dev->kobj);
	kobject_put(&sess_dev->kobj);
	wait_for_completion(&sysfs_compl);
}

static void ibnbd_srv_sess_dev_release(struct kobject *kobj)
{
	struct ibnbd_srv_sess_dev *sess_dev;

	sess_dev = container_of(kobj, struct ibnbd_srv_sess_dev, kobj);
	if (sess_dev->sysfs_release_compl)
		complete_all(sess_dev->sysfs_release_compl);
}

static struct kobj_type ibnbd_srv_sess_dev_ktype = {
	.sysfs_ops	= &kobj_sysfs_ops,
	.release	= ibnbd_srv_sess_dev_release,
};

int ibnbd_srv_create_dev_session_sysfs(struct ibnbd_srv_sess_dev *sess_dev)
{
	int ret;

	ret = kobject_init_and_add(&sess_dev->kobj, &ibnbd_srv_sess_dev_ktype,
				   &sess_dev->dev->dev_sessions_kobj, "%s",
				   sess_dev->sess->sessname);
	if (ret)
		return ret;

	ret = sysfs_create_group(&sess_dev->kobj,
				 &ibnbd_srv_default_dev_session_attr_group);
	if (ret)
		goto err;

	return 0;

err:
	kobject_del(&sess_dev->kobj);
	kobject_put(&sess_dev->kobj);

	return ret;
}

int ibnbd_srv_create_sysfs_files(void)
{
	int err;

	ibnbd_dev_class = class_create(THIS_MODULE, "ibnbd-server");
	if (unlikely(IS_ERR(ibnbd_dev_class)))
		return PTR_ERR(ibnbd_dev_class);

	ibnbd_dev = device_create(ibnbd_dev_class, NULL,
				  MKDEV(0, 0), NULL, "ctl");
	if (unlikely(IS_ERR(ibnbd_dev))) {
		err = PTR_ERR(ibnbd_dev);
		goto cls_destroy;
	}
	ibnbd_devs_kobj = kobject_create_and_add("devices", &ibnbd_dev->kobj);
	if (unlikely(!ibnbd_devs_kobj)) {
		err = -ENOMEM;
		goto dev_destroy;
	}

	return 0;

dev_destroy:
	device_destroy(ibnbd_dev_class, MKDEV(0, 0));
cls_destroy:
	class_destroy(ibnbd_dev_class);

	return err;
}

void ibnbd_srv_destroy_sysfs_files(void)
{
	kobject_del(ibnbd_devs_kobj);
	kobject_put(ibnbd_devs_kobj);
	device_destroy(ibnbd_dev_class, MKDEV(0, 0));
	class_destroy(ibnbd_dev_class);
}
