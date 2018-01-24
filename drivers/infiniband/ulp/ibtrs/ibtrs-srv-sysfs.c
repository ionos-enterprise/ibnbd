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

#undef pr_fmt
#define pr_fmt(fmt) KBUILD_MODNAME " L" __stringify(__LINE__) ": " fmt

#include "ibtrs-pri.h"
#include "ibtrs-srv.h"
#include "ibtrs-log.h"

extern struct class *ibtrs_dev_class;

static struct kobj_type ktype = {
	.sysfs_ops	= &kobj_sysfs_ops,
};

static ssize_t ibtrs_srv_disconnect_show(struct kobject *kobj,
					 struct kobj_attribute *attr,
					 char *page)
{
	return scnprintf(page, PAGE_SIZE, "Usage: echo 1 > %s\n",
			 attr->attr.name);
}

static ssize_t ibtrs_srv_disconnect_store(struct kobject *kobj,
					  struct kobj_attribute *attr,
					  const char *buf, size_t count)
{
	struct ibtrs_srv_sess *sess;
	char str[MAXHOSTNAMELEN];

	sess = container_of(kobj, struct ibtrs_srv_sess, kobj);
	if (!sysfs_streq(buf, "1")) {
		ibtrs_err(sess, "%s: invalid value: '%s'\n",
			  attr->attr.name, buf);
		return -EINVAL;
	}

	sockaddr_to_str((struct sockaddr *)&sess->s.dst_addr, str, sizeof(str));

	ibtrs_info(sess, "disconnect for path %s requested\n", str);
	ibtrs_srv_queue_close(sess);

	return count;
}

static struct kobj_attribute ibtrs_srv_disconnect_attr =
	__ATTR(disconnect, 0644,
	       ibtrs_srv_disconnect_show, ibtrs_srv_disconnect_store);

static ssize_t ibtrs_srv_hca_port_show(struct kobject *kobj,
				       struct kobj_attribute *attr,
				       char *page)
{
	struct ibtrs_srv_sess *sess;
	struct ibtrs_con *usr_con;

	sess = container_of(kobj, typeof(*sess), kobj);
	usr_con = sess->s.con[0];

	return scnprintf(page, PAGE_SIZE, "%u\n",
			 usr_con->cm_id->port_num);
}

static struct kobj_attribute ibtrs_srv_hca_port_attr =
	__ATTR(hca_port, 0444, ibtrs_srv_hca_port_show, NULL);

static ssize_t ibtrs_srv_hca_name_show(struct kobject *kobj,
				       struct kobj_attribute *attr,
				       char *page)
{
	struct ibtrs_srv_sess *sess;

	sess = container_of(kobj, struct ibtrs_srv_sess, kobj);

	return scnprintf(page, PAGE_SIZE, "%s\n",
			 sess->s.dev->ib_dev->name);
}

static struct kobj_attribute ibtrs_srv_hca_name_attr =
	__ATTR(hca_name, 0444, ibtrs_srv_hca_name_show, NULL);

static struct attribute *ibtrs_srv_sess_attrs[] = {
	&ibtrs_srv_hca_name_attr.attr,
	&ibtrs_srv_hca_port_attr.attr,
	&ibtrs_srv_disconnect_attr.attr,
	NULL,
};

static struct attribute_group ibtrs_srv_sess_attr_group = {
	.attrs = ibtrs_srv_sess_attrs,
};

STAT_ATTR(struct ibtrs_srv_sess, rdma,
	  ibtrs_srv_stats_rdma_to_str,
	  ibtrs_srv_reset_rdma_stats);

STAT_ATTR(struct ibtrs_srv_sess, wc_completion,
	  ibtrs_srv_stats_wc_completion_to_str,
	  ibtrs_srv_reset_wc_completion_stats);

STAT_ATTR(struct ibtrs_srv_sess, reset_all,
	  ibtrs_srv_reset_all_help,
	  ibtrs_srv_reset_all_stats);

static struct attribute *ibtrs_srv_stats_attrs[] = {
	&rdma_attr.attr,
	&wc_completion_attr.attr,
	&reset_all_attr.attr,
	NULL,
};

static struct attribute_group ibtrs_srv_stats_attr_group = {
	.attrs = ibtrs_srv_stats_attrs,
};

static void ibtrs_srv_dev_release(struct device *dev)
{
	/* Nobody plays with device references, so nop */
}

static int ibtrs_srv_create_once_sysfs_root_folders(struct ibtrs_srv_sess *sess)
{
	struct ibtrs_srv *srv = sess->srv;
	int err = 0;

	mutex_lock(&srv->paths_mutex);
	if (srv->dev_ref++) {
		/*
		 * Just increase device reference.  We can't use get_device()
		 * because we need to unregister device when ref goes to 0,
		 * not just to put it.
		 */
		goto unlock;
	}
	srv->dev.class = ibtrs_dev_class;
	srv->dev.release = ibtrs_srv_dev_release;
	dev_set_name(&srv->dev, "%s", sess->s.sessname);

	err = device_register(&srv->dev);
	if (unlikely(err)) {
		pr_err("device_register(): %d\n", err);
		goto unlock;
	}
	err = kobject_init_and_add(&srv->kobj_paths, &ktype,
				   &srv->dev.kobj, "paths");
	if (unlikely(err)) {
		pr_err("kobject_init_and_add(): %d\n", err);
		device_unregister(&srv->dev);
		goto unlock;
	}
unlock:
	mutex_unlock(&srv->paths_mutex);

	return err;
}

static void ibtrs_srv_destroy_once_sysfs_root_folders(struct ibtrs_srv_sess *sess)
{
	struct ibtrs_srv *srv = sess->srv;

	mutex_lock(&srv->paths_mutex);
	if (!--srv->dev_ref) {
		kobject_put(&srv->kobj_paths);
		device_unregister(&srv->dev);
	}
	mutex_unlock(&srv->paths_mutex);
}

static int ibtrs_srv_create_stats_files(struct ibtrs_srv_sess *sess)
{
	int err;

	err = kobject_init_and_add(&sess->kobj_stats, &ktype,
				   &sess->kobj, "stats");
	if (unlikely(err)) {
		ibtrs_err(sess, "kobject_init_and_add(): %d\n", err);
		return err;
	}
	err = sysfs_create_group(&sess->kobj_stats,
				 &ibtrs_srv_stats_attr_group);
	if (unlikely(err)) {
		ibtrs_err(sess, "sysfs_create_group(): %d\n", err);
		goto err;
	}

	return 0;

err:
	kobject_put(&sess->kobj_stats);

	return err;
}

int ibtrs_srv_create_sess_files(struct ibtrs_srv_sess *sess)
{
	struct ibtrs_srv *srv = sess->srv;
	char str[MAXHOSTNAMELEN];
	int err;

	sockaddr_to_str((struct sockaddr *)&sess->s.dst_addr, str, sizeof(str));

	err = ibtrs_srv_create_once_sysfs_root_folders(sess);
	if (unlikely(err))
		return err;

	err = kobject_init_and_add(&sess->kobj, &ktype, &srv->kobj_paths,
				   "%s", str);
	if (unlikely(err)) {
		ibtrs_err(sess, "kobject_init_and_add(): %d\n", err);
		goto destroy_root;
	}
	err = sysfs_create_group(&sess->kobj, &ibtrs_srv_sess_attr_group);
	if (unlikely(err)) {
		ibtrs_err(sess, "sysfs_create_group(): %d\n", err);
		goto put_kobj;
	}
	err = ibtrs_srv_create_stats_files(sess);
	if (unlikely(err))
		goto remove_group;

	return 0;

remove_group:
	sysfs_remove_group(&sess->kobj, &ibtrs_srv_sess_attr_group);
put_kobj:
	kobject_del(&sess->kobj);
	kobject_put(&sess->kobj);
destroy_root:
	ibtrs_srv_destroy_once_sysfs_root_folders(sess);

	return err;
}

void ibtrs_srv_destroy_sess_files(struct ibtrs_srv_sess *sess)
{
	if (sess->kobj.state_in_sysfs) {
		kobject_del(&sess->kobj_stats);
		kobject_put(&sess->kobj_stats);
		kobject_del(&sess->kobj);
		kobject_put(&sess->kobj);

		ibtrs_srv_destroy_once_sysfs_root_folders(sess);
	}
}
