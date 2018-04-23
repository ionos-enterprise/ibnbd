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
#include "ibtrs-clt.h"
#include "ibtrs-log.h"

#define MIN_MAX_RECONN_ATT -1
#define MAX_MAX_RECONN_ATT 9999

static struct kobj_type ktype = {
	.sysfs_ops = &kobj_sysfs_ops,
};

static ssize_t max_reconnect_attempts_show(struct device *dev,
					   struct device_attribute *attr,
					   char *page)
{
	struct ibtrs_clt *clt;

	clt = container_of(dev, struct ibtrs_clt, dev);

	return sprintf(page, "%d\n", ibtrs_clt_get_max_reconnect_attempts(clt));
}

static ssize_t max_reconnect_attempts_store(struct device *dev,
					    struct device_attribute *attr,
					    const char *buf,
					    size_t count)
{
	struct ibtrs_clt *clt;
	int value;
	int ret;

	clt = container_of(dev, struct ibtrs_clt, dev);

	ret = kstrtoint(buf, 10, &value);
	if (unlikely(ret)) {
		ibtrs_err(clt, "%s: failed to convert string '%s' to int\n",
			  attr->attr.name, buf);
		return ret;
	}
	if (unlikely(value > MAX_MAX_RECONN_ATT ||
		     value < MIN_MAX_RECONN_ATT)) {
		ibtrs_err(clt, "%s: invalid range"
			  " (provided: '%s', accepted: min: %d, max: %d)\n",
			  attr->attr.name, buf, MIN_MAX_RECONN_ATT,
			  MAX_MAX_RECONN_ATT);
		return -EINVAL;
	}
	ibtrs_clt_set_max_reconnect_attempts(clt, value);

	return count;
}

static DEVICE_ATTR_RW(max_reconnect_attempts);

static ssize_t mpath_policy_show(struct device *dev,
				 struct device_attribute *attr,
				 char *page)
{
	struct ibtrs_clt *clt;

	clt = container_of(dev, struct ibtrs_clt, dev);

	switch (clt->mp_policy) {
	case MP_POLICY_RR:
		return sprintf(page, "round-robin (RR: %d)\n", clt->mp_policy);
	case MP_POLICY_MIN_INFLIGHT:
		return sprintf(page, "min-inflight (MI: %d)\n", clt->mp_policy);
	default:
		return sprintf(page, "Unknown (%d)\n", clt->mp_policy);
	}
}

static ssize_t mpath_policy_store(struct device *dev,
				  struct device_attribute *attr,
				  const char *buf,
				  size_t count)
{
	struct ibtrs_clt *clt;
	int value;
	int ret;

	clt = container_of(dev, struct ibtrs_clt, dev);

	ret = kstrtoint(buf, 10, &value);
	if (!ret && (value == MP_POLICY_RR || value == MP_POLICY_MIN_INFLIGHT)) {
		clt->mp_policy = value;
		return count;
	}

	if (!strncasecmp(buf, "round-robin", 11) ||
	    !strncasecmp(buf, "rr", 2))
		clt->mp_policy = MP_POLICY_RR;
	else if (!strncasecmp(buf, "min-inflight", 12) ||
		 !strncasecmp(buf, "mi", 2))
		clt->mp_policy = MP_POLICY_MIN_INFLIGHT;
	else
		return -EINVAL;

	return count;
}

static DEVICE_ATTR_RW(mpath_policy);

static ssize_t add_path_show(struct device *dev,
			     struct device_attribute *attr, char *page)
{
	return scnprintf(page, PAGE_SIZE, "Usage: echo"
			 " [<source addr>,]<destination addr> > %s\n\n"
			"*addr ::= [ ip:<ipv4|ipv6> | gid:<gid> ]\n",
			 attr->attr.name);
}

static ssize_t add_path_store(struct device *dev,
			      struct device_attribute *attr,
			      const char *buf, size_t count)
{
	struct sockaddr_storage srcaddr, dstaddr;
	struct ibtrs_addr addr = {
		.src = &srcaddr,
		.dst = &dstaddr
	};
	struct ibtrs_clt *clt;
	const char *nl;
	size_t len;
	int err;

	clt = container_of(dev, struct ibtrs_clt, dev);

	nl = strchr(buf, '\n');
	if (nl)
		len = nl - buf;
	else
		len = count;
	err = ibtrs_addr_to_sockaddr(buf, len, clt->port, &addr);
	if (unlikely(err))
		return -EINVAL;

	err = ibtrs_clt_create_path_from_sysfs(clt, &addr);
	if (unlikely(err))
		return err;

	return count;
}

static DEVICE_ATTR_RW(add_path);

static ssize_t ibtrs_clt_state_show(struct kobject *kobj,
				    struct kobj_attribute *attr, char *page)
{
	struct ibtrs_clt_sess *sess;

	sess = container_of(kobj, struct ibtrs_clt_sess, kobj);
	if (ibtrs_clt_sess_is_connected(sess))
		return sprintf(page, "connected\n");

	return sprintf(page, "disconnected\n");
}

static struct kobj_attribute ibtrs_clt_state_attr =
	__ATTR(state, 0444, ibtrs_clt_state_show, NULL);

static ssize_t ibtrs_clt_reconnect_show(struct kobject *kobj,
					struct kobj_attribute *attr,
					char *page)
{
	return scnprintf(page, PAGE_SIZE, "Usage: echo 1 > %s\n",
			 attr->attr.name);
}

static ssize_t ibtrs_clt_reconnect_store(struct kobject *kobj,
					 struct kobj_attribute *attr,
					 const char *buf, size_t count)
{
	struct ibtrs_clt_sess *sess;
	int ret;

	sess = container_of(kobj, struct ibtrs_clt_sess, kobj);
	if (!sysfs_streq(buf, "1")) {
		ibtrs_err(sess, "%s: unknown value: '%s'\n",
			  attr->attr.name, buf);
		return -EINVAL;
	}
	ret = ibtrs_clt_reconnect_from_sysfs(sess);
	if (unlikely(ret))
		return ret;

	return count;
}

static struct kobj_attribute ibtrs_clt_reconnect_attr =
	__ATTR(reconnect, 0644, ibtrs_clt_reconnect_show,
	       ibtrs_clt_reconnect_store);

static ssize_t ibtrs_clt_disconnect_show(struct kobject *kobj,
					 struct kobj_attribute *attr,
					 char *page)
{
	return scnprintf(page, PAGE_SIZE, "Usage: echo 1 > %s\n",
			 attr->attr.name);
}

static ssize_t ibtrs_clt_disconnect_store(struct kobject *kobj,
					  struct kobj_attribute *attr,
					  const char *buf, size_t count)
{
	struct ibtrs_clt_sess *sess;
	int ret;

	sess = container_of(kobj, struct ibtrs_clt_sess, kobj);
	if (!sysfs_streq(buf, "1")) {
		ibtrs_err(sess, "%s: unknown value: '%s'\n",
			  attr->attr.name, buf);
		return -EINVAL;
	}
	ret = ibtrs_clt_disconnect_from_sysfs(sess);
	if (unlikely(ret))
		return ret;

	return count;
}

static struct kobj_attribute ibtrs_clt_disconnect_attr =
	__ATTR(disconnect, 0644, ibtrs_clt_disconnect_show,
	       ibtrs_clt_disconnect_store);

static ssize_t ibtrs_clt_remove_path_show(struct kobject *kobj,
					  struct kobj_attribute *attr,
					  char *page)
{
	return scnprintf(page, PAGE_SIZE, "Usage: echo 1 > %s\n",
			 attr->attr.name);
}

static ssize_t ibtrs_clt_remove_path_store(struct kobject *kobj,
					   struct kobj_attribute *attr,
					   const char *buf, size_t count)
{
	struct ibtrs_clt_sess *sess;
	int ret;

	sess = container_of(kobj, struct ibtrs_clt_sess, kobj);
	if (!sysfs_streq(buf, "1")) {
		ibtrs_err(sess, "%s: unknown value: '%s'\n",
			  attr->attr.name, buf);
		return -EINVAL;
	}
	ret = ibtrs_clt_remove_path_from_sysfs(sess, &attr->attr);
	if (unlikely(ret))
		return ret;

	return count;
}

static struct kobj_attribute ibtrs_clt_remove_path_attr =
	__ATTR(remove_path, 0644, ibtrs_clt_remove_path_show,
	       ibtrs_clt_remove_path_store);

STAT_ATTR(struct ibtrs_clt_sess, cpu_migration,
	  ibtrs_clt_stats_migration_cnt_to_str,
	  ibtrs_clt_reset_cpu_migr_stats);

STAT_ATTR(struct ibtrs_clt_sess, sg_entries,
	  ibtrs_clt_stats_sg_list_distr_to_str,
	  ibtrs_clt_reset_sg_list_distr_stats);

STAT_ATTR(struct ibtrs_clt_sess, reconnects,
	  ibtrs_clt_stats_reconnects_to_str,
	  ibtrs_clt_reset_reconnects_stat);

STAT_ATTR(struct ibtrs_clt_sess, rdma_lat,
	  ibtrs_clt_stats_rdma_lat_distr_to_str,
	  ibtrs_clt_reset_rdma_lat_distr_stats);

STAT_ATTR(struct ibtrs_clt_sess, wc_completion,
	  ibtrs_clt_stats_wc_completion_to_str,
	  ibtrs_clt_reset_wc_comp_stats);

STAT_ATTR(struct ibtrs_clt_sess, rdma,
	  ibtrs_clt_stats_rdma_to_str,
	  ibtrs_clt_reset_rdma_stats);

STAT_ATTR(struct ibtrs_clt_sess, reset_all,
	  ibtrs_clt_reset_all_help,
	  ibtrs_clt_reset_all_stats);

static struct attribute *ibtrs_clt_stats_attrs[] = {
	&sg_entries_attr.attr,
	&cpu_migration_attr.attr,
	&reconnects_attr.attr,
	&rdma_lat_attr.attr,
	&wc_completion_attr.attr,
	&rdma_attr.attr,
	&reset_all_attr.attr,
	NULL,
};

static struct attribute_group ibtrs_clt_stats_attr_group = {
	.attrs = ibtrs_clt_stats_attrs,
};

static int ibtrs_clt_create_stats_files(struct kobject *kobj,
					struct kobject *kobj_stats)
{
	int ret;

	ret = kobject_init_and_add(kobj_stats, &ktype, kobj, "stats");
	if (ret) {
		pr_err("Failed to init and add stats kobject, err: %d\n",
		       ret);
		return ret;
	}

	ret = sysfs_create_group(kobj_stats, &ibtrs_clt_stats_attr_group);
	if (ret) {
		pr_err("failed to create stats sysfs group, err: %d\n",
		       ret);
		goto err;
	}

	return 0;

err:
	kobject_del(kobj_stats);
	kobject_put(kobj_stats);

	return ret;
}

static ssize_t ibtrs_clt_hca_port_show(struct kobject *kobj,
				       struct kobj_attribute *attr,
				       char *page)
{
	struct ibtrs_clt_sess *sess;

	sess = container_of(kobj, typeof(*sess), kobj);

	return scnprintf(page, PAGE_SIZE, "%u\n", sess->hca_port);
}

static struct kobj_attribute ibtrs_clt_hca_port_attr =
	__ATTR(hca_port, 0444, ibtrs_clt_hca_port_show, NULL);

static ssize_t ibtrs_clt_hca_name_show(struct kobject *kobj,
				       struct kobj_attribute *attr,
				       char *page)
{
	struct ibtrs_clt_sess *sess;

	sess = container_of(kobj, struct ibtrs_clt_sess, kobj);

	return scnprintf(page, PAGE_SIZE, "%s\n", sess->hca_name);
}

static struct kobj_attribute ibtrs_clt_hca_name_attr =
	__ATTR(hca_name, 0444, ibtrs_clt_hca_name_show, NULL);

static struct attribute *ibtrs_clt_sess_attrs[] = {
	&ibtrs_clt_hca_name_attr.attr,
	&ibtrs_clt_hca_port_attr.attr,
	&ibtrs_clt_state_attr.attr,
	&ibtrs_clt_reconnect_attr.attr,
	&ibtrs_clt_disconnect_attr.attr,
	&ibtrs_clt_remove_path_attr.attr,
	NULL,
};

static struct attribute_group ibtrs_clt_sess_attr_group = {
	.attrs = ibtrs_clt_sess_attrs,
};

int ibtrs_clt_create_sess_files(struct ibtrs_clt_sess *sess)
{
	struct ibtrs_clt *clt = sess->clt;
	char str[MAXHOSTNAMELEN];
	int err;

	sockaddr_to_str((struct sockaddr *)&sess->s.dst_addr, str, sizeof(str));

	err = kobject_init_and_add(&sess->kobj, &ktype, &clt->kobj_paths,
				   "%s", str);
	if (unlikely(err)) {
		pr_err("kobject_init_and_add: %d\n", err);
		return err;
	}
	err = sysfs_create_group(&sess->kobj, &ibtrs_clt_sess_attr_group);
	if (unlikely(err)) {
		pr_err("sysfs_create_group(): %d\n", err);
		goto put_kobj;
	}
	err = ibtrs_clt_create_stats_files(&sess->kobj, &sess->kobj_stats);
	if (unlikely(err))
		goto put_kobj;

	return 0;

put_kobj:
	kobject_del(&sess->kobj);
	kobject_put(&sess->kobj);

	return err;
}

void ibtrs_clt_destroy_sess_files(struct ibtrs_clt_sess *sess,
				  const struct attribute *sysfs_self)
{
	if (sess->kobj.state_in_sysfs) {
		kobject_del(&sess->kobj_stats);
		kobject_put(&sess->kobj_stats);
		if (sysfs_self)
			/* To avoid deadlock firstly commit suicide */
			sysfs_remove_file_self(&sess->kobj, sysfs_self);
		kobject_del(&sess->kobj);
		kobject_put(&sess->kobj);
	}
}

static struct attribute *ibtrs_clt_attrs[] = {
	&dev_attr_max_reconnect_attempts.attr,
	&dev_attr_mpath_policy.attr,
	&dev_attr_add_path.attr,
	NULL,
};

static struct attribute_group ibtrs_clt_attr_group = {
	.attrs = ibtrs_clt_attrs,
};

int ibtrs_clt_create_sysfs_root_folders(struct ibtrs_clt *clt)
{
	return kobject_init_and_add(&clt->kobj_paths, &ktype,
				    &clt->dev.kobj, "paths");
}

int ibtrs_clt_create_sysfs_root_files(struct ibtrs_clt *clt)
{
	return sysfs_create_group(&clt->dev.kobj, &ibtrs_clt_attr_group);
}

void ibtrs_clt_destroy_sysfs_root_folders(struct ibtrs_clt *clt)
{
	if (clt->kobj_paths.state_in_sysfs) {
		kobject_del(&clt->kobj_paths);
		kobject_put(&clt->kobj_paths);
	}
}

void ibtrs_clt_destroy_sysfs_root_files(struct ibtrs_clt *clt)
{
	sysfs_remove_group(&clt->dev.kobj, &ibtrs_clt_attr_group);
}
