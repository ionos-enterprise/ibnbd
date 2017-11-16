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

#undef pr_fmt
#define pr_fmt(fmt) KBUILD_MODNAME " L" __stringify(__LINE__) ": " fmt

#include <linux/types.h>
#include <rdma/ibtrs.h>

#include "ibtrs-pri.h"
#include "ibtrs-clt.h"
#include "ibtrs-log.h"

static struct kobject *ibtrs_kobj;

#define MIN_MAX_RECONN_ATT -1
#define MAX_MAX_RECONN_ATT 9999

static struct kobj_type ktype = {
	.sysfs_ops = &kobj_sysfs_ops,
};

static ssize_t ibtrs_clt_max_reconn_attempts_show(struct kobject *kobj,
						  struct kobj_attribute *attr,
						  char *page)
{
	struct ibtrs_clt *clt;

	clt = container_of(kobj, struct ibtrs_clt, kobj);

	return sprintf(page, "%d\n", ibtrs_clt_get_max_reconnect_attempts(clt));
}

static ssize_t ibtrs_clt_max_reconn_attempts_store(struct kobject *kobj,
						   struct kobj_attribute *attr,
						   const char *buf,
						   size_t count)
{
	struct ibtrs_clt *clt;
	int value;
	int ret;

	clt = container_of(kobj, struct ibtrs_clt, kobj);

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

static struct kobj_attribute ibtrs_clt_max_reconnect_attempts_attr =
	__ATTR(max_reconnect_attempts, 0644,
	       ibtrs_clt_max_reconn_attempts_show,
	       ibtrs_clt_max_reconn_attempts_store);

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
					struct kobj_attribute *attr, char *page)
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
		ibtrs_err(sess, "%s: unknown value: '%s'\n", attr->attr.name, buf);
		return -EINVAL;
	}

	ret = ibtrs_clt_reconnect(sess);
	if (ret) {
		ibtrs_err(sess, "%s: failed to reconnect session, err: %d\n",
			  attr->attr.name, ret);
		return ret;
	}
	return count;
}

static struct kobj_attribute ibtrs_clt_reconnect_attr =
	__ATTR(reconnect, 0644, ibtrs_clt_reconnect_show,
	       ibtrs_clt_reconnect_store);

static ssize_t ibtrs_clt_add_path_show(struct kobject *kobj,
				       struct kobj_attribute *attr, char *page)
{
	return scnprintf(page, PAGE_SIZE, "Usage: echo"
			 " [<source addr>,]<destination addr> > %s\n\n"
			"*addr ::= [ ip:<ipv4|ipv6> | gid:<gid> ]\n",
			 attr->attr.name);
}

static ssize_t ibtrs_clt_add_path_store(struct kobject *kobj,
					struct kobj_attribute *attr,
					const char *buf, size_t count)
{
	struct sockaddr_storage srcaddr, dstaddr;
	struct ibtrs_addr addr = {
		.src = (struct sockaddr *)&srcaddr,
		.dst = (struct sockaddr *)&dstaddr
	};
	struct ibtrs_clt *clt;
	int ret;

	clt = container_of(kobj, struct ibtrs_clt, kobj);

	ret = ibtrs_addr_to_sockaddr(buf, clt->port, &addr);
	if (unlikely(ret))
		return -EINVAL;

	return 0;
}

static struct kobj_attribute ibtrs_clt_add_path_attr =
	__ATTR(add_path, 0644, ibtrs_clt_add_path_show,
	       ibtrs_clt_add_path_store);

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

STAT_ATTR(struct ibtrs_clt_sess, user_ib_messages,
	  ibtrs_clt_stats_user_ib_msgs_to_str,
	  ibtrs_clt_reset_user_ib_msgs_stats);

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
	&user_ib_messages_attr.attr,
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

static struct attribute *ibtrs_clt_sess_attrs[] = {
	&ibtrs_clt_state_attr.attr,
	&ibtrs_clt_reconnect_attr.attr,
	NULL,
};

static struct attribute_group ibtrs_clt_sess_attr_group = {
	.attrs = ibtrs_clt_sess_attrs,
};

int ibtrs_clt_create_sess_files(struct ibtrs_clt_sess *sess)
{
	int ret;

	ret = kobject_init_and_add(&sess->kobj, &ktype,
				   ibtrs_kobj, "%s", sess->s.sessname);
	if (ret) {
		pr_err("Failed to create session kobject, err: %d\n",
		       ret);
		return ret;
	}

	ret = sysfs_create_group(&sess->kobj, &ibtrs_clt_sess_attr_group);
	if (ret) {
		pr_err("Failed to create session sysfs group, err: %d\n",
		       ret);
		goto err;
	}

	ret = ibtrs_clt_create_stats_files(&sess->kobj, &sess->kobj_stats);
	if (ret) {
		pr_err("Failed to create stats files, err: %d\n",
		       ret);
		goto err1;
	}

	return 0;

err1:
	sysfs_remove_group(&sess->kobj, &ibtrs_clt_sess_attr_group);
err:
	kobject_del(&sess->kobj);
	kobject_put(&sess->kobj);

	return ret;
}

void ibtrs_clt_destroy_sess_files(struct ibtrs_clt_sess *sess)
{
	if (sess->kobj.state_in_sysfs) {
		kobject_del(&sess->kobj_stats);
		kobject_put(&sess->kobj_stats);
		kobject_del(&sess->kobj);
		kobject_put(&sess->kobj);
	}
}

static struct attribute *ibtrs_clt_attrs[] = {
	&ibtrs_clt_max_reconnect_attempts_attr.attr,
	&ibtrs_clt_add_path_attr.attr,
	NULL,
};

static struct attribute_group ibtrs_clt_attr_group = {
	.attrs = ibtrs_clt_attrs,
};

int ibtrs_clt_create_sysfs_root_folders(struct ibtrs_clt *clt)
{
	int err;

	err = kobject_init_and_add(&clt->kobj, &ktype, ibtrs_kobj,
				   "%s", clt->sessname);
	if (unlikely(err)) {
		pr_err("kobject_init_and_add(): %d\n", err);
		return err;
	}
	err = kobject_init_and_add(&clt->kobj_paths, &ktype,
				   &clt->kobj, "paths");
	if (unlikely(err)) {
		pr_err("kobject_init_and_add(): %d\n", err);
		goto put_kobj;
	}

	return 0;

put_kobj:
	kobject_del(&clt->kobj);
	kobject_put(&clt->kobj);

	return err;
}

int ibtrs_clt_create_sysfs_root_files(struct ibtrs_clt *clt)
{
	return sysfs_create_group(&clt->kobj, &ibtrs_clt_attr_group);
}

void ibtrs_clt_destroy_sysfs_root_folders(struct ibtrs_clt *clt)
{
	kobject_del(&clt->kobj_paths);
	kobject_put(&clt->kobj_paths);
	kobject_del(&clt->kobj);
	kobject_put(&clt->kobj);
}

void ibtrs_clt_destroy_sysfs_root_files(struct ibtrs_clt *clt)
{
	sysfs_remove_group(&clt->kobj, &ibtrs_clt_attr_group);
}

int ibtrs_clt_create_sysfs_module_files(void)
{
	ibtrs_kobj = kobject_create_and_add(KBUILD_MODNAME, kernel_kobj);
	if (unlikely(!ibtrs_kobj))
		return -ENOMEM;

	return 0;
}

void ibtrs_clt_destroy_sysfs_module_files(void)
{
	kobject_del(ibtrs_kobj);
	kobject_put(ibtrs_kobj);
}
