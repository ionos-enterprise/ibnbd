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

#include "ibtrs-pri.h"
#include "ibtrs-srv.h"
#include "ibtrs-log.h"

static struct kobject *ibtrs_kobj;

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

	sess = container_of(kobj, struct ibtrs_srv_sess, kobj);
	if (!sysfs_streq(buf, "1")) {
		ibtrs_err(sess, "%s: invalid value: '%s'\n", attr->attr.name, buf);
		return -EINVAL;
	}

	ibtrs_info(sess, "%s: Session disconnect requested\n", attr->attr.name);
	ibtrs_srv_queue_close(sess);

	return count;
}

static struct kobj_attribute disconnect_attr =
	__ATTR(disconnect, 0644,
	       ibtrs_srv_disconnect_show, ibtrs_srv_disconnect_store);

static ssize_t ibtrs_srv_current_hca_port_show(struct kobject *kobj,
					       struct kobj_attribute *attr,
					       char *page)
{
	struct ibtrs_srv_sess *sess;

	sess = container_of(kobj, struct ibtrs_srv_sess, kobj);

	return ibtrs_srv_current_hca_port_to_str(sess, page, PAGE_SIZE);
}

static struct kobj_attribute current_hca_port_attr =
	__ATTR(current_hca_port, 0444, ibtrs_srv_current_hca_port_show,
	       NULL);

static ssize_t ibtrs_srv_hca_name_show(struct kobject *kobj,
				       struct kobj_attribute *attr,
				       char *page)
{
	struct ibtrs_srv_sess *sess;

	sess = container_of(kobj, struct ibtrs_srv_sess, kobj);

	return scnprintf(page, PAGE_SIZE, "%s\n",
			 ibtrs_srv_get_sess_hca_name(sess));
}

static struct kobj_attribute hca_name_attr =
	__ATTR(hca_name, 0444, ibtrs_srv_hca_name_show, NULL);

static struct attribute *default_sess_attrs[] = {
	&hca_name_attr.attr,
	&current_hca_port_attr.attr,
	&disconnect_attr.attr,
	NULL,
};

static struct attribute_group default_sess_attr_group = {
	.attrs = default_sess_attrs,
};

STAT_ATTR(struct ibtrs_srv_sess, rdma,
	  ibtrs_srv_stats_rdma_to_str,
	  ibtrs_srv_reset_rdma_stats);

STAT_ATTR(struct ibtrs_srv_sess, user_ib_messages,
	  ibtrs_srv_stats_user_ib_msgs_to_str,
	  ibtrs_srv_reset_user_ib_msgs_stats);

STAT_ATTR(struct ibtrs_srv_sess, wc_completion,
	  ibtrs_srv_stats_wc_completion_to_str,
	  ibtrs_srv_reset_wc_completion_stats);

STAT_ATTR(struct ibtrs_srv_sess, reset_all,
	  ibtrs_srv_reset_all_help,
	  ibtrs_srv_reset_all_stats);

static struct attribute *ibtrs_srv_default_stats_attrs[] = {
	&rdma_attr.attr,
	&user_ib_messages_attr.attr,
	&wc_completion_attr.attr,
	&reset_all_attr.attr,
	NULL,
};

static struct attribute_group ibtrs_srv_default_stats_attr_group = {
	.attrs = ibtrs_srv_default_stats_attrs,
};

static int ibtrs_srv_create_stats_files(struct ibtrs_srv_sess *sess)
{
	int ret;

	ret = kobject_init_and_add(&sess->kobj_stats, &ktype,
				   &sess->kobj, "stats");
	if (ret) {
		ibtrs_err(sess,
			  "Failed to init and add sysfs directory for session stats,"
			  " err: %d\n", ret);
		return ret;
	}

	ret = sysfs_create_group(&sess->kobj_stats,
				 &ibtrs_srv_default_stats_attr_group);
	if (ret) {
		ibtrs_err(sess, "Failed to create sysfs group for session stats,"
			  " err: %d\n", ret);
		goto err;
	}

	return 0;

err:
	kobject_put(&sess->kobj_stats);

	return ret;
}

int ibtrs_srv_create_sess_files(struct ibtrs_srv_sess *sess)
{
	int ret;

	ret = kobject_init_and_add(&sess->kobj, &ktype, ibtrs_kobj,
				   "%s", sess->s.sessname);
	if (ret) {
		ibtrs_err(sess, "Failed to init and add sysfs directory for session,"
			  " err: %d\n", ret);
		return ret;
	}

	ret = sysfs_create_group(&sess->kobj, &default_sess_attr_group);
	if (ret) {
		ibtrs_err(sess, "Failed to create sysfs group for session,"
			  " err: %d\n", ret);
		goto err;
	}

	ret = ibtrs_srv_create_stats_files(sess);
	if (ret)
		goto err1;

	return 0;

err1:
	sysfs_remove_group(&sess->kobj, &default_sess_attr_group);
err:
	kobject_del(&sess->kobj);
	kobject_put(&sess->kobj);

	return ret;
}

void ibtrs_srv_destroy_sess_files(struct ibtrs_srv_sess *sess)
{
	if (sess->kobj.state_in_sysfs) {
		kobject_del(&sess->kobj_stats);
		kobject_put(&sess->kobj_stats);
		kobject_del(&sess->kobj);
		kobject_put(&sess->kobj);
	}
}

int ibtrs_srv_create_sysfs_module_files(void)
{
	ibtrs_kobj = kobject_create_and_add(KBUILD_MODNAME, kernel_kobj);
	if (unlikely(!ibtrs_kobj))
		return -ENOMEM;

	return 0;
}

void ibtrs_srv_destroy_sysfs_module_files(void)
{
	kobject_del(ibtrs_kobj);
	kobject_put(ibtrs_kobj);
}
