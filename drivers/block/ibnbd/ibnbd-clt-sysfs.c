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

#undef pr_fmt
#define pr_fmt(fmt) KBUILD_MODNAME " L" __stringify(__LINE__) ": " fmt

#include <linux/types.h>
#include <linux/ctype.h>
#include <linux/parser.h>
#include <linux/module.h>
#include <linux/in6.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <rdma/ib.h>
#include <rdma/rdma_cm.h>

#include "ibnbd-clt-sysfs.h"
#include "ibnbd-clt.h"

static struct kobject *ibnbd_kobject;
static struct kobject *ibnbd_devices_kobject;
static DEFINE_MUTEX(sess_lock);

struct ibnbd_clt_dev_destroy_kobj_work {
	struct ibnbd_clt_dev	*dev;
	struct work_struct	work;
};

enum {
	IBNBD_OPT_ERR		= 0,
	IBNBD_OPT_SERVER	= 1 << 0,
	IBNBD_OPT_DEV_PATH	= 1 << 1,
	IBNBD_OPT_ACCESS_MODE	= 1 << 3,
	IBNBD_OPT_INPUT_MODE	= 1 << 4,
	IBNBD_OPT_IO_MODE	= 1 << 5,
	IBNBD_OPT_SESSNAME	= 1 << 6,
};

static unsigned ibnbd_opt_mandatory[] = {
	IBNBD_OPT_SERVER,
	IBNBD_OPT_DEV_PATH,
	IBNBD_OPT_SESSNAME,
};

static const match_table_t ibnbd_opt_tokens = {
	{	IBNBD_OPT_SERVER,	"server=%s"		},
	{	IBNBD_OPT_DEV_PATH,	"device_path=%s"	},
	{	IBNBD_OPT_ACCESS_MODE,	"access_mode=%s"	},
	{	IBNBD_OPT_INPUT_MODE,	"input_mode=%s"		},
	{	IBNBD_OPT_IO_MODE,	"io_mode=%s"		},
	{	IBNBD_OPT_SESSNAME,	"sessname=%s"		},
	{	IBNBD_OPT_ERR,		NULL			},
};

/* remove new line from string */
static void strip(char *s)
{
	char *p = s;

	while (*s != '\0') {
		if (*s != '\n')
			*p++ = *s++;
		else
			++s;
	}
	*p = '\0';
}

static int ibnbd_clt_parse_map_options(const char *buf,
				       char *sessname,
				       char *server_addr,
				       char *pathname,
				       enum ibnbd_access_mode *access_mode,
				       enum ibnbd_queue_mode *queue_mode,
				       enum ibnbd_io_mode *io_mode)
{
	char *options, *sep_opt;
	char *p;
	substring_t args[MAX_OPT_ARGS];
	int opt_mask = 0;
	int token;
	int ret = -EINVAL;
	int i;

	options = kstrdup(buf, GFP_KERNEL);
	if (!options)
		return -ENOMEM;

	options = strstrip(options);
	strip(options);
	sep_opt = options;
	while ((p = strsep(&sep_opt, " ")) != NULL) {
		if (!*p)
			continue;

		token = match_token(p, ibnbd_opt_tokens, args);
		opt_mask |= token;

		switch (token) {
		case IBNBD_OPT_SESSNAME:
			p = match_strdup(args);
			if (!p) {
				ret = -ENOMEM;
				goto out;
			}
			if (strlen(p) > MAXHOSTNAMELEN) {
				pr_err("map_device: source name too long\n");
				ret = -EINVAL;
				goto out;
			}
			strlcpy(sessname, p, MAXHOSTNAMELEN);
			kfree(p);
			break;

		case IBNBD_OPT_SERVER:
			p = match_strdup(args);
			if (!p) {
				ret = -ENOMEM;
				goto out;
			}
			if (strlen(p) > MAXHOSTNAMELEN) {
				pr_err("map_device: Server address too long\n");
				ret = -EINVAL;
				goto out;
			}
			strlcpy(server_addr, p, MAXHOSTNAMELEN);
			kfree(p);
			break;

		case IBNBD_OPT_DEV_PATH:
			p = match_strdup(args);
			if (!p) {
				ret = -ENOMEM;
				goto out;
			}
			if (strlen(p) > NAME_MAX) {
				pr_err("map_device: Device path too long\n");
				ret = -EINVAL;
				goto out;
			}
			strlcpy(pathname, p, NAME_MAX);
			kfree(p);
			break;

		case IBNBD_OPT_ACCESS_MODE:
			p = match_strdup(args);
			if (!p) {
				ret = -ENOMEM;
				goto out;
			}

			if (!strcmp(p, "ro")) {
				*access_mode = IBNBD_ACCESS_RO;
			} else if (!strcmp(p, "rw")) {
				*access_mode = IBNBD_ACCESS_RW;
			} else if (!strcmp(p, "migration")) {
				*access_mode = IBNBD_ACCESS_MIGRATION;
			} else {
				pr_err("map_device: Invalid access_mode:"
				       " '%s'\n", p);
				ret = -EINVAL;
				kfree(p);
				goto out;
			}

			kfree(p);
			break;

		case IBNBD_OPT_INPUT_MODE:
			p = match_strdup(args);
			if (!p) {
				ret = -ENOMEM;
				goto out;
			}
			if (!strcmp(p, "mq")) {
				*queue_mode = BLK_MQ;
			} else if (!strcmp(p, "rq")) {
				*queue_mode = BLK_RQ;
			} else {
				pr_err("map_device: Invalid input_mode: "
				       "'%s'.\n", p);
				ret = -EINVAL;
				kfree(p);
				goto out;
			}
			kfree(p);
			break;

		case IBNBD_OPT_IO_MODE:
			p = match_strdup(args);
			if (!p) {
				ret = -ENOMEM;
				goto out;
			}
			if (!strcmp(p, "blockio")) {
				*io_mode = IBNBD_BLOCKIO;
			} else if (!strcmp(p, "fileio")) {
				*io_mode = IBNBD_FILEIO;
			} else {
				pr_err("map_device: Invalid io_mode: '%s'.\n",
				       p);
				ret = -EINVAL;
				kfree(p);
				goto out;
			}
			kfree(p);
			break;

		default:
			pr_err("map_device: Unknown parameter or missing value"
			       " '%s'\n", p);
			ret = -EINVAL;
			goto out;
		}
	}

	for (i = 0; i < ARRAY_SIZE(ibnbd_opt_mandatory); i++) {
		if ((opt_mask & ibnbd_opt_mandatory[i])) {
			ret = 0;
		} else {
			pr_err("map_device: Parameters missing\n");
			ret = -EINVAL;
			break;
		}
	}

out:
	kfree(options);
	return ret;
}

int ibnbd_clt_get_sess(struct ibnbd_clt_session *sess)
{
	return kref_get_unless_zero(&sess->refcount);
}

void ibnbd_clt_put_sess(struct ibnbd_clt_session *sess)
{
	mutex_lock(&sess_lock);
	kref_put(&sess->refcount, ibnbd_clt_sess_release);
	mutex_unlock(&sess_lock);
}

static void ibnbd_clt_dev_destroy_kobjs(struct ibnbd_clt_dev *dev)
{
	kobject_del(&dev->kobj);
	kobject_put(&dev->kobj);
}

static ssize_t ibnbd_clt_state_show(struct kobject *kobj,
				    struct kobj_attribute *attr, char *page)
{
	struct ibnbd_clt_dev *dev;

	dev = container_of(kobj, struct ibnbd_clt_dev, kobj);

	switch (dev->dev_state) {
	case (DEV_STATE_INIT):
		return scnprintf(page, PAGE_SIZE, "init\n");
	case (DEV_STATE_OPEN):
		return scnprintf(page, PAGE_SIZE, "open\n");
	case (DEV_STATE_CLOSED):
		return scnprintf(page, PAGE_SIZE, "closed\n");
	case (DEV_STATE_UNMAPPED):
		return scnprintf(page, PAGE_SIZE, "unmapped\n");
	default:
		return scnprintf(page, PAGE_SIZE, "unknown\n");
	}
}

static struct kobj_attribute ibnbd_clt_state_attr =
	__ATTR(state, 0444, ibnbd_clt_state_show, NULL);

static ssize_t ibnbd_clt_input_mode_show(struct kobject *kobj,
					 struct kobj_attribute *attr,
					 char *page)
{
	struct ibnbd_clt_dev *dev;

	dev = container_of(kobj, struct ibnbd_clt_dev, kobj);

	return scnprintf(page, PAGE_SIZE, "%s\n",
			 ibnbd_queue_mode_str(dev->queue_mode));
}

static struct kobj_attribute ibnbd_clt_input_mode_attr =
	__ATTR(input_mode, 0444, ibnbd_clt_input_mode_show, NULL);

static ssize_t ibnbd_clt_mapping_path_show(struct kobject *kobj,
					   struct kobj_attribute *attr,
					   char *page)
{
	struct ibnbd_clt_dev *dev;

	dev = container_of(kobj, struct ibnbd_clt_dev, kobj);

	return scnprintf(page, PAGE_SIZE, "%s\n", dev->pathname);
}

static struct kobj_attribute ibnbd_clt_mapping_path_attr =
	__ATTR(mapping_path, 0444, ibnbd_clt_mapping_path_show, NULL);

static ssize_t ibnbd_clt_io_mode_show(struct kobject *kobj,
				      struct kobj_attribute *attr, char *page)
{
	struct ibnbd_clt_dev *dev;

	dev = container_of(kobj, struct ibnbd_clt_dev, kobj);

	return scnprintf(page, PAGE_SIZE, "%s\n",
			 ibnbd_io_mode_str(dev->remote_io_mode));
}

static struct kobj_attribute ibnbd_clt_io_mode =
	__ATTR(io_mode, 0444, ibnbd_clt_io_mode_show, NULL);

static ssize_t ibnbd_clt_unmap_dev_show(struct kobject *kobj,
					struct kobj_attribute *attr, char *page)
{
	return scnprintf(page, PAGE_SIZE, "Usage: echo <normal|force> > %s\n",
			 attr->attr.name);
}

static void ibnbd_clt_dev_kobj_destroy_worker(struct work_struct *work)
{
	struct ibnbd_clt_dev_destroy_kobj_work *destroy_work;
	struct ibnbd_clt_dev *dev;

	destroy_work = container_of(work,
				    struct ibnbd_clt_dev_destroy_kobj_work,
				    work);
	dev = destroy_work->dev;
	kobject_get(&dev->kobj);
	ibnbd_clt_dev_destroy_kobjs(dev);
	kobject_put(&dev->kobj);
	kfree(destroy_work);
}

void ibnbd_clt_schedule_dev_destroy(struct ibnbd_clt_dev *dev)
{
	struct ibnbd_clt_dev_destroy_kobj_work *destroy_work = NULL;

	/* memory allocation cannot fail, otherwise the last reference to the
	 * session will never be put
	 */
	while (!destroy_work) {
		destroy_work = kmalloc(sizeof(*destroy_work),
				       (GFP_KERNEL | __GFP_RETRY_MAYFAIL));
		if (!destroy_work)
			cond_resched();
	}

	destroy_work->dev = dev;
	INIT_WORK(&destroy_work->work, ibnbd_clt_dev_kobj_destroy_worker);
	if (WARN(!schedule_work(&destroy_work->work),
		 "failed to schedule work\n"))
		kfree(destroy_work);
}

static ssize_t ibnbd_clt_unmap_dev_store(struct kobject *kobj,
					 struct kobj_attribute *attr,
					 const char *buf, size_t count)
{
	int err;
	struct ibnbd_clt_dev *dev;
	bool force;
	char *options;

	if (!try_module_get(THIS_MODULE))
		return -ENODEV;
	options = kstrdup(buf, GFP_KERNEL);
	if (!options)
		return -ENOMEM;

	options = strstrip(options);
	strip(options);

	dev = container_of(kobj, struct ibnbd_clt_dev, kobj);

	if (dev->dev_state == DEV_STATE_UNMAPPED) {
		err = -EALREADY;
		goto out;
	}

	if (sysfs_streq(options, "normal")) {
		force = false;
	} else if (sysfs_streq(options, "force")) {
		force = true;
	} else {
		ibnbd_err(dev, "unmap_device: Invalid value: %s\n", options);
		err = -EINVAL;
		goto out;
	}

	ibnbd_info(dev, "Unmapping device, option: %s.\n",
		   force ? "force" : "normal");

	err = ibnbd_close_device(dev, force);
	if (err) {
		ibnbd_err(dev, "unmap_device: Failed to close device, err: %d\n",
			  err);
		goto out;
	}

	wait_for_completion(dev->close_compl);

	ibnbd_clt_schedule_dev_destroy(dev);

	module_put(THIS_MODULE);
	kfree(options);
	return count;
out:
	module_put(THIS_MODULE);
	kfree(options);
	return err;
}

static struct kobj_attribute ibnbd_clt_unmap_device_attr =
	__ATTR(unmap_device, 0644, ibnbd_clt_unmap_dev_show,
	       ibnbd_clt_unmap_dev_store);

static ssize_t ibnbd_clt_remap_dev_show(struct kobject *kobj,
					struct kobj_attribute *attr, char *page)
{
	return scnprintf(page, PAGE_SIZE, "Usage: echo <1> > %s\n",
			 attr->attr.name);
}

static ssize_t ibnbd_clt_remap_dev_store(struct kobject *kobj,
					 struct kobj_attribute *attr,
					 const char *buf, size_t count)
{
	int err;
	struct ibnbd_clt_dev *dev;
	char *options;

	options = kstrdup(buf, GFP_KERNEL);
	if (!options)
		return -ENOMEM;

	options = strstrip(options);
	strip(options);

	dev = container_of(kobj, struct ibnbd_clt_dev, kobj);
	if (!sysfs_streq(options, "1")) {
		ibnbd_err(dev, "remap_device: Invalid value: %s\n", options);
		err = -EINVAL;
		goto out;
	}

	mutex_lock(&dev->lock);
	if (dev->dev_state == DEV_STATE_UNMAPPED) {
		err = -EIO;
		mutex_unlock(&dev->lock);
		goto out;
	} else if (dev->dev_state == DEV_STATE_OPEN) {
		mutex_unlock(&dev->lock);
		goto out1;
	} else if (dev->dev_state == DEV_STATE_CLOSED) {
		mutex_unlock(&dev->lock);
		ibnbd_info(dev, "Remapping device.\n");

		err = open_remote_device(dev);
		if (err) {
			ibnbd_err(dev, "remap_device: Failed to remap device,"
				  " err: %d\n", err);
			goto out;
		}
	}

out1:
	kfree(options);
	return count;
out:
	kfree(options);
	return err;
}

static struct kobj_attribute ibnbd_clt_remap_device_attr =
	__ATTR(remap_device, 0644, ibnbd_clt_remap_dev_show,
	       ibnbd_clt_remap_dev_store);

static ssize_t ibnbd_clt_session_show(struct kobject *kobj,
				      struct kobj_attribute *attr,
				      char *page)
{
	struct ibnbd_clt_dev *dev;

	dev = container_of(kobj, struct ibnbd_clt_dev, kobj);

	return scnprintf(page, PAGE_SIZE, "%s\n", dev->sess->sessname);
}

static struct kobj_attribute ibnbd_clt_session_attr =
	__ATTR(session, 0444, ibnbd_clt_session_show, NULL);

static struct attribute *ibnbd_dev_attrs[] = {
	&ibnbd_clt_unmap_device_attr.attr,
	&ibnbd_clt_remap_device_attr.attr,
	&ibnbd_clt_mapping_path_attr.attr,
	&ibnbd_clt_state_attr.attr,
	&ibnbd_clt_input_mode_attr.attr,
	&ibnbd_clt_session_attr.attr,
	&ibnbd_clt_io_mode.attr,
	NULL,
};

void ibnbd_clt_remove_dev_symlink(struct ibnbd_clt_dev *dev)
{
	if (strlen(dev->blk_symlink_name))
		sysfs_remove_link(ibnbd_devices_kobject, dev->blk_symlink_name);
}

static void ibnbd_clt_dev_release(struct kobject *kobj)
{
	struct ibnbd_clt_dev *dev;

	dev = container_of(kobj, struct ibnbd_clt_dev, kobj);
	ibnbd_destroy_gen_disk(dev);
}

static struct kobj_type ibnbd_dev_ktype = {
	.sysfs_ops      = &kobj_sysfs_ops,
	.default_attrs  = ibnbd_dev_attrs,
	.release	= ibnbd_clt_dev_release,
};

static int ibnbd_clt_add_dev_kobj(struct ibnbd_clt_dev *dev)
{
	int ret;
	struct kobject *gd_kobj = &disk_to_dev(dev->gd)->kobj;

	ret = kobject_init_and_add(&dev->kobj, &ibnbd_dev_ktype, gd_kobj, "%s",
				   "ibnbd");
	if (ret)
		ibnbd_err(dev, "Failed to create device sysfs dir, err: %d\n",
			  ret);

	return ret;
}

static int ibnbd_clt_str_ipv4_to_sockaddr(const char *con_addr,
					  struct sockaddr *dst)
{
	int ret;
	char ipaddr[INET6_ADDRSTRLEN];
	struct sockaddr_in *dst_sin = (struct sockaddr_in *)dst;
	u8 ip4[4];

	strlcpy(ipaddr, &con_addr[IP_PREFIX_LEN], sizeof(ipaddr));

	ret = in4_pton(ipaddr, strlen(ipaddr), ip4, '\0', NULL);
	if (ret == 0)
		return -EINVAL;

	memcpy(&dst_sin->sin_addr.s_addr, ip4,
	       sizeof(dst_sin->sin_addr.s_addr));
	dst_sin->sin_family = AF_INET;
	dst_sin->sin_port = htons(IBTRS_PORT);

	return 0;
}

static int ibnbd_clt_str_ipv6_to_sockaddr(const char *con_addr,
					  struct sockaddr *dst)
{
	int ret;
	char ipaddr[INET6_ADDRSTRLEN];
	struct sockaddr_in6 *dst_sin6 = (struct sockaddr_in6 *)dst;

	strlcpy(ipaddr, &con_addr[IP_PREFIX_LEN], sizeof(ipaddr));

	ret = in6_pton(ipaddr, strlen(ipaddr),
		       dst_sin6->sin6_addr.s6_addr,
		       '\0', NULL);
	if (ret != 1)
		return -EINVAL;

	dst_sin6->sin6_family = AF_INET6;
	dst_sin6->sin6_port = htons(IBTRS_PORT);

	return 0;
}

static int ibnbd_clt_str_gid_to_sockaddr(const char *con_addr,
					 struct sockaddr *dst)
{
	int ret;
	char gid[INET6_ADDRSTRLEN];
	struct sockaddr_ib *dst_ib = (struct sockaddr_ib *)dst;

	strlcpy(gid, &con_addr[GID_PREFIX_LEN], sizeof(gid));

	/* We can use some of the I6 functions since GID is a valid
	 * IPv6 address format
	 */
	ret = in6_pton(gid, strlen(gid),
		       dst_ib->sib_addr.sib_raw, '\0', NULL);
	if (ret == 0)
		return -EINVAL;

	dst_ib->sib_family = AF_IB;
	/*
	 * Use the same TCP server port number as the IB service ID
	 * on the IB port space range
	 */
	dst_ib->sib_sid = cpu_to_be64(RDMA_IB_IP_PS_IB | IBTRS_PORT);
	dst_ib->sib_sid_mask = cpu_to_be64(0xffffffffffffffffULL);
	dst_ib->sib_pkey = cpu_to_be16(0xffff);

	return 0;
}

static int ibnbd_clt_str_to_sockaddr(char *addr, struct sockaddr *sockaddr)
{
	if (strncmp(addr, GID_PREFIX, GID_PREFIX_LEN) == 0) {
		return ibnbd_clt_str_gid_to_sockaddr(addr, sockaddr);
	} else if (strncmp(addr, IP_PREFIX, IP_PREFIX_LEN) == 0) {
		if (ibnbd_clt_str_ipv4_to_sockaddr(addr, sockaddr))
			return ibnbd_clt_str_ipv6_to_sockaddr(addr, sockaddr);
		else
			return 0;
	}
	return -EPROTONOSUPPORT;
}

static struct ibnbd_clt_session *
ibnbd_clt_get_create_sess(const char *sessname, struct sockaddr *sockaddr)
{
	struct ibnbd_clt_session *sess;

	mutex_lock(&sess_lock);
	sess = ibnbd_clt_find_sess(sessname);
	if (sess) {
		if (sess->state != CLT_SESS_STATE_READY ||
		    !ibnbd_clt_get_sess(sess)) {
			pr_err("Session is not connected or "
			       "is being destroyed\n");
			sess = ERR_PTR(-EIO);
		}
	} else {
		sess = ibnbd_create_session(sessname, sockaddr);
	}
	mutex_unlock(&sess_lock);

	return sess;
}

static ssize_t ibnbd_clt_map_device_show(struct kobject *kobj,
					 struct kobj_attribute *attr,
					 char *page)
{
	return scnprintf(page, PAGE_SIZE, "Usage: echo \"server=<address>"
			 " sessname=<name of the ibtrs session>"
			 " device_path=<full path on remote side>"
			 " [access_mode=<ro|rw|migration>]"
			 " [input_mode=<mq|rq>]"
			 " [io_mode=<fileio|blockio>]\" > %s\n\n"
			 "address ::= [ ip:<ipv4> | ip:<ipv6> | gid:<gid> ]\n",
			 attr->attr.name);
}

static int ibnbd_clt_get_path_name(struct ibnbd_clt_dev *dev, char *buf,
				   size_t len)
{
	int ret;
	char pathname[NAME_MAX], *s;

	strlcpy(pathname, dev->pathname, sizeof(pathname));
	while ((s = strchr(pathname, '/')))
		s[0] = '!';

	ret = snprintf(buf, len, "%s", pathname);
	if (ret >= len)
		return -ENAMETOOLONG;

	return 0;
}

static int ibnbd_clt_add_dev_symlink(struct ibnbd_clt_dev *dev)
{
	struct kobject *gd_kobj = &disk_to_dev(dev->gd)->kobj;
	int ret;

	ret = ibnbd_clt_get_path_name(dev, dev->blk_symlink_name,
				      sizeof(dev->blk_symlink_name));
	if (ret) {
		ibnbd_err(dev, "Failed to get /sys/block symlink path, err: %d\n",
			  ret);
		goto out_err;
	}

	ret = sysfs_create_link(ibnbd_devices_kobject, gd_kobj,
				dev->blk_symlink_name);
	if (ret) {
		ibnbd_err(dev, "Creating /sys/block symlink failed, err: %d\n",
			  ret);
		goto out_err;
	}

	return 0;

out_err:
	dev->blk_symlink_name[0] = '\0';
	return ret;
}

static ssize_t ibnbd_clt_map_device_store(struct kobject *kobj,
					  struct kobj_attribute *attr,
					  const char *buf, size_t count)
{
	struct ibnbd_clt_session *sess;
	struct ibnbd_clt_dev *dev;
	int ret;
	char pathname[NAME_MAX];
	char server_addr[MAXHOSTNAMELEN];
	char sessname[MAXHOSTNAMELEN];
	enum ibnbd_access_mode access_mode = IBNBD_ACCESS_RW;
	enum ibnbd_queue_mode queue_mode = BLK_MQ;
	enum ibnbd_io_mode io_mode = IBNBD_AUTOIO;
	struct sockaddr_storage sockaddr_s;
	struct sockaddr *sockaddr = (struct sockaddr *)&sockaddr_s;

	ret = ibnbd_clt_parse_map_options(buf, sessname,
					  server_addr, pathname,
					  &access_mode, &queue_mode,
					  &io_mode);
	if (ret)
		return ret;

	ret = ibnbd_clt_str_to_sockaddr(server_addr, sockaddr);
	if (ret) {
		if (ret == -EPROTONOSUPPORT)
			pr_err("Invalid address protocol provided: %s\n",
			       server_addr);
		else
			pr_err("Converting address to binary format failed: "
			       "%s\n", server_addr);
		return -EINVAL;
	}

	if (ibnbd_clt_dev_is_mapped(pathname)) {
		pr_err("map_device: failed, Device with same path '%s' is"
		       " already mapped\n", pathname);
		return -EEXIST;
	}

	pr_info("Mapping device %s from server %s,"
		" (access_mode: %s, input_mode: %s, io_mode: %s)\n",
		pathname, server_addr, ibnbd_access_mode_str(access_mode),
		ibnbd_queue_mode_str(queue_mode), ibnbd_io_mode_str(io_mode));

	sess = ibnbd_clt_get_create_sess(sessname, sockaddr);
	if (IS_ERR(sess))
		return PTR_ERR(sess);

	dev = ibnbd_client_add_device(sess, pathname, access_mode, queue_mode,
				      io_mode);
	if (IS_ERR(dev)) {
		ret = PTR_ERR(dev);
		goto out_sess_put;
	}

	ret = ibnbd_clt_add_dev_kobj(dev);
	if (ret) {
		if (!WARN_ON(ibnbd_close_device(dev, true)))
			wait_for_completion(dev->close_compl);
		/* ibnbd_destroy_gen_disk() will put the reference that was
		 * acquired by ibnbd_client_add_device()
		 */
		ibnbd_destroy_gen_disk(dev);
		goto out_sess_put;
	}

	ret = ibnbd_clt_add_dev_symlink(dev);
	if (ret)
		goto out_close_dev;

	ibnbd_clt_put_sess(sess);
	return count;

out_close_dev:
	if (!WARN_ON(ibnbd_close_device(dev, true)))
		wait_for_completion(dev->close_compl);
	kobject_del(&dev->kobj);
	kobject_put(&dev->kobj);
out_sess_put:
	ibnbd_clt_put_sess(sess);

	return ret;
}

static struct kobj_attribute ibnbd_clt_map_device_attr =
	__ATTR(map_device, 0644,
	       ibnbd_clt_map_device_show, ibnbd_clt_map_device_store);

static struct attribute *default_attrs[] = {
	&ibnbd_clt_map_device_attr.attr,
	NULL,
};

static struct attribute_group default_attr_group = {
	.attrs = default_attrs,
};

int ibnbd_clt_create_sysfs_files(void)
{
	int err = 0;

	ibnbd_kobject = kobject_create_and_add(KBUILD_MODNAME, kernel_kobj);
	if (!ibnbd_kobject) {
		err = -ENOMEM;
		goto err1;
	}

	ibnbd_devices_kobject = kobject_create_and_add("devices",
						       ibnbd_kobject);
	if (!ibnbd_devices_kobject) {
		err = -ENOMEM;
		goto err2;
	}

	err = sysfs_create_group(ibnbd_kobject, &default_attr_group);
	if (err)
		goto err3;

	return 0;

err3:
	kobject_put(ibnbd_devices_kobject);
err2:
	kobject_put(ibnbd_kobject);
err1:
	return err;
}

void ibnbd_clt_destroy_default_group(void)
{
	sysfs_remove_group(ibnbd_kobject, &default_attr_group);
}

void ibnbd_clt_destroy_sysfs_files(void)
{
	kobject_put(ibnbd_devices_kobject);
	kobject_put(ibnbd_kobject);
}
