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
 *          Swapnil Ingle <swapnil.ingle@profitbricks.com>
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

#include <linux/types.h>
#include <linux/ctype.h>
#include <linux/parser.h>
#include <linux/module.h>
#include <linux/in6.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/device.h>
#include <rdma/ib.h>
#include <rdma/rdma_cm.h>

#include "ibnbd-clt.h"

static struct device *ibnbd_dev;
static struct class *ibnbd_dev_class;
static struct kobject *ibnbd_devs_kobj;

enum {
	IBNBD_OPT_ERR		= 0,
	IBNBD_OPT_PATH		= 1 << 0,
	IBNBD_OPT_DEV_PATH	= 1 << 1,
	IBNBD_OPT_ACCESS_MODE	= 1 << 3,
	IBNBD_OPT_IO_MODE	= 1 << 5,
	IBNBD_OPT_SESSNAME	= 1 << 6,
};

static unsigned int ibnbd_opt_mandatory[] = {
	IBNBD_OPT_PATH,
	IBNBD_OPT_DEV_PATH,
	IBNBD_OPT_SESSNAME,
};

static const match_table_t ibnbd_opt_tokens = {
	{	IBNBD_OPT_PATH,		"path=%s"		},
	{	IBNBD_OPT_DEV_PATH,	"device_path=%s"	},
	{	IBNBD_OPT_ACCESS_MODE,	"access_mode=%s"	},
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
				       struct ibtrs_addr *paths,
				       size_t *path_cnt,
				       size_t max_path_cnt,
				       char *pathname,
				       enum ibnbd_access_mode *access_mode,
				       enum ibnbd_io_mode *io_mode)
{
	char *options, *sep_opt;
	char *p;
	substring_t args[MAX_OPT_ARGS];
	int opt_mask = 0;
	int token;
	int ret = -EINVAL;
	int i;
	int p_cnt = 0;

	options = kstrdup(buf, GFP_KERNEL);
	if (!options)
		return -ENOMEM;

	sep_opt = strstrip(options);
	strip(sep_opt);
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
			if (strlen(p) > NAME_MAX) {
				pr_err("map_device: sessname too long\n");
				ret = -EINVAL;
				kfree(p);
				goto out;
			}
			strlcpy(sessname, p, NAME_MAX);
			kfree(p);
			break;

		case IBNBD_OPT_PATH:
			if (p_cnt >= max_path_cnt) {
				pr_err("map_device: too many (> %lu) paths "
				       "provided\n", max_path_cnt);
				ret = -ENOMEM;
				goto out;
			}
			p = match_strdup(args);
			if (!p) {
				ret = -ENOMEM;
				goto out;
			}

			ret = ibtrs_addr_to_sockaddr(p, strlen(p), IBTRS_PORT,
						     &paths[p_cnt]);
			if (ret) {
				pr_err("Can't parse path %s: %d\n", p, ret);
				kfree(p);
				goto out;
			}

			p_cnt++;

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
				kfree(p);
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
	*path_cnt = p_cnt;
	kfree(options);
	return ret;
}

static ssize_t ibnbd_clt_state_show(struct kobject *kobj,
				    struct kobj_attribute *attr, char *page)
{
	struct ibnbd_clt_dev *dev;

	dev = container_of(kobj, struct ibnbd_clt_dev, kobj);

	switch (dev->dev_state) {
	case (DEV_STATE_INIT):
		return scnprintf(page, PAGE_SIZE, "init\n");
	case (DEV_STATE_MAPPED):
		/* TODO fix cli tool before changing to proper state */
		return scnprintf(page, PAGE_SIZE, "open\n");
	case (DEV_STATE_MAPPED_DISCONNECTED):
		/* TODO fix cli tool before changing to proper state */
		return scnprintf(page, PAGE_SIZE, "closed\n");
	case (DEV_STATE_UNMAPPED):
		return scnprintf(page, PAGE_SIZE, "unmapped\n");
	default:
		return scnprintf(page, PAGE_SIZE, "unknown\n");
	}
}

static struct kobj_attribute ibnbd_clt_state_attr =
	__ATTR(state, 0444, ibnbd_clt_state_show, NULL);

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

static ssize_t ibnbd_clt_unmap_dev_store(struct kobject *kobj,
					 struct kobj_attribute *attr,
					 const char *buf, size_t count)
{
	struct ibnbd_clt_dev *dev;
	char *opt, *options;
	bool force;
	int err;

	opt = kstrdup(buf, GFP_KERNEL);
	if (!opt)
		return -ENOMEM;

	options = strstrip(opt);
	strip(options);

	dev = container_of(kobj, struct ibnbd_clt_dev, kobj);

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

	/*
	 * We take explicit module reference only for one reason: do not
	 * race with lockless ibnbd_destroy_sessions().
	 */
	if (!try_module_get(THIS_MODULE)) {
		err = -ENODEV;
		goto out;
	}
	err = ibnbd_clt_unmap_device(dev, force, &attr->attr);
	if (unlikely(err)) {
		if (unlikely(err != -EALREADY))
			ibnbd_err(dev, "unmap_device: %d\n",  err);
		goto module_put;
	}

	/*
	 * Here device can be vanished!
	 */

	err = count;

module_put:
	module_put(THIS_MODULE);
out:
	kfree(opt);

	return err;
}

static struct kobj_attribute ibnbd_clt_unmap_device_attr =
	__ATTR(unmap_device, 0644, ibnbd_clt_unmap_dev_show,
	       ibnbd_clt_unmap_dev_store);

static ssize_t ibnbd_clt_resize_dev_show(struct kobject *kobj,
					 struct kobj_attribute *attr,
					 char *page)
{
	return scnprintf(page, PAGE_SIZE,
			 "Usage: echo <new size in sectors> > %s\n",
			 attr->attr.name);
}

static ssize_t ibnbd_clt_resize_dev_store(struct kobject *kobj,
					  struct kobj_attribute *attr,
					  const char *buf, size_t count)
{
	int ret;
	unsigned long sectors;
	struct ibnbd_clt_dev *dev;

	dev = container_of(kobj, struct ibnbd_clt_dev, kobj);

	ret = kstrtoul(buf, 0, &sectors);
	if (ret)
		return ret;

	ret = ibnbd_clt_resize_disk(dev, (size_t)sectors);
	if (ret)
		return ret;

	return count;
}

static struct kobj_attribute ibnbd_clt_resize_dev_attr =
	__ATTR(resize, 0644, ibnbd_clt_resize_dev_show,
	       ibnbd_clt_resize_dev_store);

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
	struct ibnbd_clt_dev *dev;
	char *opt, *options;
	int err;

	opt = kstrdup(buf, GFP_KERNEL);
	if (!opt)
		return -ENOMEM;

	options = strstrip(opt);
	strip(options);

	dev = container_of(kobj, struct ibnbd_clt_dev, kobj);
	if (!sysfs_streq(options, "1")) {
		ibnbd_err(dev, "remap_device: Invalid value: %s\n", options);
		err = -EINVAL;
		goto out;
	}
	err = ibnbd_clt_remap_device(dev);
	if (likely(!err))
		err = count;

out:
	kfree(opt);

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
	&ibnbd_clt_resize_dev_attr.attr,
	&ibnbd_clt_remap_device_attr.attr,
	&ibnbd_clt_mapping_path_attr.attr,
	&ibnbd_clt_state_attr.attr,
	&ibnbd_clt_session_attr.attr,
	&ibnbd_clt_io_mode.attr,
	NULL,
};

void ibnbd_clt_remove_dev_symlink(struct ibnbd_clt_dev *dev)
{
	/*
	 * The module_is_live() check is crucial and helps to avoid annoying
	 * sysfs warning raised in sysfs_remove_link(), when the whole sysfs
	 * path was just removed, see ibnbd_close_sessions().
	 */
	if (strlen(dev->blk_symlink_name) && module_is_live(THIS_MODULE))
		sysfs_remove_link(ibnbd_devs_kobj, dev->blk_symlink_name);
}

static struct kobj_type ibnbd_dev_ktype = {
	.sysfs_ops      = &kobj_sysfs_ops,
	.default_attrs  = ibnbd_dev_attrs,
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

static ssize_t ibnbd_clt_map_device_show(struct kobject *kobj,
					 struct kobj_attribute *attr,
					 char *page)
{
	return scnprintf(page, PAGE_SIZE, "Usage: echo \""
			 "sessname=<name of the ibtrs session>"
			 " path=<[srcaddr,]dstaddr>"
			 " [path=<[srcaddr,]dstaddr>]"
			 " device_path=<full path on remote side>"
			 " [access_mode=<ro|rw|migration>]"
			 " [io_mode=<fileio|blockio>]\" > %s\n\n"
			 "addr ::= [ ip:<ipv4> | ip:<ipv6> | gid:<gid> ]\n",
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

	ret = sysfs_create_link(ibnbd_devs_kobj, gd_kobj,
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
	struct ibnbd_clt_dev *dev;
	int ret;
	char pathname[NAME_MAX];
	char sessname[NAME_MAX];
	enum ibnbd_access_mode access_mode = IBNBD_ACCESS_RW;
	enum ibnbd_io_mode io_mode = IBNBD_AUTOIO;

	size_t path_cnt;
	struct ibtrs_addr paths[3];
	struct sockaddr_storage saddr[ARRAY_SIZE(paths)];
	struct sockaddr_storage daddr[ARRAY_SIZE(paths)];

	for (path_cnt = 0; path_cnt < ARRAY_SIZE(paths); path_cnt++) {
		paths[path_cnt].src = &saddr[path_cnt];
		paths[path_cnt].dst = &daddr[path_cnt];
	}

	ret = ibnbd_clt_parse_map_options(buf, sessname, paths,
					  &path_cnt, ARRAY_SIZE(paths),
					  pathname, &access_mode, &io_mode);
	if (ret)
		return ret;

	pr_info("Mapping device %s on session %s, (access_mode: %s, "
		"io_mode: %s)\n", pathname, sessname,
		ibnbd_access_mode_str(access_mode), ibnbd_io_mode_str(io_mode));

	dev = ibnbd_clt_map_device(sessname, paths, path_cnt, pathname,
				   access_mode, io_mode);
	if (unlikely(IS_ERR(dev)))
		return PTR_ERR(dev);

	ret = ibnbd_clt_add_dev_kobj(dev);
	if (unlikely(ret))
		goto unmap_dev;

	ret = ibnbd_clt_add_dev_symlink(dev);
	if (ret)
		goto unmap_dev;

	return count;

unmap_dev:
	ibnbd_clt_unmap_device(dev, true, NULL);

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
	int err;

	ibnbd_dev_class = class_create(THIS_MODULE, "ibnbd-client");
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
	err = sysfs_create_group(&ibnbd_dev->kobj, &default_attr_group);
	if (unlikely(err))
		goto put_devs_kobj;

	return 0;

put_devs_kobj:
	kobject_del(ibnbd_devs_kobj);
	kobject_put(ibnbd_devs_kobj);
dev_destroy:
	device_destroy(ibnbd_dev_class, MKDEV(0, 0));
cls_destroy:
	class_destroy(ibnbd_dev_class);

	return err;
}

void ibnbd_clt_destroy_default_group(void)
{
	sysfs_remove_group(&ibnbd_dev->kobj, &default_attr_group);
}

void ibnbd_clt_destroy_sysfs_files(void)
{
	kobject_del(ibnbd_devs_kobj);
	kobject_put(ibnbd_devs_kobj);
	device_destroy(ibnbd_dev_class, MKDEV(0, 0));
	class_destroy(ibnbd_dev_class);
}
