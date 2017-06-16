#define pr_fmt(fmt) KBUILD_MODNAME " L" __stringify(__LINE__) ": " fmt

#include <uapi/linux/limits.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/stat.h>
#include <linux/genhd.h>
#include <linux/list.h>
#include <linux/moduleparam.h>

#include "ibnbd.h"
#include "ibnbd-srv.h"
#include "ibnbd-srv-sysfs.h"

static struct kobject *ibnbd_srv_kobj;
static struct kobject *ibnbd_srv_devices_kobj;

static ssize_t ibnbd_srv_revalidate_dev_show(struct kobject *kobj,
					     struct kobj_attribute *attr,
					     char *page)
{
	return scnprintf(page, PAGE_SIZE,
			 "Usage: echo 1 > %s\n", attr->attr.name);
}

static ssize_t ibnbd_srv_revalidate_dev_store(struct kobject *kobj,
					      struct kobj_attribute *attr,
					      const char *buf, size_t count)
{
	int ret;
	struct ibnbd_srv_dev *dev = container_of(kobj, struct ibnbd_srv_dev,
						 dev_kobj);

	if (!sysfs_streq(buf, "1")) {
		pr_err("%s: invalid value: '%s'\n", attr->attr.name, buf);
		return -EINVAL;
	}
	ret = ibnbd_srv_revalidate_dev(dev);
	if (ret)
		return ret;

	return count;
}

static struct kobj_attribute ibnbd_srv_revalidate_dev_attr =
	__ATTR(revalidate, 0644,
	       ibnbd_srv_revalidate_dev_show,
	       ibnbd_srv_revalidate_dev_store);

static struct attribute *ibnbd_srv_default_dev_attrs[] = {
	&ibnbd_srv_revalidate_dev_attr.attr,
	NULL,
};

static struct attribute_group ibnbd_srv_default_dev_attr_group = {
	.attrs = ibnbd_srv_default_dev_attrs,
};

static ssize_t ibnbd_srv_attr_show(struct kobject *kobj, struct attribute *attr,
				   char *page)
{
	struct kobj_attribute *kattr;
	int ret = -EIO;

	kattr = container_of(attr, struct kobj_attribute, attr);
	if (kattr->show)
		ret = kattr->show(kobj, kattr, page);
	return ret;
}

static ssize_t ibnbd_srv_attr_store(struct kobject *kobj,
				    struct attribute *attr,
				    const char *page, size_t length)
{
	struct kobj_attribute *kattr;
	int ret = -EIO;

	kattr = container_of(attr, struct kobj_attribute, attr);
	if (kattr->store)
		ret = kattr->store(kobj, kattr, page, length);
	return ret;
}

static const struct sysfs_ops ibnbd_srv_sysfs_ops = {
	.show	= ibnbd_srv_attr_show,
	.store	= ibnbd_srv_attr_store,
};

static struct kobj_type ibnbd_srv_dev_ktype = {
	.sysfs_ops	= &ibnbd_srv_sysfs_ops,
};

static struct kobj_type ibnbd_srv_dev_clients_ktype = {
	.sysfs_ops	= &ibnbd_srv_sysfs_ops,
};

int ibnbd_srv_create_dev_sysfs(struct ibnbd_srv_dev *dev,
			       struct block_device *bdev,
			       const char *dir_name)
{
	struct kobject *bdev_kobj;
	int ret;

	ret = kobject_init_and_add(&dev->dev_kobj, &ibnbd_srv_dev_ktype,
				   ibnbd_srv_devices_kobj, dir_name);
	if (ret)
		return ret;

	ret = kobject_init_and_add(&dev->dev_clients_kobj,
				   &ibnbd_srv_dev_clients_ktype,
				   &dev->dev_kobj, "clients");
	if (ret)
		goto err;

	ret = sysfs_create_group(&dev->dev_kobj,
				 &ibnbd_srv_default_dev_attr_group);
	if (ret)
		goto err2;

	bdev_kobj = &disk_to_dev(bdev->bd_disk)->kobj;
	ret = sysfs_create_link(&dev->dev_kobj, bdev_kobj, "block_dev");
	if (ret)
		goto err3;

	return 0;

err3:
	sysfs_remove_group(&dev->dev_kobj,
			   &ibnbd_srv_default_dev_attr_group);
err2:
	kobject_del(&dev->dev_clients_kobj);
	kobject_put(&dev->dev_clients_kobj);
err:
	kobject_del(&dev->dev_kobj);
	kobject_put(&dev->dev_kobj);
	return ret;
}

void ibnbd_srv_destroy_dev_sysfs(struct ibnbd_srv_dev *dev)
{
	sysfs_remove_link(&dev->dev_kobj, "block_dev");
	sysfs_remove_group(&dev->dev_kobj, &ibnbd_srv_default_dev_attr_group);
	kobject_del(&dev->dev_clients_kobj);
	kobject_put(&dev->dev_clients_kobj);
	kobject_del(&dev->dev_kobj);
	kobject_put(&dev->dev_kobj);
}

static ssize_t ibnbd_srv_dev_client_ro_show(struct kobject *kobj,
					    struct kobj_attribute *attr,
					    char *page)
{
	struct ibnbd_srv_sess_dev *sess_dev;

	sess_dev = container_of(kobj, struct ibnbd_srv_sess_dev, kobj);

	return scnprintf(page, PAGE_SIZE, "%s\n",
			 (sess_dev->open_flags & FMODE_WRITE) ? "0" : "1");
}

static struct kobj_attribute ibnbd_srv_dev_client_ro_attr =
	__ATTR(read_only, 0444,
	       ibnbd_srv_dev_client_ro_show,
	       NULL);

static ssize_t ibnbd_srv_dev_client_mapping_path_show(
	struct kobject *kobj,
	struct kobj_attribute *attr,
	char *page)
{
	struct ibnbd_srv_sess_dev *sess_dev;

	sess_dev = container_of(kobj, struct ibnbd_srv_sess_dev, kobj);

	return scnprintf(page, PAGE_SIZE, "%s\n", sess_dev->pathname);
}

static struct kobj_attribute ibnbd_srv_dev_client_mapping_path_attr =
	__ATTR(mapping_path, 0444,
	       ibnbd_srv_dev_client_mapping_path_show,
	       NULL);

static struct attribute *ibnbd_srv_default_dev_clients_attrs[] = {
	&ibnbd_srv_dev_client_ro_attr.attr,
	&ibnbd_srv_dev_client_mapping_path_attr.attr,
	NULL,
};

static struct attribute_group ibnbd_srv_default_dev_client_attr_group = {
	.attrs = ibnbd_srv_default_dev_clients_attrs,
};

void ibnbd_srv_destroy_dev_client_sysfs(struct ibnbd_srv_sess_dev *sess_dev)
{
	struct completion sysfs_compl;

	sysfs_remove_group(&sess_dev->kobj,
			   &ibnbd_srv_default_dev_client_attr_group);

	init_completion(&sysfs_compl);
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
	.sysfs_ops	= &ibnbd_srv_sysfs_ops,
	.release	= ibnbd_srv_sess_dev_release,
};

int ibnbd_srv_create_dev_client_sysfs(struct ibnbd_srv_sess_dev *sess_dev)
{
	int ret;

	ret = kobject_init_and_add(&sess_dev->kobj, &ibnbd_srv_sess_dev_ktype,
				   &sess_dev->dev->dev_clients_kobj, "%s",
				   sess_dev->sess->str_addr);
	if (ret)
		return ret;

	ret = sysfs_create_group(&sess_dev->kobj,
				 &ibnbd_srv_default_dev_client_attr_group);
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

	ibnbd_srv_kobj = kobject_create_and_add(KBUILD_MODNAME, kernel_kobj);
	if (!ibnbd_srv_kobj)
		return -ENOMEM;

	ibnbd_srv_devices_kobj = kobject_create_and_add("devices",
							ibnbd_srv_kobj);
	if (!ibnbd_srv_devices_kobj) {
		err = -ENOMEM;
		goto err;
	}

	return 0;

err:
	kobject_put(ibnbd_srv_kobj);
	return err;
}

void ibnbd_srv_destroy_sysfs_files(void)
{
	kobject_put(ibnbd_srv_devices_kobj);
	kobject_put(ibnbd_srv_kobj);
}
