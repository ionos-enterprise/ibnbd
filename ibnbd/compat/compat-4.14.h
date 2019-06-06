/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2018 - 2019 1&1 IONOS Cloud GmbH. All rights reserved.
 * Authors: Roman Penyaev <roman.penyaev@profitbricks.com>
 */

#ifndef LINUX_4_14_COMPAT_H
#define LINUX_4_14_COMPAT_H

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

#include <linux/version.h>
#include <linux/blk-mq.h>

static inline void
backport_blk_queue_flag_set(unsigned int flag, struct request_queue *q)
{
	unsigned long flags;

	spin_lock_irqsave(q->queue_lock, flags);
	queue_flag_set(flag, q);
	spin_unlock_irqrestore(q->queue_lock, flags);
}

#define blk_queue_flag_set backport_blk_queue_flag_set

static inline int
backport_bioset_init(struct bio_set *bs, unsigned int pool_size,
                unsigned int front_pad, int flags)
{
    struct bio_set *tbs;

    tbs = bioset_create(pool_size, front_pad, flags);
    if (unlikely(!tbs))
        return -ENOMEM;

    memcpy(bs, tbs, sizeof(*tbs));
    kfree(tbs);
    return 0;
}

static inline void
backport_bioset_exit(struct bio_set *bs)
{
    struct bio_set *tbs;

    tbs = kzalloc(sizeof(*tbs), GFP_KERNEL);
    if (WARN_ON(!tbs))
        return;
    memcpy(tbs, bs, sizeof(*bs));
    bioset_free(tbs);
}

#define bioset_init backport_bioset_init
#define bioset_exit backport_bioset_exit

#endif /* LINUX_4_14_COMPAT_H */
