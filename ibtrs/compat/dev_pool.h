/*
 * Copyright (c) 2018 ProfitBricks GmbH.  All rights reserved.
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
 */

#ifndef __DEV_POOL__
#define __DEV_POOL__

#include <linux/mutex.h>
#include <linux/list.h>
#include <linux/kref.h>
#include <rdma/rdma_cm.h>

struct ib_pool_device;

struct ib_device_pool_ops {
	struct ib_pool_device *(*alloc)(void);
	void (*free)(struct ib_pool_device *);
	int (*init)(struct ib_pool_device *);
	void (*deinit)(struct ib_pool_device *);
};

struct ib_device_pool {
	struct mutex		mutex;
	struct list_head	list;
	enum ib_pd_flags	pd_flags;
	const struct ib_device_pool_ops	*ops;
};

struct ib_pool_device {
	struct ib_device	*ib_dev;
	struct ib_pd		*ib_pd;
	struct kref		ref;
	struct list_head	entry;
	struct ib_device_pool	*pool;
};

static inline
void ib_pool_dev_init(enum ib_pd_flags pd_flags, struct ib_device_pool *pool)
{
	BUG_ON(pool->ops && (!pool->ops->alloc ^ !pool->ops->free));
	INIT_LIST_HEAD(&pool->list);
	mutex_init(&pool->mutex);
	pool->pd_flags = pd_flags;
}

static inline void
ib_pool_dev_deinit(struct ib_device_pool *pool)
{
	WARN_ON(!list_empty(&pool->list));
}

static inline void
dev_free(struct kref *ref)
{
	struct ib_device_pool *pool;
	struct ib_pool_device *dev;

	dev = container_of(ref, typeof(*dev), ref);
	pool = dev->pool;

	mutex_lock(&pool->mutex);
	list_del(&dev->entry);
	mutex_unlock(&pool->mutex);

	if (pool->ops && pool->ops->deinit)
		pool->ops->deinit(dev);

	ib_dealloc_pd(dev->ib_pd);

	if (pool->ops && pool->ops->free)
		pool->ops->free(dev);
	else
		kfree(dev);
}

static inline int
ib_pool_dev_put(struct ib_pool_device *dev)
{
	return kref_put(&dev->ref, dev_free);
}

static inline int
ib_pool_dev_get(struct ib_pool_device *dev)
{
	return kref_get_unless_zero(&dev->ref);
}

static inline bool
ib_pool_dev_exists(struct ib_device *ib_dev,
			struct ib_device_pool *pool)
{
	struct ib_pool_device *dev;
	bool found = false;

	mutex_lock(&pool->mutex);
	list_for_each_entry(dev, &pool->list, entry) {
		if (dev->ib_dev == ib_dev) {
			found = true;
			break;
		}
	}
	mutex_unlock(&pool->mutex);

	return found;
}

static inline struct ib_pool_device *
ib_pool_dev_find_get_or_create(struct ib_device *ib_dev,
			       struct ib_device_pool *pool)
{
	struct ib_pool_device *dev;

	mutex_lock(&pool->mutex);
	list_for_each_entry(dev, &pool->list, entry) {
		if (dev->ib_dev->node_guid == ib_dev->node_guid &&
		    ib_pool_dev_get(dev))
			goto out_unlock;
	}
	if (pool->ops && pool->ops->alloc)
		dev = pool->ops->alloc();
	else
		dev = kzalloc(sizeof(*dev), GFP_KERNEL);
	if (unlikely(IS_ERR_OR_NULL(dev)))
		goto out_err;

	kref_init(&dev->ref);
	dev->pool = pool;
	dev->ib_dev = ib_dev;
	dev->ib_pd = ib_alloc_pd(ib_dev, pool->pd_flags);
	if (unlikely(IS_ERR(dev->ib_pd)))
		goto out_free_dev;

	if (pool->ops && pool->ops->init && pool->ops->init(dev))
		goto out_free_pd;

	list_add(&dev->entry, &pool->list);
out_unlock:
	mutex_unlock(&pool->mutex);
	return dev;

out_free_pd:
	ib_dealloc_pd(dev->ib_pd);
out_free_dev:
	if (pool->ops && pool->ops->free)
		pool->ops->free(dev);
	else
		kfree(dev);
out_err:
	mutex_unlock(&pool->mutex);
	return NULL;
}

#endif /* __DEV_POOL__ */
