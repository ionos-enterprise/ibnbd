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

#include <rdma/dev_pool.h>

void ib_pool_dev_init(enum ib_pd_flags pd_flags, struct ib_device_pool *pool)
{
	BUG_ON(pool->ops && (!pool->ops->alloc ^ !pool->ops->free));
	INIT_LIST_HEAD(&pool->list);
	mutex_init(&pool->mutex);
	pool->pd_flags = pd_flags;
}
EXPORT_SYMBOL(ib_pool_dev_init);

void ib_pool_dev_deinit(struct ib_device_pool *pool)
{
	WARN_ON(!list_empty(&pool->list));
}
EXPORT_SYMBOL(ib_pool_dev_deinit);

static void dev_free(struct kref *ref)
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

int ib_pool_dev_put(struct ib_pool_device *dev)
{
	return kref_put(&dev->ref, dev_free);
}
EXPORT_SYMBOL(ib_pool_dev_put);

int ib_pool_dev_get(struct ib_pool_device *dev)
{
	return kref_get_unless_zero(&dev->ref);
}
EXPORT_SYMBOL(ib_pool_dev_get);

bool ib_pool_dev_exists(struct ib_device *ib_dev,
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
EXPORT_SYMBOL(ib_pool_dev_exists);

struct ib_pool_device *
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
EXPORT_SYMBOL(ib_pool_dev_find_get_or_create);
