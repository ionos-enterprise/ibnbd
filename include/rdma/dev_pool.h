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

void ib_pool_dev_init(enum ib_pd_flags pd_flags, struct ib_device_pool *pool);
void ib_pool_dev_deinit(struct ib_device_pool *pool);

struct ib_pool_device *
ib_pool_dev_find_get_or_create(struct ib_device *ib_dev,
			       struct ib_device_pool *pool);

bool ib_pool_dev_exists(struct ib_device *ib_dev,
			struct ib_device_pool *pool);

int ib_pool_dev_get(struct ib_pool_device *dev);
int ib_pool_dev_put(struct ib_pool_device *dev);

#endif /* __DEV_POOL__ */
