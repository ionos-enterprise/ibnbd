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

#ifndef LINUX_DEV_POOL_H
#define LINUX_DEV_POOL_H

#include <linux/version.h>

#if LINUX_VERSION_CODE == KERNEL_VERSION(4,4,112)
#include "../../dev_pool.h"
#elif LINUX_VERSION_CODE == KERNEL_VERSION(4,4,73)
#include "../../dev_pool-4.4.73.h"
#else
#error Unsupported version
#endif

#endif /* LINUX_DEV_POOL_H */
