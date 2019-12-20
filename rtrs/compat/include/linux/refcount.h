/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2018 - 2019 1&1 IONOS Cloud GmbH. All rights reserved.
 * Authors: Roman Penyaev <roman.penyaev@profitbricks.com>
 */

#ifndef LINUX_REFCOUNT_H
#define LINUX_REFCOUNT_H

#include <linux/version.h>

#if LINUX_VERSION_CODE == KERNEL_VERSION(4,4,112) || \
	LINUX_VERSION_CODE == KERNEL_VERSION(4,4,157) || \
	LINUX_VERSION_CODE == KERNEL_VERSION(4,4,131)

#include "../../refcount-4.4.h"

#endif

#endif /* LINUX_REFCOUNT_H */
