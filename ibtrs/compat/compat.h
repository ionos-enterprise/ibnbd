/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2018 - 2019 1&1 IONOS Cloud GmbH. All rights reserved.
 * Authors: Roman Penyaev <roman.penyaev@profitbricks.com>
 */

#ifndef LINUX_COMPAT_H
#define LINUX_COMPAT_H

#include <linux/version.h>

#if LINUX_VERSION_CODE == KERNEL_VERSION(4,14,86) || \
	LINUX_VERSION_CODE == KERNEL_VERSION(4,14,150) || \
	LINUX_VERSION_CODE == KERNEL_VERSION(4,14,144)
#include "compat-4.14.h"
#elif LINUX_VERSION_CODE == KERNEL_VERSION(4,19,80)
#include "compat-4.19.h"
#else
#error Unsupported kernel version
#endif

#endif /* LINUX_COMPAT_H */
