/*
 * Copyright (c) Roman Pen, ProfitBricks GmbH.
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

#ifndef LINUX_COMPAT_H
#define LINUX_COMPAT_H

#include <linux/version.h>

#if LINUX_VERSION_CODE == KERNEL_VERSION(4,4,112)
#include "compat-4.4.h"
#elif LINUX_VERSION_CODE == KERNEL_VERSION(4,14,86) || \
	LINUX_VERSION_CODE == KERNEL_VERSION(4,14,110) || \
	LINUX_VERSION_CODE == KERNEL_VERSION(4,14,93)
#include "compat-4.14.h"
#else
#error Unsupported kernel version
#endif

#endif /* LINUX_COMPAT_H */
