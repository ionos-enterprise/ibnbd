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

#ifndef IBTRS_COMPAT_H
#define IBTRS_COMPAT_H

#define sockaddr_to_str ORIGINAL_sockaddr_to_str
#include "../ibtrs-pri.h"
#undef sockaddr_to_str

static inline void sockaddr_to_str(const struct sockaddr *addr,
				   char *buf, size_t len)
{
	switch (addr->sa_family) {
	case AF_INET6:
		/* workaround for ip4 client addr being set to INET6 family.
		 * This should fix it:
		 * yotamke@mellanox.com: [PATCH for-next] RDMA/CMA: Mark
		 * IPv4 addresses correctly when the listener is IPv6]
		 * http://permalink.gmane.org/gmane.linux.drivers.rdma/22395
		 *
		 * The first byte of ip6 address can't be 0. If it is, assume
		 * structure addr actually contains ip4 address.
		 *                                                   Danil K.
		 */
		if (!((struct sockaddr_in6 *)addr)->sin6_addr.s6_addr[0]) {
			scnprintf(buf, len, "ip:%pI4",
				  &((struct sockaddr_in *)addr)->sin_addr);
			return;
		}
		/* FALLTHRU */
	default:
		return ORIGINAL_sockaddr_to_str(addr, buf, len);
	}
}

#endif /* IBTRS_COMPAT_H */
