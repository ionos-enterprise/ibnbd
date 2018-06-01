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

#ifndef LINUX_4_4_COMPAT_H
#define LINUX_4_4_COMPAT_H

/*
 * linux/gfp.h
 */
#define __GFP_RETRY_MAYFAIL __GFP_REPEAT

/*
 * linux/uuid.h
 */
#include <linux/uuid.h>
typedef uuid_be uuid_t;
#define uuid_gen uuid_be_gen
#define uuid_copy(dst,src) memcpy(dst, src, sizeof(uuid_t))
#define uuid_equal(u1,u2) (!memcmp(u1, u2, sizeof(uuid_t)))

/*
 * linux/kernel.h
 */
#define COUNT_ARGS(...) COUNT_ARGS_(,##__VA_ARGS__,6,5,4,3,2,1,0)
#define COUNT_ARGS_(z,a,b,c,d,e,f,cnt,...) cnt

/*
 * implement _copy_from_iter from lib/iov_iter.c
 */
#include <linux/uio.h>
#include <linux/bug.h>

static inline size_t _copy_from_iter(void *data, size_t bytes,
				     struct iov_iter *i)
{
	size_t seg, len, copy = bytes;
	const struct kvec *vec = i->kvec;

	BUG_ON(!(i->type & ITER_KVEC));

	for (seg = 0; copy; seg++) {
		len = min(vec[seg].iov_len, copy);
		memcpy(data, vec[seg].iov_base, len);
		data += len;
		copy -= len;
	}

	return bytes;
}

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

/*
 * rdma/rdma_cm.h
 */

#define rdma_ucm_port_space rdma_port_space

/*
 * Version specific
 */

#if LINUX_VERSION_CODE == KERNEL_VERSION(4,4,112) || \
	LINUX_VERSION_CODE == KERNEL_VERSION(4,4,131)
#include "compat-4.4.112.h"
#else
#error Unsupported kernel version
#endif

/*
 * IBTRS internals
 */

#define sockaddr_to_str ORIGINAL_sockaddr_to_str
#define ibtrs_invalidate_flag ORIGINAL_ibtrs_invalidate_flag
#include "../ibtrs-pri.h"
#undef sockaddr_to_str
#undef ibtrs_invalidate_flag

static inline int sockaddr_to_str(const struct sockaddr *addr,
				   char *buf, size_t len)
{
	int cnt;

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
			cnt = scnprintf(buf, len, "ip:%pI4",
				&((struct sockaddr_in *)addr)->sin_addr);
			return cnt;
		}
		/* FALLTHRU */
	default:
		return ORIGINAL_sockaddr_to_str(addr, buf, len);
	}
}

/*
 * Since in compat we do FMR instead of FR no need to invalidate keys.
 */
static inline u32 ibtrs_invalidate_flag(void)
{
	return 0;
}

/*
 * net/core/utils.h
 */

#include <linux/inet.h>

static inline
int inet4_pton(const char *src, u16 port_num,
	       struct sockaddr_storage *addr)
{
	struct sockaddr_in *addr4 = (struct sockaddr_in *)addr;
	int srclen = strlen(src);

	if (srclen > INET_ADDRSTRLEN)
		return -EINVAL;

	if (in4_pton(src, srclen, (u8 *)&addr4->sin_addr.s_addr,
		     '\n', NULL) == 0)
		return -EINVAL;

	addr4->sin_family = AF_INET;
	addr4->sin_port = htons(port_num);

	return 0;
}

static inline int
inet6_pton(struct net *net, const char *src, u16 port_num,
	   struct sockaddr_storage *addr)
{
	struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)addr;
	const char *scope_delim;
	int srclen = strlen(src);

	if (srclen > INET6_ADDRSTRLEN)
		return -EINVAL;

	if (in6_pton(src, srclen, (u8 *)&addr6->sin6_addr.s6_addr,
		     '%', &scope_delim) == 0)
		return -EINVAL;

	if (ipv6_addr_type(&addr6->sin6_addr) & IPV6_ADDR_LINKLOCAL &&
	    src + srclen != scope_delim && *scope_delim == '%') {
		struct net_device *dev;
		char scope_id[16];
		size_t scope_len = min_t(size_t, sizeof(scope_id) - 1,
					 src + srclen - scope_delim - 1);

		memcpy(scope_id, scope_delim + 1, scope_len);
		scope_id[scope_len] = '\0';

		dev = dev_get_by_name(net, scope_id);
		if (dev) {
			addr6->sin6_scope_id = dev->ifindex;
			dev_put(dev);
		} else if (kstrtouint(scope_id, 0, &addr6->sin6_scope_id)) {
			return -EINVAL;
		}
	}

	addr6->sin6_family = AF_INET6;
	addr6->sin6_port = htons(port_num);

	return 0;
}

/**
 * inet_pton_with_scope - convert an IPv4/IPv6 and port to socket address
 * @net: net namespace (used for scope handling)
 * @af: address family, AF_INET, AF_INET6 or AF_UNSPEC for either
 * @src: the start of the address string
 * @port: the start of the port string (or NULL for none)
 * @addr: output socket address
 *
 * Return zero on success, return errno when any error occurs.
 */
static inline
int inet_pton_with_scope(struct net *net, __kernel_sa_family_t af,
		const char *src, const char *port, struct sockaddr_storage *addr)
{
	u16 port_num;
	int ret = -EINVAL;

	if (port) {
		if (kstrtou16(port, 0, &port_num))
			return -EINVAL;
	} else {
		port_num = 0;
	}

	switch (af) {
	case AF_INET:
		ret = inet4_pton(src, port_num, addr);
		break;
	case AF_INET6:
		ret = inet6_pton(net, src, port_num, addr);
		break;
	case AF_UNSPEC:
		ret = inet4_pton(src, port_num, addr);
		if (ret)
			ret = inet6_pton(net, src, port_num, addr);
		break;
	default:
		pr_err("unexpected address family %d\n", af);
	};

	return ret;
}

/*
 * linux/rculist.h
 */

/**
 * list_next_or_null_rcu - get the first element from a list
 * @head:	the head for the list.
 * @ptr:        the list head to take the next element from.
 * @type:       the type of the struct this is embedded in.
 * @member:     the name of the list_head within the struct.
 *
 * Note that if the ptr is at the end of the list, NULL is returned.
 *
 * This primitive may safely run concurrently with the _rcu list-mutation
 * primitives such as list_add_rcu() as long as it's guarded by rcu_read_lock().
 */
#define list_next_or_null_rcu(head, ptr, type, member) \
({ \
	struct list_head *__head = (head); \
	struct list_head *__ptr = (ptr); \
	struct list_head *__next = READ_ONCE(__ptr->next); \
	likely(__next != __head) ? list_entry_rcu(__next, type, \
						  member) : NULL; \
})

#endif /* LINUX_4_4_COMPAT_H */
