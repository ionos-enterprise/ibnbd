#ifndef __IBNBD_H
#define __IBNBD_H

#include <linux/types.h>
#include <linux/blkdev.h>
#include <linux/inet.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <rdma/ib.h>

/* TODO: should be configurable */
#define IBTRS_PORT 1234

static inline int ibnbd_sockaddr_to_str(const struct sockaddr_storage *addr,
					char *buf, size_t len)
{
	switch (addr->ss_family) {
	case AF_IB:
		return scnprintf(buf, len, "gid:%pI6",
				 &((struct sockaddr_ib *)addr)->sib_addr.sib_raw);
	case AF_INET:
		return scnprintf(buf, len, "ip:%pI4",
				 &((struct sockaddr_in *)addr)->sin_addr);
	case AF_INET6:
		/* workaround for ip4 client addr being set to INET6 family.
		 * This should fix it:
		 * yotamke@mellanox.com: [PATCH for-next] RDMA/CMA: Mark
		 * IPv4 addresses correctly when the listener is IPv6]
		 * http://permalink.gmane.org/gmane.linux.drivers.rdma/22395
		 *
		 * The first byte of ip6 address can't be 0. If it is, assume
		 * structure addr actually contains ip4 address.
		 */
		if (!((struct sockaddr_in6 *)addr)->sin6_addr.s6_addr[0]) {
			return scnprintf(buf, len, "ip:%pI4",
					 &((struct sockaddr_in *)
					   addr)->sin_addr);
		}
		/* end of workaround*/
		return scnprintf(buf, len, "ip:%pI6c",
				 &((struct sockaddr_in6 *)addr)->sin6_addr);
	default:
		pr_err("Invalid address family\n");
		return -EINVAL;
	}
}

u32 rq_cmd_to_ibnbd_io_flags(struct request *rq);
u32 ibnbd_io_flags_to_bi_rw(u32 flags);

#endif
