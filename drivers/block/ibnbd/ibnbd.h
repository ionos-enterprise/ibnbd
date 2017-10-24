#ifndef __IBNBD_H
#define __IBNBD_H

#include <linux/types.h>
#include <linux/blkdev.h>
#include <linux/inet.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <rdma/ib.h>

#define IBNBD_VER_MAJOR 1
#define IBNBD_VER_MINOR 0
#define IBNBD_VER_STRING __stringify(IBNBD_VER_MAJOR) "." \
			 __stringify(IBNBD_VER_MINOR)

/* TODO: should be configurable */
#define IBTRS_PORT 1234

static inline int ibnbd_sockaddr_to_str(const struct sockaddr *addr,
					char *buf, size_t len)
{
	switch (addr->sa_family) {
	case AF_IB:
		return scnprintf(buf, len, "gid:%pI6",
				 &((struct sockaddr_ib *)addr)->sib_addr.sib_raw);
	case AF_INET:
		return scnprintf(buf, len, "ip:%pI4",
				 &((struct sockaddr_in *)addr)->sin_addr);
	case AF_INET6:
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
