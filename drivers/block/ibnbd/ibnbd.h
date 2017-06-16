#ifndef __IBNBD_H
#define __IBNBD_H

#include <linux/types.h>
#include <linux/blkdev.h>
#include <linux/inet.h>			/* for sockaddr_in */

u32 rq_cmd_to_ibnbd_io_flags(struct request *rq);
u32 ibnbd_io_flags_to_bi_rw(u32 flags);

#endif
