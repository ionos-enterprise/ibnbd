#ifndef __IBNBD_LOG_H__
#define __IBNBD_LOG_H__

#include "ibnbd-clt.h"
#include "ibnbd-srv.h"

#define ibnbd_diskname(dev) ({						\
	struct gendisk *gd = ((struct ibnbd_clt_dev *)dev)->gd;		\
	gd ? gd->disk_name : "<no dev>";				\
})

#define ibnbd_prefix(dev) ((dev)->sess->hostname[0] ? (dev)->sess->hostname : \
			   (dev)->sess->str_addr)

void unknown_type(void);

#define ibnbd_log(lvl, fn, dev, fmt, ...) ({				\
	__builtin_choose_expr(						\
		__builtin_types_compatible_p(				\
			typeof(dev), struct ibnbd_clt_dev *),		\
		fn(lvl "<%s@%s> %s: " fmt, (dev)->pathname,		\
		   ibnbd_prefix(dev), ibnbd_diskname(dev),		\
		   ##__VA_ARGS__),					\
		__builtin_choose_expr(					\
			__builtin_types_compatible_p(typeof(dev),	\
					struct ibnbd_srv_sess_dev *),	\
			fn(lvl "<%s@%s>: " fmt, (dev)->pathname,	\
			   ibnbd_prefix(dev), ##__VA_ARGS__),		\
			unknown_type()));				\
})

#define ibnbd_err(dev, fmt, ...)	\
	ibnbd_log(KERN_ERR, printk, dev, fmt, ##__VA_ARGS__)
#define ibnbd_err_rl(dev, fmt, ...)	\
	ibnbd_log(KERN_ERR, printk_ratelimited, dev, fmt, ##__VA_ARGS__)
#define ibnbd_wrn(dev, fmt, ...)	\
	ibnbd_log(KERN_WARNING, printk, dev, fmt, ##__VA_ARGS__)
#define ibnbd_wrn_rl(dev, fmt, ...) \
	ibnbd_log(KERN_WARNING, printk_ratelimited, dev, fmt, ##__VA_ARGS__)
#define ibnbd_info(dev, fmt, ...) \
	ibnbd_log(KERN_INFO, printk, dev, fmt, ##__VA_ARGS__)
#define ibnbd_info_rl(dev, fmt, ...) \
	ibnbd_log(KERN_INFO, printk_ratelimited, dev, fmt, ##__VA_ARGS__)

#endif /*__IBNBD_LOG_H__*/
