#ifndef __IBNBD_LOG_H__
#define __IBNBD_LOG_H__

#include "ibnbd-clt.h"
#include "ibnbd-srv.h"

#define ibnbd_diskname(dev) ({						\
	struct gendisk *gd = ((struct ibnbd_clt_dev *)dev)->gd;		\
	gd ? gd->disk_name : "<no dev>";				\
})

void unknown_type(void);

#define ibnbd_log(fn, dev, fmt, ...) ({					\
	__builtin_choose_expr(						\
		__builtin_types_compatible_p(				\
			typeof(dev), struct ibnbd_clt_dev *),		\
		fn("<%s@%s> %s: " fmt, (dev)->pathname,		\
		   (dev)->sess->sessname, ibnbd_diskname(dev),		\
		   ##__VA_ARGS__),					\
		__builtin_choose_expr(					\
			__builtin_types_compatible_p(typeof(dev),	\
					struct ibnbd_srv_sess_dev *),	\
			fn("<%s@%s>: " fmt, (dev)->pathname,	\
			   (dev)->sess->sessname, ##__VA_ARGS__),		\
			unknown_type()));				\
})

#define ibnbd_err(dev, fmt, ...)	\
	ibnbd_log(pr_err, dev, fmt, ##__VA_ARGS__)
#define ibnbd_err_rl(dev, fmt, ...)	\
	ibnbd_log(pr_err_ratelimited, dev, fmt, ##__VA_ARGS__)
#define ibnbd_wrn(dev, fmt, ...)	\
	ibnbd_log(pr_warn, dev, fmt, ##__VA_ARGS__)
#define ibnbd_wrn_rl(dev, fmt, ...) \
	ibnbd_log(pr_warn_ratelimited, dev, fmt, ##__VA_ARGS__)
#define ibnbd_info(dev, fmt, ...) \
	ibnbd_log(pr_info, dev, fmt, ##__VA_ARGS__)
#define ibnbd_info_rl(dev, fmt, ...) \
	ibnbd_log(pr_info_ratelimited, dev, fmt, ##__VA_ARGS__)

#endif /*__IBNBD_LOG_H__*/
