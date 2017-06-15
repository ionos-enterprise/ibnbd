#ifndef __IBNBD_CLT_LOG_H__
#define __IBNBD_CLT_LOG_H__

#define ibnbd_diskname(dev) ((dev)->gd ? (dev)->gd->disk_name : "<no dev>")
#define ibnbd_prefix(dev) ((dev)->sess->hostname[0] ? (dev)->sess->hostname : \
			   (dev)->sess->str_addr)

#define ibnbd_log(lvl, fn, dev, fmt, ...) ({				\
	if (__builtin_types_compatible_p(typeof(dev),			\
					 struct ibnbd_dev *))		\
		fn(lvl "<%s@%s> %s: " fmt, (dev)->pathname,		\
		   ibnbd_prefix(dev), ibnbd_diskname(dev),		\
		   ##__VA_ARGS__);					\
	else if (__builtin_types_compatible_p(typeof(dev),		\
					      struct ibnbd_srv_dev *))	\
		fn(lvl "<%s@%s>: " fmt, (dev)->pathname,		\
		   ibnbd_prefix(dev), ##__VA_ARGS__);			\
})

#define ERR(dev, fmt, ...)	\
	ibnbd_log(KERN_ERR, printk, dev, fmt, ##__VA_ARGS__)
#define ERR_RL(dev, fmt, ...)	\
	ibnbd_log(KERN_ERR, printk_ratelimited, dev, fmt, ##__VA_ARGS__)
#define WRN(dev, fmt, ...)	\
	ibnbd_log(KERN_WARNING, printk, dev, fmt, ##__VA_ARGS__)
#define WRN_RL(dev, fmt, ...) \
	ibnbd_log(KERN_WARNING, printk_ratelimited, dev, fmt, ##__VA_ARGS__)
#define INFO(dev, fmt, ...) \
	ibnbd_log(KERN_INFO, printk, dev, fmt, ##__VA_ARGS__)
#define INFO_RL(dev, fmt, ...) \
	ibnbd_log(KERN_INFO, printk_ratelimited, dev, fmt, ##__VA_ARGS__)

#endif /*__IBNBD_CLT_LOG_H__*/
