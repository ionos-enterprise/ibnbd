#ifndef __IBNBD_CLT_LOG_H__
#define __IBNBD_CLT_LOG_H__

#define blkdev_name(dev) ((dev->gd == NULL) ? "<no dev>" : dev->gd->disk_name)
#define ibnbd_prefix_clt(dev) ((dev->sess->hostname[0] != '\0') ?		\
			       dev->sess->hostname : dev->sess->str_addr)


#define ERR(dev, fmt, ...) pr_err("<%s@%s> %s: " fmt,\
				  dev->pathname, ibnbd_prefix_clt(dev),	\
				  blkdev_name(dev), ##__VA_ARGS__)

#define ERR_RL(dev, fmt, ...) pr_err_ratelimited("<%s@%s> %s: "\
				fmt, dev->pathname,\
				ibnbd_prefix_clt(dev), blkdev_name(dev),\
				##__VA_ARGS__)

#define WRN(dev, fmt, ...) pr_warn("<%s@%s> %s: " fmt,\
				dev->pathname, ibnbd_prefix_clt(dev),\
				blkdev_name(dev), ##__VA_ARGS__)

#define WRN_RL(dev, fmt, ...) pr_warn_ratelimited("<%s@%s> %s: "\
			fmt, dev->pathname, ibnbd_prefix_clt(dev),\
			blkdev_name(dev), ##__VA_ARGS__)

#define INFO(dev, fmt, ...) pr_info("<%s@%s> %s: " \
			fmt, dev->pathname, ibnbd_prefix_clt(dev),\
			blkdev_name(dev), ##__VA_ARGS__)

#define INFO_RL(dev, fmt, ...) pr_info_ratelimited("<%s@%s> %s: " \
			fmt, dev->pathname, ibnbd_prefix_clt(dev),\
			blkdev_name(dev), ##__VA_ARGS__)

#endif /*__IBNBD_CLT_LOG_H__*/
