#ifndef __IBNBD_SRV_LOG_H__
#define __IBNBD_SRV_LOG_H__

#define ibnbd_prefix_srv(dev) ((dev->sess->hostname[0] != '\0') ?		\
			       dev->sess->hostname : dev->sess->str_addr)


#define ERR(dev, fmt, ...) pr_err("ibnbd L%d <%s@%s> ERR: " fmt, \
				__LINE__, dev->pathname, ibnbd_prefix_srv(dev),\
				##__VA_ARGS__)
#define ERR_RL(dev, fmt, ...) pr_err_ratelimited("ibnbd L%d <%s@%s> ERR: " fmt,\
				__LINE__, dev->pathname, ibnbd_prefix_srv(dev),\
				##__VA_ARGS__)
#define WRN(dev, fmt, ...) pr_warn("ibnbd L%d <%s@%s> WARN: " fmt,\
				__LINE__, dev->pathname, ibnbd_prefix_srv(dev),\
				##__VA_ARGS__)
#define WRN_RL(dev, fmt, ...) pr_warn_ratelimited("ibnbd L%d <%s@%s> WARN: " \
			fmt, __LINE__, dev->pathname, ibnbd_prefix_srv(dev),\
			##__VA_ARGS__)
#define INFO(dev, fmt, ...) pr_info("ibnbd <%s@%s>: " \
			fmt, dev->pathname, ibnbd_prefix_srv(dev), ##__VA_ARGS__)
#define INFO_RL(dev, fmt, ...) pr_info_ratelimited("ibnbd <%s@%s>: " \
			fmt, dev->pathname, ibnbd_prefix_srv(dev), ##__VA_ARGS__)

#endif /*__IBNBD_SRV_LOG_H__*/
