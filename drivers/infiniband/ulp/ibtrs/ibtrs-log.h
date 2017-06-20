#ifndef IBTRS_LOG_H
#define IBTRS_LOG_H

#define ibtrs_prefix(sess) ((sess)->hostname[0] ? (sess)->hostname : \
			    (sess)->addr)

#define ibtrs_log(lvl, fn, sess, fmt, ...)			\
	fn(lvl "<%s>: " fmt, ibtrs_prefix(sess), ##__VA_ARGS__)

#define ibtrs_err(dev, fmt, ...)	\
	ibtrs_log(KERN_ERR, printk, dev, fmt, ##__VA_ARGS__)
#define ibtrs_err_rl(dev, fmt, ...)	\
	ibtrs_log(KERN_ERR, printk_ratelimited, dev, fmt, ##__VA_ARGS__)
#define ibtrs_wrn(dev, fmt, ...)	\
	ibtrs_log(KERN_WARNING, printk, dev, fmt, ##__VA_ARGS__)
#define ibtrs_wrn_rl(dev, fmt, ...) \
	ibtrs_log(KERN_WARNING, printk_ratelimited, dev, fmt, ##__VA_ARGS__)
#define ibtrs_info(dev, fmt, ...) \
	ibtrs_log(KERN_INFO, printk, dev, fmt, ##__VA_ARGS__)
#define ibtrs_info_rl(dev, fmt, ...) \
	ibtrs_log(KERN_INFO, printk_ratelimited, dev, fmt, ##__VA_ARGS__)

#endif /* IBTRS_LOG_H */
