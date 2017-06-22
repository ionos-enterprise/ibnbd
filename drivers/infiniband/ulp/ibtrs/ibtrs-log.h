#ifndef IBTRS_LOG_H
#define IBTRS_LOG_H

struct fake_sess {
	struct ibtrs_sess sess;
};

#define FAKE_OR_REAL(dev)						\
	typeof(__builtin_choose_expr(					\
		       __builtin_types_compatible_p(typeof(dev),	\
						    struct ibtrs_con *), \
		       (struct fake_sess *)NULL,			\
		       (typeof(dev))NULL))


#define ibtrs_prefix(dev) ({					\
	const struct ibtrs_addr *addr;				\
	char str_addr[MAXHOSTNAMELEN];				\
	const char *str = str_addr;				\
								\
	__builtin_choose_expr(					\
		__builtin_types_compatible_p(			\
			typeof(dev), struct ibtrs_con *),	\
		addr = &((struct ibtrs_con *)dev)->sess->addr,	\
		addr = &((FAKE_OR_REAL(dev))(dev))->sess.addr	\
	);							\
								\
	if (addr->hostname[0])					\
		str = addr->hostname;				\
	else							\
		sockaddr_to_str(&addr->sockaddr, str_addr,	\
				sizeof(str_addr));		\
	str;							\
})

#define ibtrs_log(lvl, fn, dev, fmt, ...)			\
	fn(lvl "<%s>: " fmt, ibtrs_prefix(dev), ##__VA_ARGS__)

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
