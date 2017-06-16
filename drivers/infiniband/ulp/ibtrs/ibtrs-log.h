#ifndef __IBTRS_LOG_H__
#define __IBTRS_LOG_H__

#define ibtrs_prefix(sess) ((sess->hostname[0] != '\0') ? sess->hostname : \
							  sess->addr)

#define ERR(sess, fmt, ...) pr_err("<%s>: " fmt, \
				   ibtrs_prefix(sess), ##__VA_ARGS__)
#define ERR_RL(sess, fmt, ...) pr_err_ratelimited("<%s>: " fmt, \
				ibtrs_prefix(sess), ##__VA_ARGS__)

#define WRN(sess, fmt, ...) pr_warn("<%s>: " fmt, \
				ibtrs_prefix(sess), ##__VA_ARGS__)
#define WRN_RL(sess, fmt, ...) pr_warn_ratelimited("<%s>: " \
			fmt, ibtrs_prefix(sess), ##__VA_ARGS__)

#define INFO(sess, fmt, ...) pr_info("<%s>: " fmt, \
				    ibtrs_prefix(sess), ##__VA_ARGS__)
#define INFO_RL(sess, fmt, ...) pr_info_ratelimited(": " fmt, \
					ibtrs_prefix(sess), ##__VA_ARGS__)
#endif /*__IBTRS_LOG_H__*/
