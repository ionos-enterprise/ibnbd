#define pr_fmt(fmt) KBUILD_MODNAME " L" __stringify(__LINE__) ": " fmt

#include "ibtrs-pri.h"
#include "ibtrs-log.h"

void ibtrs_heartbeat_init(struct ibtrs_heartbeat *h, u32 timeout_ms)
{
	atomic64_set(&h->send_ts_ns, 0);
	atomic64_set(&h->recv_ts_ns, 0);
	h->timeout_ms = timeout_ms;
}
EXPORT_SYMBOL_GPL(ibtrs_heartbeat_init);

void ibtrs_heartbeat_set_timeout_ms(struct ibtrs_heartbeat *h, u32 timeout_ms)
{
	h->timeout_ms = timeout_ms;
}
EXPORT_SYMBOL_GPL(ibtrs_heartbeat_set_timeout_ms);

void ibtrs_heartbeat_set_send_ts(struct ibtrs_heartbeat *h)
{
	struct timespec ts;

	getrawmonotonic(&ts);
	atomic64_set(&h->send_ts_ns, timespec64_to_ns(&ts));
}
EXPORT_SYMBOL_GPL(ibtrs_heartbeat_set_send_ts);

void ibtrs_heartbeat_set_recv_ts(struct ibtrs_heartbeat *h)
{
	struct timespec ts;

	getrawmonotonic(&ts);
	atomic64_set(&h->recv_ts_ns, timespec64_to_ns(&ts));
}
EXPORT_SYMBOL_GPL(ibtrs_heartbeat_set_recv_ts);

static inline s64 timediff_cur_ns(u64 cur_ns)
{
	struct timespec ts = ns_to_timespec(cur_ns);
	struct timespec cur;

	getrawmonotonic(&cur);

	return timespec_to_ns(&cur) - timespec_to_ns(&ts);
}

s64 ibtrs_heartbeat_send_ts_diff_ms(const struct ibtrs_heartbeat *h)
{
	return timediff_cur_ns(atomic64_read(&h->send_ts_ns)) /	NSEC_PER_MSEC;
}
EXPORT_SYMBOL_GPL(ibtrs_heartbeat_send_ts_diff_ms);

s64 ibtrs_heartbeat_recv_ts_diff_ms(const struct ibtrs_heartbeat *h)
{
	return timediff_cur_ns(atomic64_read(&h->recv_ts_ns)) / NSEC_PER_MSEC;
}
EXPORT_SYMBOL_GPL(ibtrs_heartbeat_recv_ts_diff_ms);
