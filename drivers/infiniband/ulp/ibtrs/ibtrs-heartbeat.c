#define pr_fmt(fmt) KBUILD_MODNAME " L" __stringify(__LINE__) ": " fmt

#include <rdma/ibtrs.h>
#include <rdma/ibtrs_log.h>

void ibtrs_heartbeat_set_send_ts(struct ibtrs_heartbeat *h)
{
	struct timespec ts = CURRENT_TIME;

	atomic64_set(&h->send_ts_ms, timespec_to_ms(&ts));
}
EXPORT_SYMBOL_GPL(ibtrs_heartbeat_set_send_ts);

void ibtrs_set_last_heartbeat(struct ibtrs_heartbeat *h)
{
	struct timespec ts = CURRENT_TIME;

	atomic64_set(&h->recv_ts_ms, timespec_to_ms(&ts));
}
EXPORT_SYMBOL_GPL(ibtrs_set_last_heartbeat);

static inline u64 timediff_cur_ms(u64 cur_ms)
{
	struct timespec cur = CURRENT_TIME;
	struct timespec ts = ns_to_timespec(cur_ms * NSEC_PER_MSEC);

	if (timespec_compare(&cur, &ts) < 0)
		return timespec_to_ms(&ts) - timespec_to_ms(&cur);
	else
		return timespec_to_ms(&cur) - timespec_to_ms(&ts);
}

u64 ibtrs_heartbeat_send_ts_diff_ms(const struct ibtrs_heartbeat *h)
{
	return timediff_cur_ms(atomic64_read(&h->send_ts_ms));
}
EXPORT_SYMBOL_GPL(ibtrs_heartbeat_send_ts_diff_ms);

static inline u64 ibtrs_recv_ts_ms_diff_ms(const struct ibtrs_heartbeat *h)
{
	return timediff_cur_ms(atomic64_read(&h->recv_ts_ms));
}

void ibtrs_set_heartbeat_timeout(struct ibtrs_heartbeat *h, u32 timeout_ms)
{
	h->timeout_ms = timeout_ms;
	h->warn_timeout_ms = (timeout_ms >> 1) + (timeout_ms >> 2);
}
EXPORT_SYMBOL_GPL(ibtrs_set_heartbeat_timeout);

void ibtrs_heartbeat_warn(const struct ibtrs_heartbeat *h)
{
	u64 diff = ibtrs_recv_ts_ms_diff_ms(h);

	pr_debug("last heartbeat message from %s was received %lu, %llums"
	    " ago\n", ibtrs_prefix(h), atomic64_read(&h->recv_ts_ms), diff);

	if (diff >= h->warn_timeout_ms)
		WRN(h, "Last Heartbeat message received %llums ago,"
		       " timeout: %ums\n", diff, h->timeout_ms);
}
EXPORT_SYMBOL_GPL(ibtrs_heartbeat_warn);

bool ibtrs_heartbeat_timeout_is_expired(const struct ibtrs_heartbeat *h)
{
	u64 diff;

	if (h->timeout_ms == 0)
		return false;

	diff = ibtrs_recv_ts_ms_diff_ms(h);

	pr_debug("last heartbeat message from %s received %lu, %llums ago\n",
	    ibtrs_prefix(h), atomic64_read(&h->recv_ts_ms), diff);

	if (diff >= h->timeout_ms) {
		ERR(h, "Heartbeat timeout expired, no heartbeat received "
		       "for %llums, timeout: %ums\n", diff,
		       h->timeout_ms);
		return true;
	}

	return false;
}
EXPORT_SYMBOL_GPL(ibtrs_heartbeat_timeout_is_expired);
