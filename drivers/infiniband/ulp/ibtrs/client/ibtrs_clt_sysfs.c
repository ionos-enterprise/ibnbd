#include <linux/types.h>
#include "ibtrs_clt_internal.h"
#include <rdma/ibtrs_clt.h>
#include "ibtrs_clt_sysfs.h"
#include <rdma/ibtrs.h>
#include <rdma/ibtrs_log.h>
#include <rdma/ib.h>

static struct kobject *sessions_kobj;
static struct kobject *ibtrs_kobj;

#define MIN_MAX_RECONN_ATT -1
#define MAX_MAX_RECONN_ATT 9999

static ssize_t ibtrs_clt_max_reconn_attempts_show(struct kobject *kobj,
						  struct kobj_attribute *attr,
						  char *page)
{
	struct ibtrs_session *sess = container_of(kobj, struct ibtrs_session,
						  kobj);

	return sprintf(page, "%d\n",
		       ibtrs_clt_get_max_reconnect_attempts(sess));
}

static ssize_t ibtrs_clt_max_reconn_attempts_store(struct kobject *kobj,
						   struct kobj_attribute *attr,
						   const char *buf,
						   size_t count)
{
	int ret;
	s16 value;
	struct ibtrs_session *sess = container_of(kobj, struct ibtrs_session,
						  kobj);

	ret = kstrtos16(buf, 10, &value);
	if (unlikely(ret)) {
		ERR(sess, "%s: failed to convert string '%s' to int\n",
		    attr->attr.name, buf);
		return ret;
	}
	if (unlikely(value > MAX_MAX_RECONN_ATT ||
		     value < MIN_MAX_RECONN_ATT)) {
		ERR(sess, "%s: invalid range"
		    " (provided: '%s', accepted: min: %d, max: %d)\n",
		    attr->attr.name, buf, MIN_MAX_RECONN_ATT,
		    MAX_MAX_RECONN_ATT);
		return -EINVAL;
	}

	INFO(sess, "%s: changing value from %d to %d\n", attr->attr.name,
	     ibtrs_clt_get_max_reconnect_attempts(sess), value);
	ibtrs_clt_set_max_reconnect_attempts(sess, value);
	return count;
}

static struct kobj_attribute max_ibtrs_clt_reconnect_attempts_attr =
		__ATTR(max_reconnect_attempts, 0644,
		       ibtrs_clt_max_reconn_attempts_show,
		       ibtrs_clt_max_reconn_attempts_store);

static ssize_t ibtrs_clt_hb_timeout_show(struct kobject *kobj,
					 struct kobj_attribute *attr,
					 char *page)
{
	struct ibtrs_session *sess = container_of(kobj, struct ibtrs_session,
						  kobj);

	return scnprintf(page, PAGE_SIZE, "%u\n", sess->heartbeat.timeout_ms);
}

static ssize_t ibtrs_clt_hb_timeout_store(struct kobject *kobj,
					  struct kobj_attribute *attr,
					  const char *buf, size_t count)
{
	int ret;
	u32 timeout_ms;
	struct ibtrs_session *sess = container_of(kobj, struct ibtrs_session,
						  kobj);

	ret = kstrtouint(buf, 0, &timeout_ms);
	if (ret) {
		ERR(sess,
		    "%s: failed to convert string '%s' to unsigned int\n",
		    attr->attr.name, buf);
		return ret;
	}

	ret = ibtrs_heartbeat_timeout_validate(timeout_ms);
	if (ret)
		return ret;

	INFO(sess, "%s: changing value from %u to %u\n", attr->attr.name,
	     sess->heartbeat.timeout_ms, timeout_ms);
	ibtrs_set_heartbeat_timeout(&sess->heartbeat, timeout_ms);
	return count;
}

static struct kobj_attribute ibtrs_clt_heartbeat_timeout_ms_attr =
		__ATTR(heartbeat_timeout_ms, 0644,
		       ibtrs_clt_hb_timeout_show, ibtrs_clt_hb_timeout_store);

static ssize_t ibtrs_clt_state_show(struct kobject *kobj,
				    struct kobj_attribute *attr, char *page)
{
	struct ibtrs_session *sess = container_of(kobj, struct ibtrs_session,
						  kobj);
	if (ibtrs_clt_sess_is_connected(sess))
		return sprintf(page, "connected\n");

	return sprintf(page, "disconnected\n");
}

static struct kobj_attribute ibtrs_clt_state_attr = __ATTR(state, 0444,
							   ibtrs_clt_state_show,
							   NULL);

static ssize_t ibtrs_clt_hostname_show(struct kobject *kobj,
				       struct kobj_attribute *attr, char *page)
{
	struct ibtrs_session *sess = container_of(kobj, struct ibtrs_session,
						  kobj);
	return sprintf(page, "%s\n", sess->hostname);
}

static struct kobj_attribute ibtrs_clt_hostname_attr =
		__ATTR(hostname, 0444, ibtrs_clt_hostname_show, NULL);

static ssize_t ibtrs_clt_reconnect_show(struct kobject *kobj,
					struct kobj_attribute *attr, char *page)
{
	return scnprintf(page, PAGE_SIZE, "Usage: echo 1 > %s\n",
			 attr->attr.name);
}

static ssize_t ibtrs_clt_reconnect_store(struct kobject *kobj,
					 struct kobj_attribute *attr,
					 const char *buf, size_t count)
{
	struct ibtrs_session *sess;
	int ret;

	sess = container_of(kobj, struct ibtrs_session, kobj);

	if (!sysfs_streq(buf, "1")) {
		ERR(sess, "%s: unknown value: '%s'\n", attr->attr.name, buf);
		return -EINVAL;
	}

	ret = ibtrs_clt_reconnect(sess);
	if (ret) {
		ERR(sess, "%s: failed to reconnect session, err: %s\n",
		    attr->attr.name, strerror(ret));
		return ret;
	}
	return count;
}

static struct kobj_attribute ibtrs_clt_reconnect_attr =
		__ATTR(reconnect, 0644, ibtrs_clt_reconnect_show,
		       ibtrs_clt_reconnect_store);

static ssize_t ibtrs_clt_queue_show(struct kobject *kobj,
				    struct kobj_attribute *attr, char *page)
{
	struct ibtrs_session *sess = container_of(kobj, struct ibtrs_session,
						  kobj);
	return scnprintf(page, PAGE_SIZE, "%d\n",
			 ibtrs_clt_get_user_queue_depth(sess));
}

static ssize_t ibtrs_clt_queue_store(struct kobject *kobj,
				     struct kobj_attribute *attr,
				     const char *buf, size_t count)
{
	int res;
	u16 old_queue_depth, queue_depth;
	struct ibtrs_session *sess = container_of(kobj, struct ibtrs_session,
						  kobj);
	res = kstrtou16(buf, 0, &queue_depth);
	if (res) {
		ERR(sess,
		    "%s: failed to convert string '%s' to unsigned int\n",
		    attr->attr.name, buf);
		return res;
	}

	old_queue_depth = ibtrs_clt_get_user_queue_depth(sess);
	res = ibtrs_clt_set_user_queue_depth(sess, queue_depth);
	if (!res) {
		INFO(sess, "%s: changed value from %u to %u\n",
		     attr->attr.name, old_queue_depth, queue_depth);
	} else {
		ERR(sess, "%s: failed to set queue depth, err: %s\n",
		    attr->attr.name, strerror(res));
		return res;
	}
	return count;
}

STAT_ATTR(cpu_migration, ibtrs_clt_stats_migration_cnt_to_str,
	  ibtrs_clt_reset_cpu_migr_stats);

STAT_ATTR(sg_entries, ibtrs_clt_stats_sg_list_distr_to_str,
	  ibtrs_clt_reset_sg_list_distr_stats);

STAT_ATTR(reconnects, ibtrs_clt_stats_reconnects_to_str,
	  ibtrs_clt_reset_reconnects_stat);

STAT_ATTR(rdma_lat, ibtrs_clt_stats_rdma_lat_distr_to_str,
	  ibtrs_clt_reset_rdma_lat_distr_stats);

STAT_ATTR(user_ib_messages, ibtrs_clt_stats_user_ib_msgs_to_str,
	  ibtrs_clt_reset_user_ib_msgs_stats);

STAT_ATTR(wc_completion, ibtrs_clt_stats_wc_completion_to_str,
	  ibtrs_clt_reset_wc_comp_stats);

STAT_ATTR(rdma, ibtrs_clt_stats_rdma_to_str,
	  ibtrs_clt_reset_rdma_stats);

STAT_ATTR(reset_all, ibtrs_clt_reset_all_help, ibtrs_clt_reset_all_stats);

static struct attribute *ibtrs_clt_default_stats_attrs[] = {
	&sg_entries_attr.attr,
	&cpu_migration_attr.attr,
	&reconnects_attr.attr,
	&rdma_lat_attr.attr,
	&user_ib_messages_attr.attr,
	&wc_completion_attr.attr,
	&rdma_attr.attr,
	&reset_all_attr.attr,
	NULL,
};

static struct attribute_group ibtrs_clt_default_stats_attr_group = {
	.attrs = ibtrs_clt_default_stats_attrs,
};

static struct kobj_type ibtrs_stats_ktype = {
	.sysfs_ops = &kobj_sysfs_ops,
};

static int ibtrs_clt_create_stats_files(struct kobject *kobj,
					struct kobject *kobj_stats)
{
	int ret;

	ret = kobject_init_and_add(kobj_stats, &ibtrs_stats_ktype, kobj,
				   "stats");
	if (ret) {
		pr_err("Failed to init and add stats kobject, err: %s\n",
		       strerror(ret));
		return ret;
	}

	ret = sysfs_create_group(kobj_stats,
				 &ibtrs_clt_default_stats_attr_group);
	if (ret) {
		pr_err("failed to create stats sysfs group, err: %s\n",
		       strerror(ret));
		goto err;
	}

	return 0;

err:
	kobject_del(kobj_stats);
	kobject_put(kobj_stats);

	return ret;
}

static struct kobj_attribute ibtrs_clt_queue_depth_attr =
		__ATTR(queue_depth, 0644, ibtrs_clt_queue_show,
		       ibtrs_clt_queue_store);

static struct attribute *ibtrs_clt_default_sess_attrs[] = {
	&max_ibtrs_clt_reconnect_attempts_attr.attr,
	&ibtrs_clt_heartbeat_timeout_ms_attr.attr,
	&ibtrs_clt_state_attr.attr,
	&ibtrs_clt_hostname_attr.attr,
	&ibtrs_clt_reconnect_attr.attr,
	&ibtrs_clt_queue_depth_attr.attr,
	NULL,
};

static struct attribute_group ibtrs_clt_default_sess_attr_group = {
	.attrs = ibtrs_clt_default_sess_attrs,
};

static struct kobj_type ibtrs_session_ktype = {
	.sysfs_ops = &kobj_sysfs_ops,
};

int ibtrs_clt_create_sess_files(struct kobject *kobj,
				struct kobject *kobj_stats, const char *ip)
{
	int ret;

	ret = kobject_init_and_add(kobj, &ibtrs_session_ktype, sessions_kobj,
				   "%s", ip);
	if (ret) {
		pr_err("Failed to create session kobject, err: %s\n",
		       strerror(ret));
		return ret;
	}

	ret = sysfs_create_group(kobj, &ibtrs_clt_default_sess_attr_group);
	if (ret) {
		pr_err("Failed to create session sysfs group, err: %s\n",
		       strerror(ret));
		goto err;
	}

	ret = ibtrs_clt_create_stats_files(kobj, kobj_stats);
	if (ret) {
		pr_err("Failed to create stats files, err: %s\n",
		       strerror(ret));
		goto err1;
	}

	return 0;

err1:
	sysfs_remove_group(kobj, &ibtrs_clt_default_sess_attr_group);
err:
	kobject_del(kobj);
	kobject_put(kobj);

	return ret;
}

void ibtrs_clt_destroy_sess_files(struct kobject *kobj,
				  struct kobject *kobj_stats)
{
	if (kobj->state_in_sysfs) {
		kobject_del(kobj_stats);
		kobject_put(kobj_stats);
		kobject_del(kobj);
		kobject_put(kobj);
	}
}

int ibtrs_clt_create_sysfs_files(void)
{
	ibtrs_kobj = kobject_create_and_add("ibtrs", kernel_kobj);
	if (!ibtrs_kobj) {
		pr_err("Failed to create 'ibtrs' kobject\n");
		return -ENOMEM;
	}

	sessions_kobj = kobject_create_and_add("sessions", ibtrs_kobj);
	if (!sessions_kobj) {
		pr_err("Failed to create 'sessions' kobject\n");
		kobject_del(ibtrs_kobj);
		kobject_put(ibtrs_kobj);
		return -ENOMEM;
	}
	return 0;
}

void ibtrs_clt_destroy_sysfs_files(void)
{
	kobject_del(sessions_kobj);
	kobject_del(ibtrs_kobj);
	kobject_put(sessions_kobj);
	kobject_put(ibtrs_kobj);
}
