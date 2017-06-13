#define pr_fmt(fmt) KBUILD_MODNAME " L" __stringify(__LINE__) ": " fmt

#include "ibtrs_srv_sysfs.h"
#include "ibtrs_srv_internal.h"
#include <rdma/ibtrs_srv.h>
#include <rdma/ibtrs.h>
#include <rdma/ibtrs_log.h>

static struct kobject *ibtrs_srv_kobj;
static struct kobject *ibtrs_srv_sessions_kobj;

static ssize_t ibtrs_srv_hb_timeout_show(struct kobject *kobj,
					 struct kobj_attribute *attr,
					 char *page)
{
	struct ibtrs_session *sess = container_of(kobj, struct ibtrs_session,
						  kobj);

	return scnprintf(page, PAGE_SIZE, "%u\n", sess->heartbeat.timeout_ms);
}

static ssize_t ibtrs_srv_hb_timeout_store(struct kobject *kobj,
					  struct kobj_attribute *attr,
					  const char *buf, size_t count)
{
	int ret;
	u32 timeout_ms;
	struct ibtrs_session *sess = container_of(kobj, struct ibtrs_session,
						  kobj);

	ret = kstrtouint(buf, 0, &timeout_ms);
	if (ret)
		return ret;

	ret = ibtrs_heartbeat_timeout_validate(timeout_ms);
	if (ret)
		return ret;

	INFO(sess, "%s: changing value from %u to %u\n", attr->attr.name,
	     sess->heartbeat.timeout_ms, timeout_ms);
	ibtrs_set_heartbeat_timeout(&sess->heartbeat, timeout_ms);
	return count;
}

static struct kobj_attribute ibtrs_srv_heartbeat_timeout_ms_attr =
	__ATTR(heartbeat_timeout_ms, 0644,
	       ibtrs_srv_hb_timeout_show, ibtrs_srv_hb_timeout_store);

static ssize_t ibtrs_srv_disconnect_show(struct kobject *kobj,
					 struct kobj_attribute *attr,
					 char *page)
{
	return scnprintf(page, PAGE_SIZE, "Usage: echo 1 > %s\n",
			 attr->attr.name);
}

static ssize_t ibtrs_srv_disconnect_store(struct kobject *kobj,
					  struct kobj_attribute *attr,
					  const char *buf, size_t count)
{
	struct ibtrs_session *sess = container_of(kobj, struct ibtrs_session,
						  kobj);

	if (!sysfs_streq(buf, "1")) {
		ERR(sess, "%s: invalid value: '%s'\n", attr->attr.name, buf);
		return -EINVAL;
	}

	INFO(sess, "%s: Session disconnect requested\n", attr->attr.name);
	ibtrs_srv_queue_close(sess);

	return count;
}

static struct kobj_attribute disconnect_attr =
	__ATTR(disconnect, 0644,
	       ibtrs_srv_disconnect_show, ibtrs_srv_disconnect_store);

static ssize_t ibtrs_srv_current_hca_port_show(struct kobject *kobj,
					       struct kobj_attribute *attr,
					       char *page)
{
	struct ibtrs_session *sess = container_of(kobj, struct ibtrs_session,
						  kobj);
	return ibtrs_srv_current_hca_port_to_str(sess, page, PAGE_SIZE);
}

static struct kobj_attribute current_hca_port_attr =
	__ATTR(current_hca_port, 0444, ibtrs_srv_current_hca_port_show,
	       NULL);

static ssize_t ibtrs_srv_hca_name_show(struct kobject *kobj,
				       struct kobj_attribute *attr,
				       char *page)
{
	struct ibtrs_session *sess = container_of(kobj, struct ibtrs_session,
						  kobj);

	return scnprintf(page, PAGE_SIZE, "%s\n",
			 ibtrs_srv_get_sess_hca_name(sess));
}

static struct kobj_attribute hca_name_attr =
	__ATTR(hca_name, 0444, ibtrs_srv_hca_name_show, NULL);

static ssize_t hostname_show(struct kobject *kobj,
			     struct kobj_attribute *attr, char *page)
{
	struct ibtrs_session *sess = container_of(kobj, struct ibtrs_session,
						  kobj);
	return sprintf(page, "%s\n", sess->hostname);
}

static struct kobj_attribute hostname_attr =
		__ATTR(hostname, 0444, hostname_show, NULL);

static struct attribute *default_sess_attrs[] = {
	&hca_name_attr.attr,
	&hostname_attr.attr,
	&current_hca_port_attr.attr,
	&disconnect_attr.attr,
	&ibtrs_srv_heartbeat_timeout_ms_attr.attr,
	NULL,
};

static struct attribute_group default_sess_attr_group = {
	.attrs = default_sess_attrs,
};

static void ibtrs_srv_sess_release(struct kobject *kobj)
{
	struct ibtrs_session *sess = container_of(kobj, struct ibtrs_session,
						  kobj);

	ibtrs_srv_sess_put(sess);
}

static struct kobj_type ibtrs_srv_sess_ktype = {
	.sysfs_ops	= &kobj_sysfs_ops,
	.release	= ibtrs_srv_sess_release,
};

STAT_ATTR(rdma, ibtrs_srv_stats_rdma_to_str, ibtrs_srv_reset_rdma_stats);

STAT_ATTR(user_ib_messages, ibtrs_srv_stats_user_ib_msgs_to_str,
	  ibtrs_srv_reset_user_ib_msgs_stats);

STAT_ATTR(wc_completion, ibtrs_srv_stats_wc_completion_to_str,
	  ibtrs_srv_reset_wc_completion_stats);

STAT_ATTR(reset_all, ibtrs_srv_reset_all_help, ibtrs_srv_reset_all_stats);

static struct attribute *ibtrs_srv_default_stats_attrs[] = {
	&rdma_attr.attr,
	&user_ib_messages_attr.attr,
	&wc_completion_attr.attr,
	&reset_all_attr.attr,
	NULL,
};

static struct attribute_group ibtrs_srv_default_stats_attr_group = {
	.attrs = ibtrs_srv_default_stats_attrs,
};

static struct kobj_type ibtrs_stats_ktype = {
	.sysfs_ops = &kobj_sysfs_ops,
};

static int ibtrs_srv_create_stats_files(struct ibtrs_session *sess)
{
	int ret;

	ret = kobject_init_and_add(&sess->kobj_stats, &ibtrs_stats_ktype,
				   &sess->kobj, "stats");
	if (ret) {
		ERR(sess,
		    "Failed to init and add sysfs directory for session stats,"
		    " err: %s\n", strerror(ret));
		return ret;
	}

	ret = sysfs_create_group(&sess->kobj_stats,
				 &ibtrs_srv_default_stats_attr_group);
	if (ret) {
		ERR(sess, "Failed to create sysfs group for session stats,"
		    " err: %s\n", strerror(ret));
		goto err;
	}

	return 0;

err:
	kobject_put(&sess->kobj_stats);

	return ret;
}

int ibtrs_srv_create_sess_files(struct ibtrs_session *sess)
{
	int ret;

	pr_debug("creating sysfs files for sess %s\n", sess->addr);

	if (WARN_ON(!ibtrs_srv_sess_get(sess)))
		return -EINVAL;

	ret = kobject_init_and_add(&sess->kobj, &ibtrs_srv_sess_ktype,
				   ibtrs_srv_sessions_kobj, "%s", sess->addr);
	if (ret) {
		ERR(sess, "Failed to init and add sysfs directory for session,"
		    " err: %s\n", strerror(ret));
		ibtrs_srv_sess_put(sess);
		return ret;
	}

	ret = sysfs_create_group(&sess->kobj, &default_sess_attr_group);
	if (ret) {
		ERR(sess, "Failed to create sysfs group for session,"
		    " err: %s\n", strerror(ret));
		goto err;
	}

	ret = ibtrs_srv_create_stats_files(sess);
	if (ret)
		goto err1;

	return 0;

err1:
	sysfs_remove_group(&sess->kobj, &default_sess_attr_group);
err:
	kobject_put(&sess->kobj);

	return ret;
}

int ibtrs_srv_create_sysfs_files(void)
{
	ibtrs_srv_kobj = kobject_create_and_add("ibtrs", kernel_kobj);
	if (!ibtrs_srv_kobj)
		return -ENOMEM;

	ibtrs_srv_sessions_kobj = kobject_create_and_add("sessions",
							 ibtrs_srv_kobj);
	if (!ibtrs_srv_sessions_kobj) {
		kobject_put(ibtrs_srv_kobj);
		return -ENOMEM;
	}

	return 0;
}

void ibtrs_srv_destroy_sysfs_files(void)
{
	kobject_put(ibtrs_srv_sessions_kobj);
	kobject_put(ibtrs_srv_kobj);
}
