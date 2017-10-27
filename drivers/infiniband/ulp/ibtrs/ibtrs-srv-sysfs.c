#define pr_fmt(fmt) KBUILD_MODNAME " L" __stringify(__LINE__) ": " fmt

#include "ibtrs-pri.h"
#include "ibtrs-srv.h"
#include "ibtrs-log.h"

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
	struct ibtrs_srv_sess *sess;

	sess = container_of(kobj, struct ibtrs_srv_sess, kobj);
	if (!sysfs_streq(buf, "1")) {
		ibtrs_err(sess, "%s: invalid value: '%s'\n", attr->attr.name, buf);
		return -EINVAL;
	}

	ibtrs_info(sess, "%s: Session disconnect requested\n", attr->attr.name);
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
	struct ibtrs_srv_sess *sess;

	sess = container_of(kobj, struct ibtrs_srv_sess, kobj);

	return ibtrs_srv_current_hca_port_to_str(sess, page, PAGE_SIZE);
}

static struct kobj_attribute current_hca_port_attr =
	__ATTR(current_hca_port, 0444, ibtrs_srv_current_hca_port_show,
	       NULL);

static ssize_t ibtrs_srv_hca_name_show(struct kobject *kobj,
				       struct kobj_attribute *attr,
				       char *page)
{
	struct ibtrs_srv_sess *sess;

	sess = container_of(kobj, struct ibtrs_srv_sess, kobj);

	return scnprintf(page, PAGE_SIZE, "%s\n",
			 ibtrs_srv_get_sess_hca_name(sess));
}

static struct kobj_attribute hca_name_attr =
	__ATTR(hca_name, 0444, ibtrs_srv_hca_name_show, NULL);

static ssize_t addr_show(struct kobject *kobj,
			     struct kobj_attribute *attr, char *page)
{
	struct ibtrs_srv_sess *sess;
	char str_addr[MAXHOSTNAMELEN];
	sess = container_of(kobj, struct ibtrs_srv_sess, kobj);

	sockaddr_to_str((struct sockaddr *)&sess->s.addr.sockaddr,
			str_addr, sizeof(str_addr));

	return sprintf(page, "%s\n", str_addr);
}

static struct kobj_attribute addr_attr =
	__ATTR(addr, 0444, addr_show, NULL);

static struct attribute *default_sess_attrs[] = {
	&hca_name_attr.attr,
	&addr_attr.attr,
	&current_hca_port_attr.attr,
	&disconnect_attr.attr,
	NULL,
};

static struct attribute_group default_sess_attr_group = {
	.attrs = default_sess_attrs,
};

static struct kobj_type ibtrs_srv_sess_ktype = {
	.sysfs_ops	= &kobj_sysfs_ops,
};

STAT_ATTR(struct ibtrs_srv_sess, rdma,
	  ibtrs_srv_stats_rdma_to_str,
	  ibtrs_srv_reset_rdma_stats);

STAT_ATTR(struct ibtrs_srv_sess, user_ib_messages,
	  ibtrs_srv_stats_user_ib_msgs_to_str,
	  ibtrs_srv_reset_user_ib_msgs_stats);

STAT_ATTR(struct ibtrs_srv_sess, wc_completion,
	  ibtrs_srv_stats_wc_completion_to_str,
	  ibtrs_srv_reset_wc_completion_stats);

STAT_ATTR(struct ibtrs_srv_sess, reset_all,
	  ibtrs_srv_reset_all_help,
	  ibtrs_srv_reset_all_stats);

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

static int ibtrs_srv_create_stats_files(struct ibtrs_srv_sess *sess)
{
	int ret;

	ret = kobject_init_and_add(&sess->kobj_stats, &ibtrs_stats_ktype,
				   &sess->kobj, "stats");
	if (ret) {
		ibtrs_err(sess,
			  "Failed to init and add sysfs directory for session stats,"
			  " err: %d\n", ret);
		return ret;
	}

	ret = sysfs_create_group(&sess->kobj_stats,
				 &ibtrs_srv_default_stats_attr_group);
	if (ret) {
		ibtrs_err(sess, "Failed to create sysfs group for session stats,"
			  " err: %d\n", ret);
		goto err;
	}

	return 0;

err:
	kobject_put(&sess->kobj_stats);

	return ret;
}

static struct kobject *ibtrs_srv_kobj;
static struct kobject *ibtrs_srv_sessions_kobj;

int ibtrs_srv_create_sess_files(struct ibtrs_srv_sess *sess)
{
	int ret;

	ret = kobject_init_and_add(&sess->kobj, &ibtrs_srv_sess_ktype,
				   ibtrs_srv_sessions_kobj, "%s",
				   sess->s.sessname);
	if (ret) {
		ibtrs_err(sess, "Failed to init and add sysfs directory for session,"
			  " err: %d\n", ret);
		return ret;
	}

	ret = sysfs_create_group(&sess->kobj, &default_sess_attr_group);
	if (ret) {
		ibtrs_err(sess, "Failed to create sysfs group for session,"
			  " err: %d\n", ret);
		goto err;
	}

	ret = ibtrs_srv_create_stats_files(sess);
	if (ret)
		goto err1;

	return 0;

err1:
	sysfs_remove_group(&sess->kobj, &default_sess_attr_group);
err:
	kobject_del(&sess->kobj);
	kobject_put(&sess->kobj);

	return ret;
}

void ibtrs_srv_destroy_sess_files(struct ibtrs_srv_sess *sess)
{
	if (sess->kobj.state_in_sysfs) {
		kobject_del(&sess->kobj_stats);
		kobject_put(&sess->kobj_stats);
		kobject_del(&sess->kobj);
		kobject_put(&sess->kobj);
	}
}

int ibtrs_srv_create_sysfs_files(void)
{
	ibtrs_srv_kobj = kobject_create_and_add(KBUILD_MODNAME, kernel_kobj);
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
