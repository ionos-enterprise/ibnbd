#include <linux/types.h>
#include <rdma/ibtrs.h>

#include "ibtrs-pri.h"
#include "ibtrs-clt.h"
#include "ibtrs-log.h"

static struct kobject *sessions_kobj;
static struct kobject *ibtrs_kobj;

#define MIN_MAX_RECONN_ATT -1
#define MAX_MAX_RECONN_ATT 9999

static ssize_t ibtrs_clt_max_reconn_attempts_show(struct kobject *kobj,
						  struct kobj_attribute *attr,
						  char *page)
{
	struct ibtrs_clt_sess *sess;

	sess = container_of(kobj, struct ibtrs_clt_sess, kobj);

	return sprintf(page, "%d\n",
		       ibtrs_clt_get_max_reconnect_attempts(sess));
}

static ssize_t ibtrs_clt_max_reconn_attempts_store(struct kobject *kobj,
						   struct kobj_attribute *attr,
						   const char *buf,
						   size_t count)
{
	struct ibtrs_clt_sess *sess;
	s16 value;
	int ret;

	sess = container_of(kobj, struct ibtrs_clt_sess, kobj);
	ret = kstrtos16(buf, 10, &value);
	if (unlikely(ret)) {
		ibtrs_err(sess, "%s: failed to convert string '%s' to int\n",
			  attr->attr.name, buf);
		return ret;
	}
	if (unlikely(value > MAX_MAX_RECONN_ATT ||
		     value < MIN_MAX_RECONN_ATT)) {
		ibtrs_err(sess, "%s: invalid range"
			  " (provided: '%s', accepted: min: %d, max: %d)\n",
			  attr->attr.name, buf, MIN_MAX_RECONN_ATT,
			  MAX_MAX_RECONN_ATT);
		return -EINVAL;
	}

	ibtrs_info(sess, "%s: changing value from %d to %d\n", attr->attr.name,
		   ibtrs_clt_get_max_reconnect_attempts(sess), value);
	ibtrs_clt_set_max_reconnect_attempts(sess, value);
	return count;
}

static struct kobj_attribute max_ibtrs_clt_reconnect_attempts_attr =
	__ATTR(max_reconnect_attempts, 0644,
	       ibtrs_clt_max_reconn_attempts_show,
	       ibtrs_clt_max_reconn_attempts_store);

static ssize_t ibtrs_clt_state_show(struct kobject *kobj,
				    struct kobj_attribute *attr, char *page)
{
	struct ibtrs_clt_sess *sess;

	sess = container_of(kobj, struct ibtrs_clt_sess, kobj);
	if (ibtrs_clt_sess_is_connected(sess))
		return sprintf(page, "connected\n");

	return sprintf(page, "disconnected\n");
}

static struct kobj_attribute ibtrs_clt_state_attr = __ATTR(state, 0444,
							   ibtrs_clt_state_show,
							   NULL);

static ssize_t ibtrs_clt_addr_show(struct kobject *kobj,
				       struct kobj_attribute *attr, char *page)
{
	struct ibtrs_clt_sess *sess;
	char str_addr[MAXHOSTNAMELEN];

	sess = container_of(kobj, struct ibtrs_clt_sess, kobj);

	sockaddr_to_str((struct sockaddr *)&sess->s.addr.sockaddr,
			str_addr, sizeof(str_addr));

	return sprintf(page, "%s\n", str_addr);
}

static struct kobj_attribute ibtrs_clt_addr_attr =
	__ATTR(addr, 0444, ibtrs_clt_addr_show, NULL);

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
	struct ibtrs_clt_sess *sess;
	int ret;

	sess = container_of(kobj, struct ibtrs_clt_sess, kobj);
	if (!sysfs_streq(buf, "1")) {
		ibtrs_err(sess, "%s: unknown value: '%s'\n", attr->attr.name, buf);
		return -EINVAL;
	}

	ret = ibtrs_clt_reconnect(sess);
	if (ret) {
		ibtrs_err(sess, "%s: failed to reconnect session, err: %d\n",
			  attr->attr.name, ret);
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
	struct ibtrs_clt_sess *sess;

	sess = container_of(kobj, struct ibtrs_clt_sess, kobj);

	return scnprintf(page, PAGE_SIZE, "%d\n",
			 ibtrs_clt_get_user_queue_depth(sess));
}

static ssize_t ibtrs_clt_queue_store(struct kobject *kobj,
				     struct kobj_attribute *attr,
				     const char *buf, size_t count)
{
	int res;
	u16 old_queue_depth, queue_depth;
	struct ibtrs_clt_sess *sess;

	sess = container_of(kobj, struct ibtrs_clt_sess, kobj);
	res = kstrtou16(buf, 0, &queue_depth);
	if (res) {
		ibtrs_err(sess,
			  "%s: failed to convert string '%s' to unsigned int\n",
			  attr->attr.name, buf);
		return res;
	}

	old_queue_depth = ibtrs_clt_get_user_queue_depth(sess);
	res = ibtrs_clt_set_user_queue_depth(sess, queue_depth);
	if (!res) {
		ibtrs_info(sess, "%s: changed value from %u to %u\n",
			   attr->attr.name, old_queue_depth, queue_depth);
	} else {
		ibtrs_err(sess, "%s: failed to set queue depth, err: %d\n",
			  attr->attr.name, res);
		return res;
	}
	return count;
}

STAT_ATTR(struct ibtrs_clt_sess, cpu_migration,
	  ibtrs_clt_stats_migration_cnt_to_str,
	  ibtrs_clt_reset_cpu_migr_stats);

STAT_ATTR(struct ibtrs_clt_sess, sg_entries,
	  ibtrs_clt_stats_sg_list_distr_to_str,
	  ibtrs_clt_reset_sg_list_distr_stats);

STAT_ATTR(struct ibtrs_clt_sess, reconnects,
	  ibtrs_clt_stats_reconnects_to_str,
	  ibtrs_clt_reset_reconnects_stat);

STAT_ATTR(struct ibtrs_clt_sess, rdma_lat,
	  ibtrs_clt_stats_rdma_lat_distr_to_str,
	  ibtrs_clt_reset_rdma_lat_distr_stats);

STAT_ATTR(struct ibtrs_clt_sess, user_ib_messages,
	  ibtrs_clt_stats_user_ib_msgs_to_str,
	  ibtrs_clt_reset_user_ib_msgs_stats);

STAT_ATTR(struct ibtrs_clt_sess, wc_completion,
	  ibtrs_clt_stats_wc_completion_to_str,
	  ibtrs_clt_reset_wc_comp_stats);

STAT_ATTR(struct ibtrs_clt_sess, rdma,
	  ibtrs_clt_stats_rdma_to_str,
	  ibtrs_clt_reset_rdma_stats);

STAT_ATTR(struct ibtrs_clt_sess, reset_all,
	  ibtrs_clt_reset_all_help,
	  ibtrs_clt_reset_all_stats);

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
		pr_err("Failed to init and add stats kobject, err: %d\n",
		       ret);
		return ret;
	}

	ret = sysfs_create_group(kobj_stats,
				 &ibtrs_clt_default_stats_attr_group);
	if (ret) {
		pr_err("failed to create stats sysfs group, err: %d\n",
		       ret);
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
	&ibtrs_clt_state_attr.attr,
	&ibtrs_clt_addr_attr.attr,
	&ibtrs_clt_reconnect_attr.attr,
	&ibtrs_clt_queue_depth_attr.attr,
	NULL,
};

static struct attribute_group ibtrs_clt_default_sess_attr_group = {
	.attrs = ibtrs_clt_default_sess_attrs,
};

static struct kobj_type ibtrs_clt_sess_ktype = {
	.sysfs_ops = &kobj_sysfs_ops,
};

int ibtrs_clt_create_sess_files(struct ibtrs_clt_sess *sess)
{
	int ret;

	ret = kobject_init_and_add(&sess->kobj, &ibtrs_clt_sess_ktype,
				   sessions_kobj, "%s", sess->s.sessname);
	if (ret) {
		pr_err("Failed to create session kobject, err: %d\n",
		       ret);
		return ret;
	}

	ret = sysfs_create_group(&sess->kobj,
				 &ibtrs_clt_default_sess_attr_group);
	if (ret) {
		pr_err("Failed to create session sysfs group, err: %d\n",
		       ret);
		goto err;
	}

	ret = ibtrs_clt_create_stats_files(&sess->kobj, &sess->kobj_stats);
	if (ret) {
		pr_err("Failed to create stats files, err: %d\n",
		       ret);
		goto err1;
	}

	return 0;

err1:
	sysfs_remove_group(&sess->kobj, &ibtrs_clt_default_sess_attr_group);
err:
	kobject_del(&sess->kobj);
	kobject_put(&sess->kobj);

	return ret;
}

void ibtrs_clt_destroy_sess_files(struct ibtrs_clt_sess *sess)
{
	if (sess->kobj.state_in_sysfs) {
		kobject_del(&sess->kobj_stats);
		kobject_put(&sess->kobj_stats);
		kobject_del(&sess->kobj);
		kobject_put(&sess->kobj);
	}
}

int ibtrs_clt_create_sysfs_files(void)
{
	ibtrs_kobj = kobject_create_and_add(KBUILD_MODNAME, kernel_kobj);
	if (!ibtrs_kobj)
		return -ENOMEM;

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
