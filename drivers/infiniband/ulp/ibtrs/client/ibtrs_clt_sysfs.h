#ifndef _IBTRS_CLT_SYFS_H
#define _IBTRS_CLT_SYFS_H

#include <linux/kobject.h>

int ibtrs_clt_create_sysfs_files(void);

void ibtrs_clt_destroy_sysfs_files(void);

int ibtrs_clt_create_sess_files(struct kobject *kobj, struct kobject *kobj_sess,
				const char *ip);

void ibtrs_clt_destroy_sess_files(struct kobject *kobj,
				  struct kobject *kobj_sess);

#endif
