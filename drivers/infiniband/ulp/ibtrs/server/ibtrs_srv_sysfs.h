#ifndef _IBTRS_SRV_SYFS_H
#define _IBTRS_SRV_SYFS_H

#include <linux/kobject.h>
#include "ibtrs_srv_internal.h"

int ibtrs_srv_create_sysfs_files(void);

void ibtrs_srv_destroy_sysfs_files(void);

int ibtrs_srv_create_sess_files(struct ibtrs_session *sess);

#endif
