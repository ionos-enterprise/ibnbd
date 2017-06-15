#ifndef _IBNBD_CLT_SYSFS_H
#define _IBNBD_CLT_SYSFS_H

#include "ibnbd-clt.h"

int ibnbd_clt_create_sysfs_files(void);

void ibnbd_clt_destroy_sysfs_files(void);
void ibnbd_clt_destroy_default_group(void);
void ibnbd_clt_schedule_dev_destroy(struct ibnbd_clt_dev *dev);

void ibnbd_clt_remove_dev_symlink(struct ibnbd_clt_dev *dev);

int ibnbd_clt_get_sess(struct ibnbd_clt_session *sess);

void ibnbd_clt_put_sess(struct ibnbd_clt_session *sess);

#endif
