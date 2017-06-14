#ifndef _IBNBD_SRV_SYFS_H
#define _IBNBD_SRV_SYFS_H

int ibnbd_srv_create_dev_sysfs(struct ibnbd_srv_dev *dev,
			       struct block_device *bdev,
			       const char *dir_name);

void ibnbd_srv_destroy_dev_sysfs(struct ibnbd_srv_dev *dev);

int ibnbd_srv_create_dev_client_sysfs(struct ibnbd_srv_sess_dev *sess_dev);

void ibnbd_srv_destroy_dev_client_sysfs(struct ibnbd_srv_sess_dev *sess_dev);

int ibnbd_srv_create_sysfs_files(void);

void ibnbd_srv_destroy_sysfs_files(void);

#endif
