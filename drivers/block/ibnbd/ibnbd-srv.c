#define pr_fmt(fmt) KBUILD_MODNAME " L" __stringify(__LINE__) ": " fmt

#include <linux/module.h>
#include <linux/blkdev.h>
#include <linux/idr.h>

#include <rdma/ibtrs.h>
#include <rdma/ibtrs_srv.h>

#include "ibnbd-srv.h"
#include "ibnbd-srv-log.h"
#include "ibnbd-srv-sysfs.h"
#include "ibnbd-srv-dev.h"
#include "ibnbd.h"
#include "ibnbd-proto.h"


MODULE_AUTHOR("ibnbd@profitbricks.com");
MODULE_VERSION(__stringify(IBNBD_VER));
MODULE_DESCRIPTION("InfiniBand Network Block Device Server");
MODULE_LICENSE("GPL");

#define DEFAULT_DEV_SEARCH_PATH "/"

static char dev_search_path[PATH_MAX] = DEFAULT_DEV_SEARCH_PATH;

static int dev_search_path_set(const char *val, const struct kernel_param *kp)
{
	char *dup;

	if (strlen(val) >= sizeof(dev_search_path))
		return -EINVAL;

	dup = kstrdup(val, GFP_KERNEL);

	if (dup[strlen(dup) - 1] == '\n')
		dup[strlen(dup) - 1] = '\0';

	strlcpy(dev_search_path, dup, sizeof(dev_search_path));

	kfree(dup);
	pr_info("dev_search_path changed to '%s'\n", dev_search_path);

	return 0;
}

static struct kparam_string dev_search_path_kparam_str = {
	.maxlen	= sizeof(dev_search_path),
	.string	= dev_search_path
};

static const struct kernel_param_ops dev_search_path_ops = {
	.set	= dev_search_path_set,
	.get	= param_get_string,
};

module_param_cb(dev_search_path, &dev_search_path_ops,
		&dev_search_path_kparam_str, 0444);
MODULE_PARM_DESC(dev_search_path, "Sets the device_search_path."
		 " When a device is mapped this path is prepended to the"
		 " device_path from the map_device operation."
		 " (default: " DEFAULT_DEV_SEARCH_PATH ")");

static int def_io_mode = IBNBD_BLOCKIO;
module_param(def_io_mode, int, 0444);
MODULE_PARM_DESC(def_io_mode, "By default, export devices in"
		 " blockio(" __stringify(_IBNBD_BLOCKIO) ") or"
		 " fileio(" __stringify(_IBNBD_FILEIO) ") mode."
		 " (default: " __stringify(_IBNBD_BLOCKIO) " (blockio))");

static DEFINE_MUTEX(sess_lock);
static DEFINE_SPINLOCK(dev_lock);

static LIST_HEAD(sess_list);
static LIST_HEAD(dev_list);


struct ibnbd_io_private {
	struct ibtrs_ops_id		*id;
	struct ibnbd_srv_sess_dev	*sess_dev;
};

static struct ibtrs_srv_ops ibnbd_srv_ops;

static void ibnbd_sess_dev_release(struct kref *kref)
{
	struct ibnbd_srv_sess_dev *sess_dev;

	sess_dev = container_of(kref, struct ibnbd_srv_sess_dev, kref);
	complete(sess_dev->destroy_comp);
}

static inline void ibnbd_put_sess_dev(struct ibnbd_srv_sess_dev *sess_dev)
{
	kref_put(&sess_dev->kref, ibnbd_sess_dev_release);
}

static void ibnbd_endio(void *priv, int error)
{
	int ret;
	struct ibnbd_io_private *ibnbd_priv = priv;
	struct ibnbd_srv_sess_dev *sess_dev = ibnbd_priv->sess_dev;

	ibnbd_put_sess_dev(sess_dev);

	ret = ibtrs_srv_resp_rdma(ibnbd_priv->id, error);
	if (unlikely(ret))
		ERR_RL(sess_dev, "Sending I/O response failed, err: %s\n",
		       strerror(ret));

	kfree(priv);
}

static struct ibnbd_srv_sess_dev *
ibnbd_get_sess_dev(int dev_id, struct ibnbd_srv_session *srv_sess)
{
	struct ibnbd_srv_sess_dev *sess_dev;
	int ret = 0;

	read_lock(&srv_sess->index_lock);
	sess_dev = idr_find(&srv_sess->index_idr, dev_id);
	if (likely(sess_dev))
		ret = kref_get_unless_zero(&sess_dev->kref);
	read_unlock(&srv_sess->index_lock);

	if (unlikely(!sess_dev || !ret))
		return ERR_PTR(-ENXIO);

	return sess_dev;
}

static int process_rdma(struct ibtrs_session *sess,
			struct ibnbd_srv_session *srv_sess,
			struct ibtrs_ops_id *id, void *data, u32 len)
{
	struct ibnbd_io_private *priv;
	struct ibnbd_srv_sess_dev *sess_dev;
	struct ibnbd_msg_io *msg;
	size_t data_len;
	int err;
	u32 dev_id;

	priv = kmalloc(sizeof(*priv), GFP_KERNEL);
	if (unlikely(!priv))
		return -ENOMEM;

	data_len = len - sizeof(*msg);
	/* ibnbd message is after disk data */
	msg = (struct ibnbd_msg_io *)(data + data_len);

	dev_id = msg->device_id;

	sess_dev = ibnbd_get_sess_dev(dev_id, srv_sess);
	if (unlikely(IS_ERR(sess_dev))) {
		pr_err_ratelimited("Got I/O request from client %s for unknown device id"
			  " %d\n", srv_sess->str_addr, dev_id);
		err = -ENOTCONN;
		goto err;
	}

	priv->sess_dev = sess_dev;
	priv->id = id;

	err = ibnbd_dev_submit_io(sess_dev->ibnbd_dev, msg->sector, data,
				  data_len, msg->bi_size, msg->rw, priv);
	if (unlikely(err)) {
		ERR(sess_dev, "Submitting I/O to device failed, err: %s\n",
		    strerror(err));
		goto sess_dev_put;
	}

	return 0;

sess_dev_put:
	ibnbd_put_sess_dev(sess_dev);
err:
	kfree(priv);
	return err;
}

static void destroy_device(struct ibnbd_srv_dev *dev)
{
	WARN(!list_empty(&dev->sess_dev_list),
	     "Device %s is being destroyed but still in use!\n",
	     dev->id);

	spin_lock(&dev_lock);
	list_del(&dev->list);
	spin_unlock(&dev_lock);

	if (dev->dev_kobj.state_in_sysfs)
		/*
		 * Destroy kobj only if it was really created.
		 * The following call should be sync, because
		 *  we free the memory afterwards.
		 */
		ibnbd_srv_destroy_dev_sysfs(dev);

	kfree(dev);
}

static void destroy_device_cb(struct kref *kref)
{
	struct ibnbd_srv_dev *dev;

	dev = container_of(kref, struct ibnbd_srv_dev, kref);

	destroy_device(dev);
}

static void ibnbd_put_srv_dev(struct ibnbd_srv_dev *dev)
{
	kref_put(&dev->kref, destroy_device_cb);
}

static void ibnbd_destroy_sess_dev(struct ibnbd_srv_sess_dev *sess_dev,
				   bool locked)
{
	struct completion dc;

	write_lock(&sess_dev->sess->index_lock);
	idr_remove(&sess_dev->sess->index_idr, sess_dev->device_id);
	write_unlock(&sess_dev->sess->index_lock);

	init_completion(&dc);
	sess_dev->destroy_comp = &dc;
	ibnbd_put_sess_dev(sess_dev);
	wait_for_completion(&dc);

	ibnbd_dev_close(sess_dev->ibnbd_dev);
	if (!locked)
		mutex_lock(&sess_dev->sess->lock);
	list_del(&sess_dev->sess_list);
	if (!locked)
		mutex_unlock(&sess_dev->sess->lock);

	mutex_lock(&sess_dev->dev->lock);
	list_del(&sess_dev->dev_list);
	if (sess_dev->open_flags & FMODE_WRITE)
		sess_dev->dev->open_write_cnt--;
	mutex_unlock(&sess_dev->dev->lock);

	ibnbd_put_srv_dev(sess_dev->dev);

	INFO(sess_dev, "Device closed\n");
	kfree(sess_dev);
}

static void destroy_sess(struct ibnbd_srv_session *srv_sess)
{
	struct ibnbd_srv_sess_dev *sess_dev, *tmp;

	srv_sess->state = SESS_STATE_DISCONNECTED;

	if (list_empty(&srv_sess->sess_dev_list))
		goto out;

	mutex_lock(&srv_sess->lock);
	list_for_each_entry_safe(sess_dev, tmp, &srv_sess->sess_dev_list,
				 sess_list) {
		ibnbd_srv_destroy_dev_client_sysfs(sess_dev);
		ibnbd_destroy_sess_dev(sess_dev, true);
	}
	mutex_unlock(&srv_sess->lock);

out:
	idr_destroy(&srv_sess->index_idr);
	bioset_free(srv_sess->sess_bio_set);

	pr_info("IBTRS Session to %s disconnected\n", srv_sess->str_addr);

	mutex_lock(&sess_lock);
	list_del(&srv_sess->list);
	mutex_unlock(&sess_lock);

	kfree(srv_sess);
}

static int create_sess(struct ibtrs_session *sess)
{
	struct ibnbd_srv_session *srv_sess;

	srv_sess = kzalloc(sizeof(*srv_sess), GFP_KERNEL);
	if (!srv_sess) {
		pr_err("Allocating srv_session for client %s failed\n",
		       ibtrs_srv_get_sess_addr(sess));
		return -ENOMEM;
	}
	srv_sess->queue_depth = ibtrs_srv_get_sess_qdepth(sess);
	srv_sess->sess_bio_set =  bioset_create(srv_sess->queue_depth, 0);
	if (!srv_sess->sess_bio_set) {
		pr_err("Allocating srv_session for client %s failed\n",
		       ibtrs_srv_get_sess_addr(sess));
		kfree(srv_sess);
		return -ENOMEM;
	}

	idr_init(&srv_sess->index_idr);
	rwlock_init(&srv_sess->index_lock);
	INIT_LIST_HEAD(&srv_sess->sess_dev_list);
	mutex_init(&srv_sess->lock);
	srv_sess->state = SESS_STATE_CONNECTED;
	mutex_lock(&sess_lock);
	list_add(&srv_sess->list, &sess_list);
	mutex_unlock(&sess_lock);

	srv_sess->ibtrs_sess = sess;
	srv_sess->queue_depth = ibtrs_srv_get_sess_qdepth(sess);
	strlcpy(srv_sess->str_addr, ibtrs_srv_get_sess_addr(sess),
		sizeof(srv_sess->str_addr));

	ibtrs_srv_set_sess_priv(sess, srv_sess);

	return 0;
}

static int ibnbd_srv_sess_ev(struct ibtrs_session *sess,
			     enum ibtrs_srv_sess_ev ev, void *priv)
{
	struct ibnbd_srv_session *srv_sess = priv;

	switch (ev) {
	case IBTRS_SRV_SESS_EV_CONNECTED:
		pr_info("IBTRS session to %s established\n",
			ibtrs_srv_get_sess_addr(sess));
		return create_sess(sess);

	case IBTRS_SRV_SESS_EV_DISCONNECTING:
		if (WARN_ON(!priv ||
			    srv_sess->state != SESS_STATE_CONNECTED))
			return -EINVAL;

		pr_info("IBTRS Session to %s will be disconnected.\n",
			srv_sess->str_addr);
		srv_sess->state = SESS_STATE_DISCONNECTED;

		return 0;

	case IBTRS_SRV_SESS_EV_DISCONNECTED:
		if (WARN_ON(!priv))
			return -EINVAL;

		destroy_sess(srv_sess);
		return 0;

	default:
		pr_warn("Received unknown IBTRS session event %d from session"
		       " %s\n", ev, srv_sess->str_addr);
		return -EINVAL;
	}
}

static int ibnbd_srv_rdma_ev(struct ibtrs_session *sess, void *priv,
			     struct ibtrs_ops_id *id, enum ibtrs_srv_rdma_ev ev,
			     void *data, size_t len)
{
	struct ibnbd_srv_session *srv_sess = priv;

	if (unlikely(WARN_ON(!srv_sess) ||
		     srv_sess->state == SESS_STATE_DISCONNECTED))
		return -ENODEV;

	switch (ev) {
	case IBTRS_SRV_RDMA_EV_RECV:
	case IBTRS_SRV_RDMA_EV_WRITE_REQ:
		return process_rdma(sess, srv_sess, id, data, len);

	default:
		pr_warn("Received unexpected RDMA event %d from session %s\n",
		       ev, srv_sess->str_addr);
		return -EINVAL;
	}
}

static struct ibnbd_srv_sess_dev
*ibnbd_sess_dev_alloc(struct ibnbd_srv_session *srv_sess)
{
	struct ibnbd_srv_sess_dev *sess_dev;
	int error;

	sess_dev = kzalloc(sizeof(*sess_dev), GFP_KERNEL);
	if (!sess_dev)
		return ERR_PTR(-ENOMEM);

	idr_preload(GFP_KERNEL);
	write_lock(&srv_sess->index_lock);

	error = idr_alloc(&srv_sess->index_idr, sess_dev, 0, -1, GFP_NOWAIT);
	if (error < 0) {
		pr_warn("Allocating idr failed, err: %s\n", strerror(error));
		goto out_unlock;
	}

	sess_dev->device_id = error;
	error = 0;

out_unlock:
	write_unlock(&srv_sess->index_lock);
	idr_preload_end();
	if (error) {
		kfree(sess_dev);
		return ERR_PTR(error);
	}

	return sess_dev;
}

static struct ibnbd_srv_dev *ibnbd_srv_init_srv_dev(const char *id,
						    enum ibnbd_io_mode mode)
{
	struct ibnbd_srv_dev *dev;

	dev = kzalloc(sizeof(*dev), GFP_KERNEL);
	if (!dev)
		return ERR_PTR(-ENOMEM);

	strlcpy(dev->id, id, sizeof(dev->id));
	dev->mode = mode;
	kref_init(&dev->kref);
	INIT_LIST_HEAD(&dev->sess_dev_list);
	mutex_init(&dev->lock);

	return dev;
}

static struct ibnbd_srv_dev *
ibnbd_srv_find_or_add_srv_dev(struct ibnbd_srv_dev *new_dev)
{
	struct ibnbd_srv_dev *dev;

	spin_lock(&dev_lock);
	list_for_each_entry(dev, &dev_list, list) {
		if (!strncmp(dev->id, new_dev->id, sizeof(dev->id))) {
			if (!kref_get_unless_zero(&dev->kref))
				/*
				 * We lost the race, device is almost dead.
				 *  Continue traversing to find a valid one.
				 */
				continue;
			spin_unlock(&dev_lock);
			return dev;
		}
	}
	list_add(&new_dev->list, &dev_list);
	spin_unlock(&dev_lock);

	return new_dev;
}

static int ibnbd_srv_check_update_open_perm(struct ibnbd_srv_dev *srv_dev,
					    struct ibnbd_srv_session *srv_sess,
					    enum ibnbd_io_mode io_mode,
					    enum ibnbd_access_mode access_mode)
{
	int ret = -EPERM;

	mutex_lock(&srv_dev->lock);

	if (srv_dev->mode != io_mode) {
		pr_err("Mapping device '%s' for client %s in %s mode forbidden,"
		       " device is already mapped from other client(s) in"
		       " %s mode\n", srv_dev->id, srv_sess->str_addr,
		       ibnbd_io_mode_str(io_mode),
		       ibnbd_io_mode_str(srv_dev->mode));
		goto out;
	}

	switch (access_mode) {
	case IBNBD_ACCESS_RO:
		ret = 0;
		break;
	case IBNBD_ACCESS_RW:
		if (srv_dev->open_write_cnt == 0)  {
			srv_dev->open_write_cnt++;
			ret = 0;
		} else {
			pr_err("Mapping device '%s' for client %s with"
			       " RW permissions failed. Device already opened"
			       " as 'RW' by %d client(s) in %s mode.\n",
			       srv_dev->id, srv_sess->str_addr,
			       srv_dev->open_write_cnt,
			       ibnbd_io_mode_str(srv_dev->mode));
		}
		break;
	case IBNBD_ACCESS_MIGRATION:
		if (srv_dev->open_write_cnt < 2) {
			srv_dev->open_write_cnt++;
			ret = 0;
		} else {
			pr_err("Mapping device '%s' for client %s with"
			       " migration permissions failed. Device already"
			       " opened as 'RW' by %d client(s) in %s mode.\n",
			       srv_dev->id, srv_sess->str_addr,
			       srv_dev->open_write_cnt,
			       ibnbd_io_mode_str(srv_dev->mode));
		}
		break;
	default:
		pr_err("Received mapping request for device '%s' from client %s"
		       " with invalid access mode: %d\n", srv_dev->id,
		       srv_sess->str_addr, access_mode);
		ret = -EINVAL;
	}

out:
	mutex_unlock(&srv_dev->lock);

	return ret;
}

static struct ibnbd_srv_dev *
ibnbd_srv_get_or_create_srv_dev(struct ibnbd_dev *ibnbd_dev,
				struct ibnbd_srv_session *srv_sess,
				enum ibnbd_io_mode io_mode,
				enum ibnbd_access_mode access_mode)
{
	int ret;
	struct ibnbd_srv_dev *new_dev, *dev;
	const char *dev_name = ibnbd_dev_get_name(ibnbd_dev);

	new_dev = ibnbd_srv_init_srv_dev(dev_name, io_mode);
	if (IS_ERR(new_dev))
		return new_dev;

	dev = ibnbd_srv_find_or_add_srv_dev(new_dev);
	if (dev != new_dev)
		kfree(new_dev);

	ret = ibnbd_srv_check_update_open_perm(dev, srv_sess, io_mode,
					       access_mode);
	if (ret) {
		ibnbd_put_srv_dev(dev);
		return ERR_PTR(ret);
	}

	return dev;
}

static inline void
ibnbd_srv_fill_msg_open_rsp_header(struct ibnbd_msg_open_rsp *rsp,
				   u32 clt_device_id)
{
	rsp->hdr.type		= IBNBD_MSG_OPEN_RSP;
	rsp->clt_device_id	= clt_device_id;
}

static void ibnbd_srv_fill_msg_open_rsp(struct ibnbd_msg_open_rsp *rsp,
					u32 device_id, u32 clt_device_id,
					size_t nsectors,
					const struct ibnbd_dev *ibnbd_dev)
{
	struct block_device *bdev;

	ibnbd_srv_fill_msg_open_rsp_header(rsp, clt_device_id);

	rsp->result			= 0;
	rsp->device_id			= device_id;
	rsp->nsectors			= nsectors;
	rsp->logical_block_size		=
		ibnbd_dev_get_logical_bsize(ibnbd_dev);
	rsp->physical_block_size	= ibnbd_dev_get_phys_bsize(ibnbd_dev);
	rsp->max_segments		= ibnbd_dev_get_max_segs(ibnbd_dev);
	rsp->max_hw_sectors		= ibnbd_dev_get_max_hw_sects(ibnbd_dev);
	rsp->max_write_same_sectors	=
		ibnbd_dev_get_max_write_same_sects(ibnbd_dev);

	rsp->max_discard_sectors	=
		ibnbd_dev_get_max_discard_sects(ibnbd_dev);
	rsp->discard_zeroes_data	=
		ibnbd_dev_get_discard_zeroes_data(ibnbd_dev);
	rsp->discard_granularity	=
		ibnbd_dev_get_discard_granularity(ibnbd_dev);

	rsp->discard_alignment	= ibnbd_dev_get_discard_alignment(ibnbd_dev);
	rsp->secure_discard	= ibnbd_dev_get_secure_discard(ibnbd_dev);

	bdev = ibnbd_dev_get_bdev(ibnbd_dev);
	rsp->rotational	= !blk_queue_nonrot(bdev_get_queue(bdev));
	rsp->io_mode	= ibnbd_dev->mode;

	pr_debug("nsectors = %llu, logical_block_size = %d, "
	    "physical_block_size = %d, max_segments = %d, "
	    "max_hw_sectors = %d, max_write_same_sects = %d, "
	    "max_discard_sectors = %d, rotational = %d, io_mode = %d\n",
	    rsp->nsectors, rsp->logical_block_size, rsp->physical_block_size,
	    rsp->max_segments, rsp->max_hw_sectors, rsp->max_write_same_sectors,
	    rsp->max_discard_sectors, rsp->rotational, rsp->io_mode);
}

static struct ibnbd_srv_sess_dev *
ibnbd_srv_create_set_sess_dev(struct ibnbd_srv_session *srv_sess,
			      const struct ibnbd_msg_open *open_msg,
			      struct ibnbd_dev *ibnbd_dev, fmode_t open_flags,
			      struct ibnbd_srv_dev *srv_dev)
{
	struct ibnbd_srv_sess_dev *sdev = ibnbd_sess_dev_alloc(srv_sess);

	if (IS_ERR(sdev))
		return sdev;

	kref_init(&sdev->kref);

	strlcpy(sdev->pathname, open_msg->dev_name, sizeof(sdev->pathname));

	sdev->ibnbd_dev		= ibnbd_dev;
	sdev->sess		= srv_sess;
	sdev->dev		= srv_dev;
	sdev->open_flags	= open_flags;
	sdev->clt_device_id	= open_msg->clt_device_id;

	return sdev;
}

static char *ibnbd_srv_get_full_path(const char *dev_name)
{
	char *full_path;
	char *a, *b;

	full_path = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!full_path)
		return ERR_PTR(-ENOMEM);

	snprintf(full_path, PATH_MAX, "%s/%s", dev_search_path, dev_name);

	/* eliminitate duplicated slashes */
	a = strchr(full_path, '/');
	b = a;
	while (*b != '\0') {
		if (*b == '/' && *a == '/') {
			b++;
		} else {
			a++;
			*a = *b;
			b++;
		}
	}
	a++;
	*a = '\0';

	return full_path;
}

static void process_msg_sess_info(struct ibtrs_session *s,
				  struct ibnbd_srv_session *srv_sess,
				  const void *msg, size_t len)
{
	int err;
	const struct ibnbd_msg_sess_info *sess_info_msg = msg;
	struct ibnbd_msg_sess_info_rsp rsp;
	struct kvec vec = {
		.iov_base = &rsp,
		.iov_len  = sizeof(rsp)
	};

	if (srv_sess->hostname[0] == '\0')
		strlcpy(srv_sess->hostname, ibtrs_srv_get_sess_hostname(s),
			sizeof(srv_sess->hostname));

	srv_sess->ver = min_t(u8, sess_info_msg->ver, IBNBD_VERSION);
	pr_debug("Session to %s (%s) using protocol version %d (client version: %d,"
	    " server version: %d)\n", srv_sess->str_addr, srv_sess->hostname,
	    srv_sess->ver, sess_info_msg->ver, IBNBD_VERSION);

	rsp.hdr.type = IBNBD_MSG_SESS_INFO_RSP;
	rsp.ver = srv_sess->ver;

	err = ibtrs_srv_send(s, &vec, 1);
	if (unlikely(err))
		pr_err("Failed to send session info response to client"
		       "%s (%s)\n", srv_sess->str_addr, srv_sess->hostname);
}

static void process_msg_open(struct ibtrs_session *s,
			     struct ibnbd_srv_session *srv_sess,
			     const void *msg, size_t len)
{
	int ret;
	struct ibnbd_srv_dev *srv_dev;
	struct ibnbd_srv_sess_dev *srv_sess_dev;
	const struct ibnbd_msg_open *open_msg = msg;
	fmode_t open_flags;
	char *full_path;
	struct ibnbd_dev *ibnbd_dev;
	enum ibnbd_io_mode io_mode;
	struct ibnbd_msg_open_rsp rsp;
	struct kvec vec = {
		.iov_base = &rsp,
		.iov_len  = sizeof(rsp)
	};

	pr_debug("Open message received: client='%s' path='%s' access_mode=%d"
	    " io_mode=%d\n", srv_sess->str_addr, open_msg->dev_name,
	    open_msg->access_mode, open_msg->io_mode);
	open_flags = FMODE_READ;
	if (open_msg->access_mode != IBNBD_ACCESS_RO)
		open_flags |= FMODE_WRITE;

	if ((strlen(dev_search_path) + strlen(open_msg->dev_name))
	    >= PATH_MAX) {
		pr_err("Opening device for client %s failed, device path too"
		       " long. '%s/%s' is longer than PATH_MAX (%d)\n",
		       srv_sess->str_addr, dev_search_path, open_msg->dev_name,
		       PATH_MAX);
		ret = -EINVAL;
		goto reject;
	}
	full_path = ibnbd_srv_get_full_path(open_msg->dev_name);
	if (IS_ERR(full_path)) {
		ret = PTR_ERR(full_path);
		pr_err("Opening device '%s' for client %s failed,"
		       " failed to get device full path, err: %s\n",
		       open_msg->dev_name, srv_sess->str_addr, strerror(ret));
		goto reject;
	}

	if (open_msg->io_mode == IBNBD_BLOCKIO)
		io_mode = IBNBD_BLOCKIO;
	else if (open_msg->io_mode == IBNBD_FILEIO)
		io_mode = IBNBD_FILEIO;
	else
		io_mode = def_io_mode;

	ibnbd_dev = ibnbd_dev_open(full_path, open_flags, io_mode,
				   srv_sess->sess_bio_set, ibnbd_endio);
	if (IS_ERR(ibnbd_dev)) {
		pr_err("Opening device '%s' for client %s failed,"
		       " failed to open the block device, err:"
		       " %s\n", full_path, srv_sess->str_addr,
		       strerror(PTR_ERR(ibnbd_dev)));
		ret = PTR_ERR(ibnbd_dev);
		goto free_path;
	}

	srv_dev = ibnbd_srv_get_or_create_srv_dev(ibnbd_dev, srv_sess, io_mode,
						  open_msg->access_mode);
	if (IS_ERR(srv_dev)) {
		pr_err("Opening device '%s' for client %s failed,"
		       " creating srv_dev failed, err: %s\n", full_path,
		       srv_sess->str_addr, strerror(PTR_ERR(srv_dev)));
		ret = PTR_ERR(srv_dev);
		goto ibnbd_dev_close;
	}

	srv_sess_dev = ibnbd_srv_create_set_sess_dev(srv_sess, open_msg,
						     ibnbd_dev, open_flags,
						     srv_dev);
	if (IS_ERR(srv_sess_dev)) {
		pr_err("Opening device '%s' for client %s failed,"
		       " creating sess_dev failed, err: %s\n", full_path,
		       srv_sess->str_addr, strerror(PTR_ERR(srv_sess_dev)));
		ret = PTR_ERR(srv_sess_dev);
		goto srv_dev_put;
	}

	/* Create the srv_dev sysfs files if they haven't been created yet. The
	 * reason to delay the creation is not to create the sysfs files before
	 * we are sure the device can be opened.
	 */
	mutex_lock(&srv_dev->lock);
	if (!srv_dev->dev_kobj.state_in_sysfs) {
		ret = ibnbd_srv_create_dev_sysfs(srv_dev,
						 ibnbd_dev_get_bdev(ibnbd_dev),
						 ibnbd_dev_get_name(ibnbd_dev));
		if (ret) {
			mutex_unlock(&srv_dev->lock);
			ERR(srv_sess_dev, "Opening device failed, failed to"
			    " create device sysfs files, err: %s\n",
			    strerror(ret));
			goto free_srv_sess_dev;
		}
	}

	ret = ibnbd_srv_create_dev_client_sysfs(srv_sess_dev);
	if (ret) {
		mutex_unlock(&srv_dev->lock);
		ERR(srv_sess_dev, "Opening device failed, failed to create"
		    " dev client sysfs files, err: %s\n", strerror(ret));
		goto free_srv_sess_dev;
	}

	list_add(&srv_sess_dev->dev_list, &srv_dev->sess_dev_list);
	mutex_unlock(&srv_dev->lock);

	mutex_lock(&srv_sess->lock);
	list_add(&srv_sess_dev->sess_list, &srv_sess->sess_dev_list);
	mutex_unlock(&srv_sess->lock);

	srv_sess_dev->nsectors = ibnbd_dev_get_capacity(ibnbd_dev);

	ibnbd_srv_fill_msg_open_rsp(&rsp, srv_sess_dev->device_id,
				    open_msg->clt_device_id,
				    srv_sess_dev->nsectors, ibnbd_dev);

	if (unlikely(srv_sess->state == SESS_STATE_DISCONNECTED)) {
		ret = -ENODEV;
		ERR(srv_sess_dev, "Opening device failed, session"
		    " is disconnected, err: %s\n", strerror(ret));
		goto remove_srv_sess_dev;
	}

	ret = ibtrs_srv_send(s, &vec, 1);
	if (unlikely(ret)) {
		ERR(srv_sess_dev, "Opening device failed, sending open"
		    " response msg failed, err: %s\n", strerror(ret));
		goto remove_srv_sess_dev;
	}
	srv_sess_dev->is_visible = true;
	INFO(srv_sess_dev, "Opened device '%s' in %s mode\n",
	     srv_dev->id, ibnbd_io_mode_str(io_mode));

	kfree(full_path);
	return;

remove_srv_sess_dev:
	ibnbd_srv_destroy_dev_client_sysfs(srv_sess_dev);
	mutex_lock(&srv_sess->lock);
	list_del(&srv_sess_dev->sess_list);
	mutex_unlock(&srv_sess->lock);

	mutex_lock(&srv_dev->lock);
	list_del(&srv_sess_dev->dev_list);
	mutex_unlock(&srv_dev->lock);
free_srv_sess_dev:
	write_lock(&srv_sess->index_lock);
	idr_remove(&srv_sess->index_idr, srv_sess_dev->device_id);
	write_unlock(&srv_sess->index_lock);
	kfree(srv_sess_dev);
srv_dev_put:
	if (open_msg->access_mode != IBNBD_ACCESS_RO) {
		mutex_lock(&srv_dev->lock);
		srv_dev->open_write_cnt--;
		mutex_unlock(&srv_dev->lock);
	}
	ibnbd_put_srv_dev(srv_dev);
ibnbd_dev_close:
	ibnbd_dev_close(ibnbd_dev);
free_path:
	kfree(full_path);
reject:
	pr_debug("Sending negative response to client %s for device '%s' err: %s\n",
	    srv_sess->str_addr, open_msg->dev_name, strerror(ret));
	ibnbd_srv_fill_msg_open_rsp_header(&rsp, open_msg->clt_device_id);
	rsp.result = ret;
	if (unlikely(srv_sess->state == SESS_STATE_DISCONNECTED))
		return;
	ret = ibtrs_srv_send(s, &vec, 1);
	if (ret)
		pr_err("Rejecting mapping request of device '%s' from client %s"
		       " failed, err: %s\n", open_msg->dev_name,
		       srv_sess->str_addr, strerror(ret));
}

static int send_msg_close_rsp(struct ibtrs_session *sess, u32 clt_device_id)
{
	struct ibnbd_msg_close_rsp msg;
	struct kvec vec = {
		.iov_base = &msg,
		.iov_len  = sizeof(msg)
	};

	msg.hdr.type	= IBNBD_MSG_CLOSE_RSP;
	msg.clt_device_id	= clt_device_id;

	return ibtrs_srv_send(sess, &vec, 1);
}

static void process_msg_close(struct ibtrs_session *s,
			      struct ibnbd_srv_session *srv_sess,
			      const void *msg, size_t len)
{
	const struct ibnbd_msg_close *close_msg = msg;
	struct ibnbd_srv_sess_dev *sess_dev;
	u32 dev_id;

	dev_id = close_msg->device_id;

	sess_dev = ibnbd_get_sess_dev(dev_id, srv_sess);
	if (likely(!IS_ERR(sess_dev))) {
		u32 clt_device_id = sess_dev->clt_device_id;

		ibnbd_srv_destroy_dev_client_sysfs(sess_dev);
		ibnbd_put_sess_dev(sess_dev);
		ibnbd_destroy_sess_dev(sess_dev, false);
		send_msg_close_rsp(s, clt_device_id);
	} else {
		pr_err("Destroying device id %d from client %s failed,"
		       " device not open\n", dev_id, srv_sess->str_addr);
	}
}

static void ibnbd_srv_recv(struct ibtrs_session *sess, void *priv,
			   const void *msg, size_t len)
{
	struct ibnbd_msg_hdr *hdr;
	struct ibnbd_srv_session *srv_sess;

	hdr = (struct ibnbd_msg_hdr *)msg;
	srv_sess = priv;

	if (unlikely(WARN_ON(!srv_sess)))
		return;
	if (unlikely(WARN_ON(!hdr) || ibnbd_validate_message(msg, len)))
		return;

	print_hex_dump_debug("", DUMP_PREFIX_OFFSET, 8, 1, msg, len, true);

	switch (hdr->type) {
	case IBNBD_MSG_SESS_INFO:
		process_msg_sess_info(sess, srv_sess, msg, len);
		break;
	case IBNBD_MSG_OPEN:
		process_msg_open(sess, srv_sess, msg, len);
		break;
	case IBNBD_MSG_CLOSE:
		process_msg_close(sess, srv_sess, msg, len);
		break;
	default:
		pr_warn("Message with unexpected type %d received from client"
		       " %s\n", hdr->type, srv_sess->str_addr);
		break;
	}
}

static int ibnbd_srv_revalidate_sess_dev(struct ibnbd_srv_sess_dev *sess_dev)
{
	int ret;
	size_t nsectors;
	struct ibnbd_msg_revalidate msg;
	struct kvec vec = {
		.iov_base = &msg,
		.iov_len  = sizeof(msg)
	};

	nsectors = ibnbd_dev_get_capacity(sess_dev->ibnbd_dev);

	msg.hdr.type		= IBNBD_MSG_REVAL;
	msg.clt_device_id	= sess_dev->clt_device_id;
	msg.nsectors		= nsectors;

	if (unlikely(sess_dev->sess->state == SESS_STATE_DISCONNECTED))
		return -ENODEV;

	if (!sess_dev->is_visible) {
		INFO(sess_dev, "revalidate device failed, wait for sending "
		     "open reply first\n");
		return -EAGAIN;
	}

	ret = ibtrs_srv_send(sess_dev->sess->ibtrs_sess, &vec, 1);
	if (unlikely(ret)) {
		ERR(sess_dev, "revalidate: Sending new device size"
		    " to client failed, err: %s\n", strerror(ret));
	} else {
		INFO(sess_dev, "notified client about device size change"
		     " (old nsectors: %lu, new nsectors: %lu)\n",
		     sess_dev->nsectors, nsectors);
		sess_dev->nsectors = nsectors;
	}

	return ret;
}

int ibnbd_srv_revalidate_dev(struct ibnbd_srv_dev *dev)
{
	struct ibnbd_srv_sess_dev *sess_dev;
	int ret = 0;

	mutex_lock(&dev->lock);
	list_for_each_entry(sess_dev, &dev->sess_dev_list, dev_list)
		ret += ibnbd_srv_revalidate_sess_dev(sess_dev);
	mutex_unlock(&dev->lock);

	if (ret)
		return -EIO;

	return 0;
}

static int __init ibnbd_srv_init_module(void)
{
	int err;

	pr_info("Loading module ibnbd_server, version: %s (dev_search_path: "
		"'%s', def_io_mode: '%s')\n", __stringify(IBNBD_VER),
		dev_search_path, ibnbd_io_mode_str(def_io_mode));

	ibnbd_srv_ops.owner	= THIS_MODULE;
	ibnbd_srv_ops.recv	= ibnbd_srv_recv;
	ibnbd_srv_ops.rdma_ev	= ibnbd_srv_rdma_ev;
	ibnbd_srv_ops.sess_ev	= ibnbd_srv_sess_ev;

	err = ibtrs_srv_register(&ibnbd_srv_ops);
	if (err) {
		pr_err("Failed to load module, IBTRS registration failed,"
		       " err: %s\n", strerror(err));
		goto out;
	}

	err = ibnbd_dev_init();
	if (err) {
		pr_err("Failed to load module, init device resources failed,"
		       " err: %s\n", strerror(err));
		goto unreg;
	}

	err = ibnbd_srv_create_sysfs_files();
	if (err) {
		pr_err("Failed to load module, create sysfs files failed,"
		       " err: %s\n", strerror(err));
		goto dev_destroy;
	}

	return 0;

dev_destroy:
	ibnbd_dev_destroy();
unreg:
	ibtrs_srv_unregister(&ibnbd_srv_ops);
out:
	return err;
}

static void __exit ibnbd_srv_cleanup_module(void)
{
	pr_info("Unloading module\n");
	ibtrs_srv_unregister(&ibnbd_srv_ops);
	WARN_ON(!list_empty(&sess_list));
	ibnbd_srv_destroy_sysfs_files();
	ibnbd_dev_destroy();
	pr_info("Module unloaded\n");
}

module_init(ibnbd_srv_init_module);
module_exit(ibnbd_srv_cleanup_module);
