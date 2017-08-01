#include <linux/slab.h>
#include "ibtrs-pri.h"

static void free_usr_msg_list(struct list_head *iu_list,
			      struct ibtrs_ib_dev *dev)
{
	struct ibtrs_iu *iu;

	while (!list_empty(iu_list)) {
		iu = list_first_entry(iu_list, typeof(*iu), list);
		list_del(&iu->list);
		ibtrs_iu_free(iu, DMA_TO_DEVICE, dev->dev);
	}
}

int ibtrs_usr_msg_alloc_list(struct ibtrs_sess *sess,
			     struct ibtrs_ib_dev *dev,
			     unsigned max_req_size)
{
	const unsigned msg_cnt = USR_MSG_CNT;
	struct ibtrs_iu *iu;
	int i;

	might_sleep();

	spin_lock_init(&sess->usr_lock);
	INIT_LIST_HEAD(&sess->usr_iu_list);
	init_completion(&sess->usr_comp);
	atomic_set(&sess->usr_msg_cnt, msg_cnt);
	sess->usr_freed = false;

	for (i = 0; i < msg_cnt; ++i) {
		iu = ibtrs_iu_alloc(i, max_req_size, GFP_KERNEL,
				    dev->dev, DMA_TO_DEVICE);
		if (unlikely(!iu))
			goto err;

		list_add(&iu->list, &sess->usr_iu_list);
		/* Prepare completions */
		complete(&sess->usr_comp);
	}

	return 0;

err:
	free_usr_msg_list(&sess->usr_iu_list, dev);

	return -ENOMEM;
}
EXPORT_SYMBOL_GPL(ibtrs_usr_msg_alloc_list);

void ibtrs_usr_msg_free_list(struct ibtrs_sess *sess, struct ibtrs_ib_dev *dev)
{
	struct list_head iu_list;

	might_sleep();

	INIT_LIST_HEAD(&iu_list);

	/*
	 * Firstly wait all iu are returned to the list.  Small race
	 * exists between changing state to !CONNECTED and getting
	 * iu from a list on ibtrs_(clt|srv)_send() path.
	 */
	spin_lock_irq(&sess->usr_lock);
	sess->usr_freed = true;
	while (atomic_read(&sess->usr_msg_cnt) < USR_MSG_CNT) {
		spin_unlock_irq(&sess->usr_lock);
		wait_for_completion(&sess->usr_comp);
		spin_lock_irq(&sess->usr_lock);
	}
	list_splice_init(&sess->usr_iu_list, &iu_list);
	complete_all(&sess->usr_comp);
	spin_unlock_irq(&sess->usr_lock);

	free_usr_msg_list(&iu_list, dev);
}
EXPORT_SYMBOL_GPL(ibtrs_usr_msg_free_list);

struct ibtrs_iu *ibtrs_usr_msg_get(struct ibtrs_sess *sess)
{
	struct ibtrs_iu *iu = NULL;

	might_sleep();

	spin_lock_irq(&sess->usr_lock);
	while (!sess->usr_freed && 0 == atomic_read(&sess->usr_msg_cnt)) {
		spin_unlock_irq(&sess->usr_lock);
		wait_for_completion(&sess->usr_comp);
		spin_lock_irq(&sess->usr_lock);
	}
	if (!sess->usr_freed) {
		iu = list_first_entry(&sess->usr_iu_list,
				      struct ibtrs_iu, list);
		list_del(&iu->list);
		atomic_dec(&sess->usr_msg_cnt);
	}
	spin_unlock_irq(&sess->usr_lock);

	return iu;
}
EXPORT_SYMBOL_GPL(ibtrs_usr_msg_get);

void ibtrs_usr_msg_return_iu(struct ibtrs_sess *sess, struct ibtrs_iu *iu)
{
	unsigned long flags;

	spin_lock_irqsave(&sess->usr_lock, flags);
	list_add(&iu->list, &sess->usr_iu_list);
	spin_unlock_irqrestore(&sess->usr_lock, flags);
}
EXPORT_SYMBOL_GPL(ibtrs_usr_msg_return_iu);

void ibtrs_usr_msg_put(struct ibtrs_sess *sess)
{
	atomic_inc(&sess->usr_msg_cnt);
	complete(&sess->usr_comp);
}
EXPORT_SYMBOL_GPL(ibtrs_usr_msg_put);

struct ibtrs_iu *ibtrs_iu_alloc(u32 tag, size_t size, gfp_t gfp_mask,
				struct ib_device *dma_dev,
				enum dma_data_direction direction)
{
	struct ibtrs_iu *iu;

	iu = kmalloc(sizeof(*iu), gfp_mask);
	if (unlikely(!iu))
		return NULL;

	iu->buf = kzalloc(size, gfp_mask);
	if (unlikely(!iu->buf))
		goto err1;

	iu->dma_addr = ib_dma_map_single(dma_dev, iu->buf, size, direction);
	if (unlikely(ib_dma_mapping_error(dma_dev, iu->dma_addr)))
		goto err2;

	iu->size      = size;
	iu->direction = direction;
	iu->tag       = tag;

	return iu;

err2:
	kfree(iu->buf);
err1:
	kfree(iu);

	return NULL;
}
EXPORT_SYMBOL_GPL(ibtrs_iu_alloc);

void ibtrs_iu_free(struct ibtrs_iu *iu, enum dma_data_direction dir,
		   struct ib_device *ib_dev)
{
	if (!iu)
		return;

	ib_dma_unmap_single(ib_dev, iu->dma_addr, iu->size, dir);
	kfree(iu->buf);
	kfree(iu);
}
EXPORT_SYMBOL_GPL(ibtrs_iu_free);
