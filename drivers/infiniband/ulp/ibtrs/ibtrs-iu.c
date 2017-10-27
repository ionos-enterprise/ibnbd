#include <linux/slab.h>
#include "ibtrs-pri.h"

static void free_usrtx_list(struct list_head *iu_list,
			    struct ibtrs_ib_dev *ibdev)
{
	struct ibtrs_iu *iu;

	while (!list_empty(iu_list)) {
		iu = list_first_entry(iu_list, typeof(*iu), list);
		list_del(&iu->list);
		ibtrs_iu_free(iu, DMA_TO_DEVICE, ibdev->dev);
	}
}

int ibtrs_iu_usrtx_alloc_list(struct ibtrs_sess *sess,
			      struct ibtrs_ib_dev *ibdev,
			      unsigned max_req_size,
			      void (*done)(struct ib_cq *cq, struct ib_wc *wc))
{
	const unsigned msg_cnt = USRTX_CNT;
	struct ibtrs_iu *iu;
	int i;

	might_sleep();

	spin_lock_init(&sess->usrtx_lock);
	INIT_LIST_HEAD(&sess->usrtx_iu_list);
	init_completion(&sess->usrtx_comp);
	atomic_set(&sess->usrtx_cnt, msg_cnt);
	sess->usrtx_freed = false;

	for (i = 0; i < msg_cnt; ++i) {
		iu = ibtrs_iu_alloc(i, max_req_size, GFP_KERNEL,
				    ibdev->dev, DMA_TO_DEVICE,
				    done);
		if (unlikely(!iu))
			goto err;

		list_add(&iu->list, &sess->usrtx_iu_list);
		/* Prepare completions */
		complete(&sess->usrtx_comp);
	}

	return 0;

err:
	free_usrtx_list(&sess->usrtx_iu_list, ibdev);

	return -ENOMEM;
}
EXPORT_SYMBOL_GPL(ibtrs_iu_usrtx_alloc_list);

void ibtrs_iu_usrtx_free_list(struct ibtrs_sess *sess,
			      struct ibtrs_ib_dev *ibdev)
{
	struct list_head iu_list;

	might_sleep();

	INIT_LIST_HEAD(&iu_list);

	/*
	 * Firstly wait all iu are returned to the list.  Small race
	 * exists between changing state to !CONNECTED and getting
	 * iu from a list on ibtrs_(clt|srv)_send() path.
	 */
	spin_lock_irq(&sess->usrtx_lock);
	sess->usrtx_freed = true;
	while (atomic_read(&sess->usrtx_cnt) < USRTX_CNT) {
		spin_unlock_irq(&sess->usrtx_lock);
		wait_for_completion(&sess->usrtx_comp);
		spin_lock_irq(&sess->usrtx_lock);
	}
	list_splice_init(&sess->usrtx_iu_list, &iu_list);
	complete_all(&sess->usrtx_comp);
	spin_unlock_irq(&sess->usrtx_lock);

	free_usrtx_list(&iu_list, ibdev);
}
EXPORT_SYMBOL_GPL(ibtrs_iu_usrtx_free_list);

struct ibtrs_iu *ibtrs_iu_usrtx_get(struct ibtrs_sess *sess)
{
	struct ibtrs_iu *iu = NULL;

	might_sleep();

	spin_lock_irq(&sess->usrtx_lock);
	while (!sess->usrtx_freed && 0 == atomic_read(&sess->usrtx_cnt)) {
		spin_unlock_irq(&sess->usrtx_lock);
		wait_for_completion(&sess->usrtx_comp);
		spin_lock_irq(&sess->usrtx_lock);
	}
	if (!sess->usrtx_freed) {
		iu = list_first_entry(&sess->usrtx_iu_list,
				      struct ibtrs_iu, list);
		list_del(&iu->list);
		atomic_dec(&sess->usrtx_cnt);
	}
	spin_unlock_irq(&sess->usrtx_lock);

	return iu;
}
EXPORT_SYMBOL_GPL(ibtrs_iu_usrtx_get);

void ibtrs_iu_usrtx_return(struct ibtrs_sess *sess, struct ibtrs_iu *iu)
{
	unsigned long flags;

	spin_lock_irqsave(&sess->usrtx_lock, flags);
	list_add(&iu->list, &sess->usrtx_iu_list);
	spin_unlock_irqrestore(&sess->usrtx_lock, flags);
}
EXPORT_SYMBOL_GPL(ibtrs_iu_usrtx_return);

void ibtrs_iu_usrtx_put(struct ibtrs_sess *sess)
{
	atomic_inc(&sess->usrtx_cnt);
	complete(&sess->usrtx_comp);
}
EXPORT_SYMBOL_GPL(ibtrs_iu_usrtx_put);

struct ibtrs_iu *ibtrs_iu_alloc(u32 tag, size_t size, gfp_t gfp_mask,
				struct ib_device *dma_dev,
				enum dma_data_direction direction,
				void (*done)(struct ib_cq *cq, struct ib_wc *wc))
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

	iu->cqe.done  = done;
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
		   struct ib_device *ibdev)
{
	if (!iu)
		return;

	ib_dma_unmap_single(ibdev, iu->dma_addr, iu->size, dir);
	kfree(iu->buf);
	kfree(iu);
}
EXPORT_SYMBOL_GPL(ibtrs_iu_free);

int ibtrs_iu_usrrx_alloc_list(struct ibtrs_sess *sess, size_t max_req_size,
			      void (*done)(struct ib_cq *cq, struct ib_wc *wc))
{
	int i;

	sess->usrrx_ring = kcalloc(USR_CON_BUF_SIZE,
				   sizeof(*sess->usrrx_ring),
				   GFP_KERNEL);
	if (unlikely(!sess->usrrx_ring))
		return -ENOMEM;

	for (i = 0; i < USR_CON_BUF_SIZE; ++i) {
		struct ibtrs_iu *iu;

		iu = ibtrs_iu_alloc(i, max_req_size, GFP_KERNEL,
				    sess->ib_dev->dev, DMA_FROM_DEVICE,
				    done);
		if (unlikely(!iu))
			goto err;
		sess->usrrx_ring[i] = iu;
	}

	return 0;

err:
	ibtrs_iu_usrrx_free_list(sess);

	return -ENOMEM;
}
EXPORT_SYMBOL_GPL(ibtrs_iu_usrrx_alloc_list);

void ibtrs_iu_usrrx_free_list(struct ibtrs_sess *sess)
{
	int i;

	if (sess->usrrx_ring) {
		for (i = 0; i < USR_CON_BUF_SIZE; ++i) {
			if (sess->usrrx_ring[i])
				ibtrs_iu_free(sess->usrrx_ring[i],
					      DMA_FROM_DEVICE,
					      sess->ib_dev->dev);
		}
		kfree(sess->usrrx_ring);
		sess->usrrx_ring = NULL;
	}
}
EXPORT_SYMBOL_GPL(ibtrs_iu_usrrx_free_list);
