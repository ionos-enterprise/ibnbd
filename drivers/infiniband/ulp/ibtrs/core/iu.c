#include <linux/slab.h>
#include <rdma/ibtrs.h>

/*
 * Return an IU  to the free pool
 */
void ibtrs_iu_put(struct list_head *head, struct ibtrs_iu *iu)
{
	list_add(&iu->list, head);
}
EXPORT_SYMBOL_GPL(ibtrs_iu_put);

/*
 * Get an IU from the free pool, need lock to protect list
 */
struct ibtrs_iu *ibtrs_iu_get(struct list_head *head)
{
	struct ibtrs_iu *iu;

	if (list_empty(head))
		return NULL;

	iu = list_first_entry(head, struct ibtrs_iu, list);
	list_del(&iu->list);
	return iu;
}
EXPORT_SYMBOL_GPL(ibtrs_iu_get);

struct ibtrs_iu *ibtrs_iu_alloc(u32 tag, size_t size, gfp_t gfp_mask,
				struct ib_device *dma_dev,
				enum dma_data_direction direction, bool is_msg)
{
	struct ibtrs_iu *iu;

	iu = kmalloc(sizeof(*iu), gfp_mask);
	if (!iu)
		return NULL;

	iu->buf = kzalloc(size, gfp_mask);
	if (!iu->buf)
		goto err1;

	iu->dma_addr = ib_dma_map_single(dma_dev, iu->buf, size, direction);
	if (ib_dma_mapping_error(dma_dev, iu->dma_addr))
		goto err2;

	iu->size      = size;
	iu->direction = direction;
	iu->tag       = tag;
	iu->is_msg     = is_msg;
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
	if (WARN_ON(!iu))
		return;

	ib_dma_unmap_single(ib_dev, iu->dma_addr, iu->size, dir);
	kfree(iu->buf);
	kfree(iu);
}
EXPORT_SYMBOL_GPL(ibtrs_iu_free);
