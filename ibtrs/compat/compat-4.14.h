/*
 * Copyright (c) Roman Pen, ProfitBricks GmbH.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef LINUX_4_14_COMPAT_H
#define LINUX_4_14_COMPAT_H

/*
 * linux/kernel.h
 */
#define COUNT_ARGS(...) COUNT_ARGS_(,##__VA_ARGS__,6,5,4,3,2,1,0)
#define COUNT_ARGS_(z,a,b,c,d,e,f,cnt,...) cnt


/*
 * linux/sysfs.h
 */
#define sysfs_remove_file_self ORIGINAL_sysfs_remove_file_self
#include <linux/sysfs.h>
#include <linux/device.h>
#undef sysfs_remove_file_self

static inline
void sysfs_remove_file_self(struct kobject *kobj,
			    const struct attribute *attr)
{
       struct device_attribute dattr = {
               .attr.name = attr->name
       };
       struct device *device;

       /*
        * Unfortunately original sysfs_remove_file_self() is not exported,
        * so consider this as a hack to call self removal of a sysfs entry
        * just using another "door".
        */

       device = container_of(kobj, typeof(*device), kobj);
       device_remove_file_self(device, &dattr);
}

/*
 * rdma/rdma_cm.h
 */

#define rdma_ucm_port_space rdma_port_space


#ifndef IBTRS_USE_FR

#include <rdma/ib_verbs.h>
#include <rdma/ib_cm.h>

struct fmr_struct {
	struct ib_fmr *fmr;
	unsigned remap_count;
	struct work_struct unmap_work;
};

struct fmr_per_mr {
	u64		   iova;
	u64		   length;
	unsigned	   max_remaps;
	unsigned	   max_pages;
	unsigned	   page_size;
	unsigned	   npages;
	u64		   *pages;
	struct fmr_struct  fmr[2];
	struct fmr_struct  *active_fmr;
	struct fmr_struct  *shadow_fmr;
};

struct backport_ib_mr {
	/*
	 * We keep preallocated FMRs for several page orders, starting
	 * from 12.  Preallocation is needed, because ib_alloc_mr() does
	 * not accept page_size, but ib_map_mr_sg() is called on hot path
	 * where sleep is not allowed.
	 */
	struct fmr_per_mr *fmr_order[8];

	u32		   rkey;
	u64		   iova;
	u64		   length;
};

struct backport_ib_reg_wr {
	struct ib_send_wr	wr;
	struct backport_ib_mr	*mr;
	u32			key;
	int			access;
};

static inline unsigned page_size_to_ind(size_t page_size)
{
	return ilog2(page_size) - 12;
}

static inline struct fmr_per_mr *get_fmr(struct backport_ib_mr *bmr,
					 size_t page_size)
{
	unsigned ind = page_size_to_ind(page_size);

	if (ind >= ARRAY_SIZE(bmr->fmr_order))
		return NULL;

	return bmr->fmr_order[ind];
}

static inline void set_fmr(struct backport_ib_mr *bmr,
			   struct fmr_per_mr *fmr_mr,
			   size_t page_size)
{
	unsigned ind = page_size_to_ind(page_size);

	BUG_ON(ind >= ARRAY_SIZE(bmr->fmr_order));
	BUG_ON(bmr->fmr_order[ind]);

	bmr->fmr_order[ind] = fmr_mr;
}

static void unmap_fmr(struct fmr_struct *fmr)
{
	LIST_HEAD(fmr_list);
	int err;

	list_add_tail(&fmr->fmr->list, &fmr_list);
	err = ib_unmap_fmr(&fmr_list);
	if (unlikely(err))
		pr_err("%s: ib_unmap_fmr() returned %d\n", __func__, err);

	fmr->remap_count = 0;
}

static void unmap_fmr_work(struct work_struct *work)
{
	struct fmr_struct *fmr;

	fmr = container_of(work, struct fmr_struct, unmap_work);
	unmap_fmr(fmr);
}

static inline struct fmr_per_mr *alloc_fmr(struct ib_pd *pd,
					   size_t page_size)
{
	struct ib_fmr_attr fmr_attr;
	struct fmr_per_mr *fmr_mr;
	int max_remaps, max_pages, err;

	if (unlikely(!pd->device->attrs.max_map_per_fmr))
		max_remaps = 32;
	else
		max_remaps = pd->device->attrs.max_map_per_fmr;

	fmr_mr = kzalloc(sizeof(*fmr_mr), GFP_KERNEL);
	if (unlikely(!fmr_mr))
		return ERR_PTR(-ENOMEM);

	/* XXX attr.max_fmr ? */
        max_pages = pd->device->attrs.max_mr_size;
	do_div(max_pages, page_size);
	max_pages = min_t(u64, 512, max_pages);

	fmr_mr->pages = kmalloc_array(max_pages, sizeof(*fmr_mr->pages),
				      GFP_KERNEL);
	if (unlikely(!fmr_mr->pages)) {
		err = -ENOMEM;
		goto err_free_fmr;
	}

	memset(&fmr_attr, 0, sizeof(fmr_attr));
	fmr_attr.max_pages  = max_pages;
	fmr_attr.max_maps   = max_remaps;
	fmr_attr.page_shift = ilog2(page_size);

	fmr_mr->fmr[0].fmr = ib_alloc_fmr(pd,
					  IB_ACCESS_LOCAL_WRITE |
					  IB_ACCESS_REMOTE_WRITE,
					  &fmr_attr);
	fmr_mr->fmr[1].fmr = ib_alloc_fmr(pd,
					  IB_ACCESS_LOCAL_WRITE |
					  IB_ACCESS_REMOTE_WRITE,
					  &fmr_attr);
	if (unlikely(IS_ERR(fmr_mr->fmr[0].fmr) ||
		     IS_ERR(fmr_mr->fmr[1].fmr))) {
		pr_err("%s: ib_alloc_fmr() failed!\n", __func__);
		err = -EINVAL;
		goto err_dealloc_fmr;
	}
	INIT_WORK(&fmr_mr->fmr[0].unmap_work, unmap_fmr_work);
	INIT_WORK(&fmr_mr->fmr[1].unmap_work, unmap_fmr_work);

	fmr_mr->max_pages = max_pages;
	fmr_mr->max_remaps = max_remaps;
	fmr_mr->active_fmr = &fmr_mr->fmr[0];
	fmr_mr->shadow_fmr = &fmr_mr->fmr[1];

	return fmr_mr;

err_dealloc_fmr:
	if (!IS_ERR(fmr_mr->fmr[0].fmr))
		ib_dealloc_fmr(fmr_mr->fmr[0].fmr);
	if (!IS_ERR(fmr_mr->fmr[1].fmr))
		ib_dealloc_fmr(fmr_mr->fmr[1].fmr);
	kfree(fmr_mr->pages);
err_free_fmr:
	kfree(fmr_mr);

	return ERR_PTR(err);
}

static inline int alloc_and_set_fmr(struct ib_pd *pd,
				    struct backport_ib_mr *bmr,
				    size_t page_size)
{
	struct fmr_per_mr *fmr_mr;

	if (get_fmr(bmr, page_size))
		return -EINVAL;

	fmr_mr = alloc_fmr(pd, page_size);
	if (unlikely(IS_ERR(fmr_mr)))
		return PTR_ERR(fmr_mr);

	set_fmr(bmr, fmr_mr, page_size);

	return 0;
}

static inline void dealloc_fmr(struct fmr_per_mr *fmr_mr)
{
	if (likely(fmr_mr)) {
		flush_work(&fmr_mr->fmr[0].unmap_work);
		flush_work(&fmr_mr->fmr[1].unmap_work);
		if (fmr_mr->fmr[0].remap_count)
			unmap_fmr(&fmr_mr->fmr[0]);
		if (fmr_mr->fmr[1].remap_count)
			unmap_fmr(&fmr_mr->fmr[1]);
		ib_dealloc_fmr(fmr_mr->fmr[0].fmr);
		ib_dealloc_fmr(fmr_mr->fmr[1].fmr);
		kfree(fmr_mr->pages);
		kfree(fmr_mr);
	}
}

static inline int backport_ib_dereg_mr(struct backport_ib_mr *bmr)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(bmr->fmr_order); i++)
		     dealloc_fmr(bmr->fmr_order[i]);
	kfree(bmr);

	return 0;
}

static inline struct backport_ib_mr *
backport_ib_alloc_mr(struct ib_pd *pd,
		     enum ib_mr_type mr_type,
		     u32 max_num_sg)
{
	struct backport_ib_mr *bmr;
	int err;

	BUG_ON(mr_type != IB_MR_TYPE_MEM_REG);

	bmr = kzalloc(sizeof(*bmr), GFP_KERNEL);
	if (unlikely(!bmr))
		return ERR_PTR(-ENOMEM);

	/*
	 * Here we are so naughty, that instead of doing FR we do FMR.
	 */

	/*
	 * For our humble IBTRS needs we preallocate FMRs for two orders:
	 * 12 (client side) and 17 (server side)
	 */

	err = alloc_and_set_fmr(pd, bmr, 1<<12);
	if (unlikely(err))
		goto err;

	err = alloc_and_set_fmr(pd, bmr, 1<<17);
	if (unlikely(err))
		goto err;

	return bmr;

err:
	backport_ib_dereg_mr(bmr);

	return ERR_PTR(err);
}

static int fmr_set_page(struct fmr_per_mr *fmr, u64 addr)
{
	if (unlikely(fmr->npages == fmr->max_pages))
		return -ENOMEM;

	fmr->pages[fmr->npages++] = addr;

	return 0;
}

/**
 * ib_sg_to_pages() - Convert the largest prefix of a sg list
 *
 * Stolen from upstream kernel.
 */
static inline int
backport_ib_sg_to_pages(struct fmr_per_mr *fmr, struct scatterlist *sgl,
			int sg_nents, unsigned int *sg_offset_p,
			int (*set_page)(struct fmr_per_mr *, u64))
{
	struct scatterlist *sg;
	u64 last_end_dma_addr = 0;
	unsigned int sg_offset = sg_offset_p ? *sg_offset_p : 0;
	unsigned int last_page_off = 0;
	u64 page_mask = ~((u64)fmr->page_size - 1);
	int i, ret;

	if (unlikely(sg_nents <= 0 || sg_offset > sg_dma_len(&sgl[0])))
		return -EINVAL;

	fmr->iova = sg_dma_address(&sgl[0]) + sg_offset;
	fmr->length = 0;

	for_each_sg(sgl, sg, sg_nents, i) {
		u64 dma_addr = sg_dma_address(sg) + sg_offset;
		u64 prev_addr = dma_addr;
		unsigned int dma_len = sg_dma_len(sg) - sg_offset;
		u64 end_dma_addr = dma_addr + dma_len;
		u64 page_addr = dma_addr & page_mask;

		/*
		 * For the second and later elements, check whether either the
		 * end of element i-1 or the start of element i is not aligned
		 * on a page boundary.
		 */
		if (i && (last_page_off != 0 || page_addr != dma_addr)) {
			/* Stop mapping if there is a gap. */
			if (last_end_dma_addr != dma_addr)
				break;

			/*
			 * Coalesce this element with the last. If it is small
			 * enough just update mr->length. Otherwise start
			 * mapping from the next page.
			 */
			goto next_page;
		}

		do {
			ret = set_page(fmr, page_addr);
			if (unlikely(ret < 0)) {
				sg_offset = prev_addr - sg_dma_address(sg);
				fmr->length += prev_addr - dma_addr;
				if (sg_offset_p)
					*sg_offset_p = sg_offset;
				return i || sg_offset ? i : ret;
			}
			prev_addr = page_addr;
next_page:
			page_addr += fmr->page_size;
		} while (page_addr < end_dma_addr);

		fmr->length += dma_len;
		last_end_dma_addr = end_dma_addr;
		last_page_off = end_dma_addr & ~page_mask;

		sg_offset = 0;
	}

	if (sg_offset_p)
		*sg_offset_p = 0;
	return i;
}

/* Defined in IBTRS (client or server) with WQ_MEM_RECLAIM */
static struct workqueue_struct *ibtrs_wq;

static inline int backport_ib_map_mr_sg(struct backport_ib_mr *bmr,
					struct scatterlist *sg,
					int sg_nents,  unsigned int *sg_offset,
					unsigned int page_size)
{
	struct fmr_per_mr *fmr_mr;
	struct fmr_struct *fmr;
	int err;

	if (WARN_ON(!ibtrs_wq))
		return -EINVAL;

	fmr_mr = get_fmr(bmr, page_size);
	if (WARN_ON(!fmr_mr))
		return -EINVAL;

	if (fmr_mr->active_fmr->remap_count >= fmr_mr->max_remaps) {
		queue_work(ibtrs_wq, &fmr_mr->active_fmr->unmap_work);
		swap(fmr_mr->active_fmr, fmr_mr->shadow_fmr);
		/* WTF? */
		if (unlikely(fmr_mr->active_fmr->remap_count >=
			     fmr_mr->max_remaps)) {
			pr_err("%s: active FMR reached max remaps?\n", __func__);
			return -EAGAIN;
		}
	}
	fmr = fmr_mr->active_fmr;
	fmr_mr->page_size = page_size;
	fmr_mr->npages = 0;
	err = backport_ib_sg_to_pages(fmr_mr, sg, sg_nents,
				      sg_offset, fmr_set_page);
	if (unlikely(err < sg_nents)) {
		pr_err("%s: ib_sg_to_pages(): %d, requested %d\n",
		       __func__, err, sg_nents);
		if (err < 0)
			return err;
		return -EINVAL;
	}
	/* We use 0 as iova to avoid problems with not aligned offsets */
	err = ib_map_phys_fmr(fmr->fmr, fmr_mr->pages, fmr_mr->npages, 0 /*iova*/);
	if (unlikely(err)) {
		pr_err("%s: ib_map_phys_fmr(): %d\n", __func__, err);
		return err;
	}
	fmr->remap_count++;

	/* iova address space starts from 0, so get offset in first page */
	bmr->iova = fmr_mr->iova & (page_size - 1);
	bmr->rkey = fmr->fmr->rkey;
	bmr->length = fmr_mr->length;

	return sg_nents;
}

static inline void
backport_ib_update_fast_reg_key(struct backport_ib_mr *bmr, u8 newkey)
{
	/*
	 * Since we do FMR, do nothing here
	 */
}

static inline int backport_ib_post_send(struct ib_qp *qp,
					struct ib_send_wr *send_wr,
					struct ib_send_wr **bad_send_wr)
{
	struct ib_send_wr *wr = send_wr, *prev = NULL;

	if (unlikely(!send_wr))
		return -EINVAL;

	while (wr) {
		if (wr->opcode == IB_WR_REG_MR) {
			/*
			 * We skip REG_MR requests, because we do FMR,
			 * thus we do not care about signalling.
			 */
			WARN_ON(wr->send_flags & IB_SEND_SIGNALED);
			if (prev)
				prev->next = wr->next;
			else
				send_wr = wr->next;
		} else {
			prev = wr;
		}
		wr = wr->next;
	}
	/* Just return 0 if all REGs are skipped */
	if (!send_wr)
		return 0;

	return ib_post_send(qp, send_wr, bad_send_wr);
}

#define ib_mr backport_ib_mr
#define ib_reg_wr backport_ib_reg_wr
#define ib_alloc_mr backport_ib_alloc_mr
#define ib_dereg_mr backport_ib_dereg_mr
#define ib_map_mr_sg backport_ib_map_mr_sg
#define ib_update_fast_reg_key backport_ib_update_fast_reg_key
#define ib_post_send backport_ib_post_send

/*
 * IBTRS internals
 */

#define ibtrs_invalidate_flag ORIGINAL_ibtrs_invalidate_flag
#include "../ibtrs-pri.h"
#undef ibtrs_invalidate_flag

/*
 * Since in compat we do FMR instead of FR no need to invalidate keys.
 */
static inline u32 ibtrs_invalidate_flag(void)
{
	return 0;
}

#endif // IBTRS_USE_FR
/*
 * linux/rculist.h
 */

/**
 * list_next_or_null_rcu - get the first element from a list
 * @head:	the head for the list.
 * @ptr:        the list head to take the next element from.
 * @type:       the type of the struct this is embedded in.
 * @member:     the name of the list_head within the struct.
 *
 * Note that if the ptr is at the end of the list, NULL is returned.
 *
 * This primitive may safely run concurrently with the _rcu list-mutation
 * primitives such as list_add_rcu() as long as it's guarded by rcu_read_lock().
 */
#define list_next_or_null_rcu(head, ptr, type, member) \
({ \
	struct list_head *__head = (head); \
	struct list_head *__ptr = (ptr); \
	struct list_head *__next = READ_ONCE(__ptr->next); \
	likely(__next != __head) ? list_entry_rcu(__next, type, \
						  member) : NULL; \
})

#endif /* LINUX_4_14_COMPAT_H */
