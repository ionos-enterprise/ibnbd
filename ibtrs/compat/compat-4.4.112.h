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

#ifndef IBTRS_4_4_112_COMPAT_H
#define IBTRS_4_4_112_COMPAT_H

#include <rdma/ib_verbs.h>
#include <rdma/rdma_cm.h>
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

struct backport_rdma_cm_id;
typedef int (*backport_rdma_cm_event_handler)(struct backport_rdma_cm_id *id,
					      struct rdma_cm_event *event);

struct backport_rdma_cm_id {
	struct ib_device	*device;
	void			*context;
	struct ib_qp		*qp;
	backport_rdma_cm_event_handler	 event_handler;
	struct rdma_route	 route;
	enum rdma_port_space	 ps;
	enum ib_qp_type		 qp_type;
	u8			 port_num;
	void			 *ucontext;
};

struct backport_ib_pd {
	u32			local_dma_lkey;
	u32			flags;
	u32			unsafe_global_rkey;
	struct ib_mr		*__internal_mr;
	struct ib_pd		*__pd;
};

struct ib_rdma_wr {
	struct ib_send_wr	wr;
	u64			remote_addr;
	u32			rkey;
};

struct ib_reg_wr {
	struct ib_send_wr	wr;
	struct backport_ib_mr		*mr;
	u32			key;
	int			access;
};

#define IB_WR_REG_MR IB_WR_FAST_REG_MR

static inline int backport_ib_post_send(struct ib_qp *qp,
					struct ib_send_wr *send_wr,
					struct ib_send_wr **bad_send_wr)
{
	struct ib_send_wr *wr = send_wr, *prev = NULL;
	struct ib_rdma_wr *rdma_wr;

	if (unlikely(!send_wr))
		return -EINVAL;

	while (wr) {
		if (wr->opcode == IB_WR_RDMA_WRITE ||
		    wr->opcode == IB_WR_RDMA_WRITE_WITH_IMM) {
			rdma_wr = container_of(wr, typeof(*rdma_wr), wr);
			wr->wr.rdma.remote_addr = rdma_wr->remote_addr;
			wr->wr.rdma.rkey = rdma_wr->rkey;
			prev = wr;
		} else if (wr->opcode == IB_WR_REG_MR) {
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

static inline struct backport_rdma_cm_id *backport_rdma_create_id(
	struct net *net,
	backport_rdma_cm_event_handler event_handler,
	void *context, enum rdma_port_space ps,
	enum ib_qp_type qp_type)
{
	(void)net;

	return (struct backport_rdma_cm_id *)rdma_create_id(
		(rdma_cm_event_handler)event_handler,
		context, ps,
		qp_type);
}

static inline void backport_rdma_destroy_id(struct backport_rdma_cm_id *id)
{
	rdma_destroy_id((struct rdma_cm_id *)id);
}

static inline int backport_rdma_bind_addr(struct backport_rdma_cm_id *id,
					  struct sockaddr *addr)
{
	return rdma_bind_addr((struct rdma_cm_id *)id, addr);
}

static inline int backport_rdma_connect(struct backport_rdma_cm_id *id,
					struct rdma_conn_param *conn_param)
{
	return rdma_connect((struct rdma_cm_id *)id, conn_param);
}

static inline void backport_rdma_disconnect(struct backport_rdma_cm_id *id)
{
	rdma_disconnect((struct rdma_cm_id *)id);
}

static inline int backport_rdma_listen(struct backport_rdma_cm_id *id,
				       int backlog)
{
	return rdma_listen((struct rdma_cm_id *)id, backlog);
}

static inline int backport_rdma_accept(struct backport_rdma_cm_id *id,
				       struct rdma_conn_param *conn_param)
{
	return rdma_accept((struct rdma_cm_id *)id, conn_param);
}

static inline int backport_rdma_notify(struct backport_rdma_cm_id *id,
				       enum ib_event_type event)
{
	return rdma_notify((struct rdma_cm_id *)id, event);
}

static inline int backport_rdma_reject(struct backport_rdma_cm_id *id,
				       const void *data, u8 len)
{
	return rdma_reject((struct rdma_cm_id *)id, data, len);
}

static inline int backport_rdma_resolve_addr(struct backport_rdma_cm_id *id,
					     struct sockaddr *src,
					     struct sockaddr *dst,
					     int timeout_ms)
{
	return rdma_resolve_addr((struct rdma_cm_id *)id, src, dst, timeout_ms);
}

static inline int backport_rdma_resolve_route(struct backport_rdma_cm_id *id,
					      int timeout_ms)
{
	return rdma_resolve_route((struct rdma_cm_id *)id, timeout_ms);
}

static inline int backport_rdma_set_reuseaddr(struct backport_rdma_cm_id *id,
					      int reuse)
{
	return rdma_set_reuseaddr((struct rdma_cm_id *)id, reuse);
}

static inline int
backport_rdma_create_qp(struct backport_rdma_cm_id *id,
			struct backport_ib_pd *bpd,
			struct ib_qp_init_attr *qp_init_attr)
{
	return rdma_create_qp((struct rdma_cm_id *)id, bpd->__pd, qp_init_attr);
}

static inline void backport_rdma_destroy_qp(struct backport_rdma_cm_id *id)
{
	return rdma_destroy_qp((struct rdma_cm_id *)id);
}

static inline __be64
backport_rdma_get_service_id(struct backport_rdma_cm_id *id,
			     struct sockaddr *addr)
{
	return rdma_get_service_id((struct rdma_cm_id *)id, addr);
}

enum ib_pd_flags {
       /*
        * Create a memory registration for all memory in the system and place
        * the rkey for it into pd->unsafe_global_rkey.  This can be used by
        * ULPs to avoid the overhead of dynamic MRs.
        *
        * This flag is generally considered unsafe and must only be used in
        * extremly trusted environments.  Every use of it will log a warning
        * in the kernel log.
        */
       IB_PD_UNSAFE_GLOBAL_RKEY        = 0x01,
};

static inline struct backport_ib_pd *
backport_ib_alloc_pd(struct ib_device *device, unsigned int flags)
{
	struct ib_device_attr attrs;
	struct backport_ib_pd *bpd;
	int mr_access_flags = 0;
	struct ib_pd *pd;
	int err;

	memset(&attrs, 0, sizeof(attrs));

	err = ib_query_device((struct ib_device *)device, &attrs);
	if (unlikely(err))
		return ERR_PTR(err);

	pd = ib_alloc_pd((struct ib_device *)device);
	if (unlikely(IS_ERR(pd)))
		return ERR_CAST(pd);

	bpd = kzalloc(sizeof(*bpd), GFP_KERNEL);
	if (unlikely(!bpd)) {
		ib_dealloc_pd(pd);
		return ERR_PTR(-ENOMEM);
	}
	bpd->flags = flags;

	if (attrs.device_cap_flags & IB_DEVICE_LOCAL_DMA_LKEY)
		bpd->local_dma_lkey = device->local_dma_lkey;
	else
		mr_access_flags |= IB_ACCESS_LOCAL_WRITE;

	if (flags & IB_PD_UNSAFE_GLOBAL_RKEY)
		/*
		 * IB_ACCESS_LOCAL_WRITE is needed to pass ib_check_mr_access()
		 */
		mr_access_flags |= IB_ACCESS_LOCAL_WRITE |
			IB_ACCESS_REMOTE_READ | IB_ACCESS_REMOTE_WRITE;

	if (mr_access_flags) {
		struct ib_mr *mr;

		mr = ib_get_dma_mr(pd, mr_access_flags);
		if (unlikely(IS_ERR(mr))) {
			ib_dealloc_pd(pd);
			kfree(bpd);
			return ERR_CAST(mr);
		}
		bpd->__internal_mr = mr;

		if (!(attrs.device_cap_flags & IB_DEVICE_LOCAL_DMA_LKEY))
			bpd->local_dma_lkey = bpd->__internal_mr->lkey;

		if (flags & IB_PD_UNSAFE_GLOBAL_RKEY)
			bpd->unsafe_global_rkey = bpd->__internal_mr->rkey;
	}
	bpd->__pd = pd;

	return bpd;
}

static inline void backport_ib_dealloc_pd(struct backport_ib_pd *bpd)
{
	struct ib_pd *pd = bpd->__pd;
	int ret;

	if (bpd->__internal_mr) {
		ret = ib_dereg_mr(bpd->__internal_mr);
		WARN_ON(ret);
		bpd->__internal_mr = NULL;
	}

	ib_dealloc_pd(pd);
	kfree(bpd);
}

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
	struct ib_device_attr attr;
	struct ib_fmr_attr fmr_attr;
	struct fmr_per_mr *fmr_mr;
	int max_remaps, max_pages, err;

	err = ib_query_device(pd->device, &attr);
	if (unlikely(err))
		return ERR_PTR(err);
	if (unlikely(!attr.max_map_per_fmr))
		max_remaps = 32;
	else
		max_remaps = attr.max_map_per_fmr;

	fmr_mr = kzalloc(sizeof(*fmr_mr), GFP_KERNEL);
	if (unlikely(!fmr_mr))
		return ERR_PTR(-ENOMEM);

	/* XXX attr.max_fmr ? */
        max_pages = attr.max_mr_size;
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
		flush_scheduled_work();
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

enum ib_mr_type {
	IB_MR_TYPE_MEM_REG,
	IB_MR_TYPE_SIGNATURE,
	IB_MR_TYPE_SG_GAPS,
};

static inline struct backport_ib_mr *ib_alloc_mr(struct backport_ib_pd *bpd,
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

	err = alloc_and_set_fmr(bpd->__pd, bmr, 1<<12);
	if (unlikely(err))
		goto err;

	err = alloc_and_set_fmr(bpd->__pd, bmr, 1<<17);
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
ib_sg_to_pages(struct fmr_per_mr *fmr, struct scatterlist *sgl, int sg_nents,
	       unsigned int *sg_offset_p,
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

static inline int ib_map_mr_sg(struct backport_ib_mr *bmr,
			       struct scatterlist *sg,
			       int sg_nents,  unsigned int *sg_offset,
			       unsigned int page_size)
{
	struct fmr_per_mr *fmr_mr;
	struct fmr_struct *fmr;
	int err;

	fmr_mr = get_fmr(bmr, page_size);
	if (WARN_ON(!fmr_mr))
		return -EINVAL;

	if (fmr_mr->active_fmr->remap_count >= fmr_mr->max_remaps) {
		schedule_work(&fmr_mr->active_fmr->unmap_work);
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
	err = ib_sg_to_pages(fmr_mr, sg, sg_nents, sg_offset, fmr_set_page);
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

static const char * const cma_events[] = {
       [RDMA_CM_EVENT_ADDR_RESOLVED]    = "address resolved",
       [RDMA_CM_EVENT_ADDR_ERROR]       = "address error",
       [RDMA_CM_EVENT_ROUTE_RESOLVED]   = "route resolved ",
       [RDMA_CM_EVENT_ROUTE_ERROR]      = "route error",
       [RDMA_CM_EVENT_CONNECT_REQUEST]  = "connect request",
       [RDMA_CM_EVENT_CONNECT_RESPONSE] = "connect response",
       [RDMA_CM_EVENT_CONNECT_ERROR]    = "connect error",
       [RDMA_CM_EVENT_UNREACHABLE]      = "unreachable",
       [RDMA_CM_EVENT_REJECTED]         = "rejected",
       [RDMA_CM_EVENT_ESTABLISHED]      = "established",
       [RDMA_CM_EVENT_DISCONNECTED]     = "disconnected",
       [RDMA_CM_EVENT_DEVICE_REMOVAL]   = "device removal",
       [RDMA_CM_EVENT_MULTICAST_JOIN]   = "multicast join",
       [RDMA_CM_EVENT_MULTICAST_ERROR]  = "multicast error",
       [RDMA_CM_EVENT_ADDR_CHANGE]      = "address change",
       [RDMA_CM_EVENT_TIMEWAIT_EXIT]    = "timewait exit",
};

static inline const char *rdma_event_msg(enum rdma_cm_event_type event)
{
       size_t index = event;

       return (index < ARRAY_SIZE(cma_events) && cma_events[index]) ?
                       cma_events[index] : "unrecognized event";
}

static const char * const ib_events[] = {
       [IB_EVENT_CQ_ERR]               = "CQ error",
       [IB_EVENT_QP_FATAL]             = "QP fatal error",
       [IB_EVENT_QP_REQ_ERR]           = "QP request error",
       [IB_EVENT_QP_ACCESS_ERR]        = "QP access error",
       [IB_EVENT_COMM_EST]             = "communication established",
       [IB_EVENT_SQ_DRAINED]           = "send queue drained",
       [IB_EVENT_PATH_MIG]             = "path migration successful",
       [IB_EVENT_PATH_MIG_ERR]         = "path migration error",
       [IB_EVENT_DEVICE_FATAL]         = "device fatal error",
       [IB_EVENT_PORT_ACTIVE]          = "port active",
       [IB_EVENT_PORT_ERR]             = "port error",
       [IB_EVENT_LID_CHANGE]           = "LID change",
       [IB_EVENT_PKEY_CHANGE]          = "P_key change",
       [IB_EVENT_SM_CHANGE]            = "SM change",
       [IB_EVENT_SRQ_ERR]              = "SRQ error",
       [IB_EVENT_SRQ_LIMIT_REACHED]    = "SRQ limit reached",
       [IB_EVENT_QP_LAST_WQE_REACHED]  = "last WQE reached",
       [IB_EVENT_CLIENT_REREGISTER]    = "client reregister",
       [IB_EVENT_GID_CHANGE]           = "GID changed",
};

static inline const char *ib_event_msg(enum ib_event_type event)
{
       size_t index = event;

       return (index < ARRAY_SIZE(ib_events) && ib_events[index]) ?
                       ib_events[index] : "unrecognized event";
}

static const char * const wc_statuses[] = {
       [IB_WC_SUCCESS]                 = "success",
       [IB_WC_LOC_LEN_ERR]             = "local length error",
       [IB_WC_LOC_QP_OP_ERR]           = "local QP operation error",
       [IB_WC_LOC_EEC_OP_ERR]          = "local EE context operation error",
       [IB_WC_LOC_PROT_ERR]            = "local protection error",
       [IB_WC_WR_FLUSH_ERR]            = "WR flushed",
       [IB_WC_MW_BIND_ERR]             = "memory management operation error",
       [IB_WC_BAD_RESP_ERR]            = "bad response error",
       [IB_WC_LOC_ACCESS_ERR]          = "local access error",
       [IB_WC_REM_INV_REQ_ERR]         = "invalid request error",
       [IB_WC_REM_ACCESS_ERR]          = "remote access error",
       [IB_WC_REM_OP_ERR]              = "remote operation error",
       [IB_WC_RETRY_EXC_ERR]           = "transport retry counter exceeded",
       [IB_WC_RNR_RETRY_EXC_ERR]       = "RNR retry counter exceeded",
       [IB_WC_LOC_RDD_VIOL_ERR]        = "local RDD violation error",
       [IB_WC_REM_INV_RD_REQ_ERR]      = "remote invalid RD request",
       [IB_WC_REM_ABORT_ERR]           = "operation aborted",
       [IB_WC_INV_EECN_ERR]            = "invalid EE context number",
       [IB_WC_INV_EEC_STATE_ERR]       = "invalid EE context state",
       [IB_WC_FATAL_ERR]               = "fatal error",
       [IB_WC_RESP_TIMEOUT_ERR]        = "response timeout error",
       [IB_WC_GENERAL_ERR]             = "general error",
};

static inline const char *ib_wc_status_msg(enum ib_wc_status status)
{
       size_t index = status;

       return (index < ARRAY_SIZE(wc_statuses) && wc_statuses[index]) ?
                       wc_statuses[index] : "unrecognized status";
}

static const char * const ibcm_rej_reason_strs[] = {
       [IB_CM_REJ_NO_QP]                       = "no QP",
       [IB_CM_REJ_NO_EEC]                      = "no EEC",
       [IB_CM_REJ_NO_RESOURCES]                = "no resources",
       [IB_CM_REJ_TIMEOUT]                     = "timeout",
       [IB_CM_REJ_UNSUPPORTED]                 = "unsupported",
       [IB_CM_REJ_INVALID_COMM_ID]             = "invalid comm ID",
       [IB_CM_REJ_INVALID_COMM_INSTANCE]       = "invalid comm instance",
       [IB_CM_REJ_INVALID_SERVICE_ID]          = "invalid service ID",
       [IB_CM_REJ_INVALID_TRANSPORT_TYPE]      = "invalid transport type",
       [IB_CM_REJ_STALE_CONN]                  = "stale conn",
       [IB_CM_REJ_RDC_NOT_EXIST]               = "RDC not exist",
       [IB_CM_REJ_INVALID_GID]                 = "invalid GID",
       [IB_CM_REJ_INVALID_LID]                 = "invalid LID",
       [IB_CM_REJ_INVALID_SL]                  = "invalid SL",
       [IB_CM_REJ_INVALID_TRAFFIC_CLASS]       = "invalid traffic class",
       [IB_CM_REJ_INVALID_HOP_LIMIT]           = "invalid hop limit",
       [IB_CM_REJ_INVALID_PACKET_RATE]         = "invalid packet rate",
       [IB_CM_REJ_INVALID_ALT_GID]             = "invalid alt GID",
       [IB_CM_REJ_INVALID_ALT_LID]             = "invalid alt LID",
       [IB_CM_REJ_INVALID_ALT_SL]              = "invalid alt SL",
       [IB_CM_REJ_INVALID_ALT_TRAFFIC_CLASS]   = "invalid alt traffic class",
       [IB_CM_REJ_INVALID_ALT_HOP_LIMIT]       = "invalid alt hop limit",
       [IB_CM_REJ_INVALID_ALT_PACKET_RATE]     = "invalid alt packet rate",
       [IB_CM_REJ_PORT_CM_REDIRECT]            = "port CM redirect",
       [IB_CM_REJ_PORT_REDIRECT]               = "port redirect",
       [IB_CM_REJ_INVALID_MTU]                 = "invalid MTU",
       [IB_CM_REJ_INSUFFICIENT_RESP_RESOURCES] = "insufficient resp resources",
       [IB_CM_REJ_CONSUMER_DEFINED]            = "consumer defined",
       [IB_CM_REJ_INVALID_RNR_RETRY]           = "invalid RNR retry",
       [IB_CM_REJ_DUPLICATE_LOCAL_COMM_ID]     = "duplicate local comm ID",
       [IB_CM_REJ_INVALID_CLASS_VERSION]       = "invalid class version",
       [IB_CM_REJ_INVALID_FLOW_LABEL]          = "invalid flow label",
       [IB_CM_REJ_INVALID_ALT_FLOW_LABEL]      = "invalid alt flow label",
};

static inline const char *__attribute_const__ ibcm_reject_msg(int reason)
{
       size_t index = reason;

       if (index < ARRAY_SIZE(ibcm_rej_reason_strs) &&
           ibcm_rej_reason_strs[index])
               return ibcm_rej_reason_strs[index];
       else
               return "unrecognized reason";
}

static inline bool rdma_ib_or_roce(const struct ib_device *device,
				   u8 port_num)
{
	/* Since we use it for IBTRS only assume always true */
	return true;
}

static inline const char *__attribute_const__
rdma_reject_msg(struct backport_rdma_cm_id *id, int reason)
{
	if (rdma_ib_or_roce(id->device, id->port_num))
		return ibcm_reject_msg(reason);

	WARN_ON_ONCE(1);
	return "unrecognized transport";
}

static inline bool
rdma_is_consumer_reject(struct backport_rdma_cm_id *id, int reason)
{
	if (rdma_ib_or_roce(id->device, id->port_num))
		return reason == IB_CM_REJ_CONSUMER_DEFINED;

	WARN_ON_ONCE(1);
	return false;
}

static inline const void *
rdma_consumer_reject_data(struct backport_rdma_cm_id *id,
			  struct rdma_cm_event *ev,
			  u8 *data_len)
{
	const void *p;

	if (rdma_is_consumer_reject(id, ev->status)) {
		*data_len = ev->param.conn.private_data_len;
		p = ev->param.conn.private_data;
	} else {
		*data_len = 0;
		p = NULL;
	}
	return p;
}

#ifndef COMPAT
/*
 * linux/gfp.h
 */
#define __GFP_RETRY_MAYFAIL __GFP_REPEAT

/*
 * linux/uuid.h
 */
typedef uuid_be uuid_t;
#define uuid_gen uuid_be_gen
#define uuid_copy(dst,src) memcpy(dst, src, sizeof(uuid_t))
#define uuid_equal(u1,u2) (!memcmp(u1, u2, sizeof(uuid_t)))

/*
 * rdma/ib_verbs.h
 * rdma/rdma_cm.h
 * rdma/ib_cm.h
 */
#define ib_mr backport_ib_mr
#define ib_dereg_mr backport_ib_dereg_mr
#define ib_update_fast_reg_key backport_ib_update_fast_reg_key
#define ib_post_send backport_ib_post_send
#define ib_alloc_pd backport_ib_alloc_pd
#define ib_dealloc_pd backport_ib_dealloc_pd
#define ib_pd backport_ib_pd
#define rdma_cm_id backport_rdma_cm_id
#define rdma_cm_event_handler backport_rdma_cm_event_handler
#define rdma_create_id backport_rdma_create_id
#define rdma_destroy_id backport_rdma_destroy_id
#define rdma_bind_addr backport_rdma_bind_addr
#define rdma_connect backport_rdma_connect
#define rdma_disconnect backport_rdma_disconnect
#define rdma_create_qp backport_rdma_create_qp
#define rdma_destroy_qp backport_rdma_destroy_qp
#define rdma_notify backport_rdma_notify
#define rdma_resolve_addr backport_rdma_resolve_addr
#define rdma_resolve_route backport_rdma_resolve_route
#define rdma_set_reuseaddr backport_rdma_set_reuseaddr
#define rdma_listen backport_rdma_listen
#define rdma_accept backport_rdma_accept
#define rdma_reject backport_rdma_reject
#define rdma_get_service_id backport_rdma_get_service_id

/*
 * Common stuff
 */
#include "compat.h"

#endif /* ifndef COMPAT */
#endif /* IBTRS_4_4_112_COMPAT_H */
