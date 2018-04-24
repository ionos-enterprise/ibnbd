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

#ifndef IBTRS_4_4_73_COMPAT_H
#define IBTRS_4_4_73_COMPAT_H

#include <rdma/ib_verbs.h>
#include <rdma/rdma_cm.h>
#include <rdma/ib_cm.h>

#include "4.4.73/irq_poll.h"

struct backport_ib_device {
	struct device                *dma_device;

	char                          name[IB_DEVICE_NAME_MAX];

	struct list_head              event_handler_list;
	spinlock_t                    event_handler_lock;

	spinlock_t                    client_data_lock;
	struct list_head              core_list;
	struct list_head              client_data_list;

	struct ib_cache               cache;
	int                          *pkey_tbl_len;
	int                          *gid_tbl_len;

	int			      num_comp_vectors;
	struct kobject		      *mad_sa_cc_kobj;

	struct iw_cm_verbs	     *iwcm;

	int		           (*get_protocol_stats)(struct ib_device *device,
							 union rdma_protocol_stats *stats);
	int		           (*query_device)(struct backport_ib_device *device,
						   struct ib_device_attr *device_attr,
						   /* BACKPORT: here pass NULL */
						   void *);
	int		           (*query_port)(struct ib_device *device,
						 u8 port_num,
						 struct ib_port_attr *port_attr);
	enum rdma_link_layer	   (*get_link_layer)(struct ib_device *device,
						     u8 port_num);
	/* When calling get_netdev, the HW vendor's driver should return the
	 * net device of device @device at port @port_num. The function
	 * is called in rtnl_lock. The HW vendor's device driver must guarantee
	 * to return NULL before the net device has reached
	 * NETDEV_UNREGISTER_FINAL state.
	 */
	struct net_device	  *(*get_netdev)(struct ib_device *device,
						 u8 port_num);
	int		           (*query_gid)(struct ib_device *device,
						u8 port_num, int index,
						union ib_gid *gid);
	/* When calling modify_gid, the HW vendor's driver should
	 * modify the gid of device @device at gid index @index of
	 * port @port to be @gid. Meta-info of that gid (for example,
	 * the network device related to this gid is available
	 * at @attr. @context allows the HW vendor driver to store extra
	 * information together with a GID entry. The HW vendor may allocate
	 * memory to contain this information and store it in @context when a
	 * new GID entry is written to. Upon the deletion of a GID entry,
	 * the HW vendor must free any allocated memory. The caller will clear
	 * @context afterwards.GID deletion is done by passing the zero gid.
	 * Params are consistent until the next call of modify_gid.
	 * The function should return 0 on success or error otherwise.
	 * The function could be called concurrently for different ports.
	 */
	int		           (*modify_gid)(struct ib_device *device,
						 u8 port_num,
						 unsigned int index,
						 const union ib_gid *gid,
						 const struct ib_gid_attr *attr,
						 void **context);
	int			   (*set_vf_port_guid)(struct ib_device *device,
						       u8 port_num, u64 guid);
	int			   (*set_vf_node_guid)(struct ib_device *device,
						       u16 vf, u64 guid);
	int		           (*query_pkey)(struct ib_device *device,
						 u8 port_num, u16 index, u16 *pkey);
	int		           (*modify_device)(struct ib_device *device,
						    int device_modify_mask,
						    struct ib_device_modify *device_modify);
	int		           (*modify_port)(struct ib_device *device,
						  u8 port_num, int port_modify_mask,
						  struct ib_port_modify *port_modify);
	struct ib_ucontext *       (*alloc_ucontext)(struct ib_device *device,
						     struct ib_udata *udata);
	int                        (*dealloc_ucontext)(struct ib_ucontext *context);
	int                        (*mmap)(struct ib_ucontext *context,
					   struct vm_area_struct *vma);
	struct ib_pd *             (*alloc_pd)(struct ib_device *device,
					       struct ib_ucontext *context,
					       struct ib_udata *udata);
	int                        (*dealloc_pd)(struct ib_pd *pd);
	struct ib_ah *             (*create_ah)(struct ib_pd *pd,
						struct ib_ah_attr *ah_attr);
	int                        (*modify_ah)(struct ib_ah *ah,
						struct ib_ah_attr *ah_attr);
	int                        (*query_ah)(struct ib_ah *ah,
					       struct ib_ah_attr *ah_attr);
	int                        (*destroy_ah)(struct ib_ah *ah);
	struct ib_srq *            (*create_srq)(struct ib_pd *pd,
						 struct ib_srq_init_attr *srq_init_attr,
						 struct ib_udata *udata);
	int                        (*modify_srq)(struct ib_srq *srq,
						 struct ib_srq_attr *srq_attr,
						 enum ib_srq_attr_mask srq_attr_mask,
						 struct ib_udata *udata);
	int                        (*query_srq)(struct ib_srq *srq,
						struct ib_srq_attr *srq_attr);
	int                        (*destroy_srq)(struct ib_srq *srq);
	int                        (*post_srq_recv)(struct ib_srq *srq,
						    struct ib_recv_wr *recv_wr,
						    struct ib_recv_wr **bad_recv_wr);
	struct ib_qp *             (*create_qp)(struct ib_pd *pd,
						struct ib_qp_init_attr *qp_init_attr,
						struct ib_udata *udata);
	int                        (*modify_qp)(struct ib_qp *qp,
						struct ib_qp_attr *qp_attr,
						int qp_attr_mask,
						struct ib_udata *udata);
	int                        (*query_qp)(struct ib_qp *qp,
					       struct ib_qp_attr *qp_attr,
					       int qp_attr_mask,
					       struct ib_qp_init_attr *qp_init_attr);
	int                        (*destroy_qp)(struct ib_qp *qp);
	int                        (*post_send)(struct ib_qp *qp,
						struct ib_send_wr *send_wr,
						struct ib_send_wr **bad_send_wr);
	int                        (*post_recv)(struct ib_qp *qp,
						struct ib_recv_wr *recv_wr,
						struct ib_recv_wr **bad_recv_wr);
	struct ib_cq *             (*create_cq)(struct ib_device *device,
						struct ib_cq_init_attr *attr,
						struct ib_ucontext *context,
						struct ib_udata *udata);
	int                        (*modify_cq)(struct ib_cq *cq,
						struct ib_cq_attr *cq_attr,
						int cq_attr_mask);
	int                        (*destroy_cq)(struct ib_cq *cq);
	int                        (*resize_cq)(struct ib_cq *cq, int cqe,
						struct ib_udata *udata);
	int                        (*poll_cq)(struct ib_cq *cq, int num_entries,
					      struct ib_wc *wc);
	int                        (*peek_cq)(struct ib_cq *cq, int wc_cnt);
	int                        (*req_notify_cq)(struct ib_cq *cq,
						    enum ib_cq_notify_flags flags);
	int                        (*req_ncomp_notif)(struct ib_cq *cq,
						      int wc_cnt);
	struct ib_mr *             (*get_dma_mr)(struct ib_pd *pd,
						 int mr_access_flags);
	struct ib_mr *             (*reg_phys_mr)(struct ib_pd *pd,
						  struct ib_phys_buf *phys_buf_array,
						  int num_phys_buf,
						  int mr_access_flags,
						  u64 *iova_start);
	struct ib_mr *             (*reg_user_mr)(struct ib_pd *pd,
						  u64 start, u64 length,
						  u64 virt_addr,
						  int mr_access_flags,
						  struct ib_udata *udata,
						  int mr_id);
	int			   (*rereg_user_mr)(struct ib_mr *mr,
						    int flags,
						    u64 start, u64 length,
						    u64 virt_addr,
						    int mr_access_flags,
						    struct ib_pd *pd,
						    struct ib_udata *udata);
	int                        (*query_mr)(struct ib_mr *mr,
					       struct ib_mr_attr *mr_attr);
	int                        (*dereg_mr)(struct ib_mr *mr);
	int                        (*destroy_mr)(struct ib_mr *mr);
	struct ib_mr *		   (*create_mr)(struct ib_pd *pd,
						struct ib_mr_init_attr *mr_init_attr);
	struct ib_mr *		   (*alloc_fast_reg_mr)(struct ib_pd *pd,
					       int max_page_list_len);
	struct ib_fast_reg_page_list * (*alloc_fast_reg_page_list)(struct ib_device *device,
								   int page_list_len);
	void			   (*free_fast_reg_page_list)(struct ib_fast_reg_page_list *page_list);
	struct ib_indir_reg_list * (*alloc_indir_reg_list)(struct ib_device *device,
							   unsigned int indir_list_len);
	void			   (*free_indir_reg_list)(struct ib_indir_reg_list *indir_list);
	int                        (*rereg_phys_mr)(struct ib_mr *mr,
						    int mr_rereg_mask,
						    struct ib_pd *pd,
						    struct ib_phys_buf *phys_buf_array,
						    int num_phys_buf,
						    int mr_access_flags,
						    u64 *iova_start);
	struct ib_mw *             (*alloc_mw)(struct ib_pd *pd,
					       enum ib_mw_type type);
	int                        (*bind_mw)(struct ib_qp *qp,
					      struct ib_mw *mw,
					      struct ib_mw_bind *mw_bind);
	int                        (*dealloc_mw)(struct ib_mw *mw);
	struct ib_fmr *	           (*alloc_fmr)(struct ib_pd *pd,
						int mr_access_flags,
						struct ib_fmr_attr *fmr_attr);
	int		           (*map_phys_fmr)(struct ib_fmr *fmr,
						   u64 *page_list, int list_len,
						   u64 iova);
	int		           (*unmap_fmr)(struct list_head *fmr_list);
	int		           (*dealloc_fmr)(struct ib_fmr *fmr);
	int                        (*attach_mcast)(struct ib_qp *qp,
						   union ib_gid *gid,
						   u16 lid);
	int                        (*detach_mcast)(struct ib_qp *qp,
						   union ib_gid *gid,
						   u16 lid);
	int                        (*process_mad)(struct ib_device *device,
						  int process_mad_flags,
						  u8 port_num,
						  struct ib_wc *in_wc,
						  struct ib_grh *in_grh,
						  struct ib_mad *in_mad,
						  struct ib_mad *out_mad);
	struct ib_xrcd *	   (*alloc_xrcd)(struct ib_device *device,
						 struct ib_ucontext *ucontext,
						 struct ib_udata *udata);
	int			   (*dealloc_xrcd)(struct ib_xrcd *xrcd);
	struct ib_flow *	   (*create_flow)(struct ib_qp *qp,
						  struct ib_flow_attr
						  *flow_attr,
						  int domain);
	int			   (*destroy_flow)(struct ib_flow *flow_id);
	int			   (*check_mr_status)(struct ib_mr *mr, u32 check_mask,
						      struct ib_mr_status *mr_status);
	void			   (*disassociate_ucontext)(struct ib_ucontext *ibcontext);

	unsigned long		   (*get_unmapped_area)(struct file *file,
					unsigned long addr,
					unsigned long len, unsigned long pgoff,
					unsigned long flags);
	int			   (*get_vf_stats)(struct ib_device *device, u16 vf,
						   struct ib_vf_stats *stats);
	int                        (*query_values)(struct ib_device *device,
						   int q_values,
						   struct ib_device_values *values);
	int			   (*ioctl)(struct ib_ucontext *context,
					    unsigned int cmd,
					    unsigned long arg);
	struct ib_dma_mapping_ops   *dma_ops;

	struct module               *owner;
	struct device                dev;
	struct kobject               *ports_parent;
	struct list_head             port_list;

	int			     uverbs_abi_ver;
	u64			     uverbs_cmd_mask;
	u64			     uverbs_ex_cmd_mask;

	struct ib_odp_statistics     odp_statistics;

	char			     node_desc[64];
	__be64			     node_guid;
	u32			     local_dma_lkey;
	u8                           node_type;
	u8                           phys_port_cnt;
	struct kref		     refcount;
	struct completion	     free;

	/*
	 * Experimental data and functions
	 */
	struct ib_wq *		(*create_wq)(struct ib_pd *pd,
					     struct ib_wq_init_attr *init_attr,
					     struct ib_udata *udata);
	int			(*destroy_wq)(struct ib_wq *wq);
	int			(*modify_wq)(struct ib_wq *wq,
					     struct ib_wq_attr *attr,
					     enum ib_wq_attr_mask attr_mask,
					     struct ib_udata *udata);
	struct ib_rwq_ind_table *(*create_rwq_ind_table)(struct ib_device *device,
							 struct ib_rwq_ind_table_init_attr *init_attr,
							 struct ib_udata *udata);
	int                     (*destroy_rwq_ind_table)(struct ib_rwq_ind_table *wq_ind_table);
	int			(*exp_query_device)(struct ib_device *device,
						    struct ib_exp_device_attr *device_attr);
	struct ib_qp *		(*exp_create_qp)(struct ib_pd *pd,
						 struct ib_exp_qp_init_attr *qp_init_attr,
						 struct ib_udata *udata);
	struct ib_dct *		(*exp_create_dct)(struct ib_pd *pd,
					      struct ib_dct_init_attr *attr,
					      struct ib_udata *udata);
	int			(*exp_destroy_dct)(struct ib_dct *dct);
	int			(*exp_query_dct)(struct ib_dct *dct, struct ib_dct_attr *attr);
	int			(*exp_arm_dct)(struct ib_dct *dct, struct ib_udata *udata);
	int			(*exp_query_mkey)(struct ib_mr *mr,
						  u64 mkey_attr_mask,
						  struct ib_mkey_attr *mkey_attr);
	/**
	 * exp_rereg_user_mr - Modifies the attributes of an existing memory region.
	 *   Conceptually, this call performs the functions deregister memory region
	 *   followed by register memory region.  Where possible,
	 *   resources are reused instead of deallocated and reallocated.
	 * @mr: The memory region to modify.
	 * @flags: A bit-mask used to indicate which of the following
	 *   properties of the memory region are being modified.
	 * @start: If %IB_MR_REREG_TRANS is set in flags, this
	 *   field specifies the start of the virtual address to use in the new
	 *   translation, otherwise, this parameter is ignored.
	 * @length: If %IB_MR_REREG_TRANS is set in flags, this
	 *   field specifies the length of the virtual address to use in the new
	 *   translation, otherwise, this parameter is ignored.
	 * @virt_address: If %IB_MR_REREG_TRANS is set in flags, this
	 *   field specifies the start of the virtual address in HCA to use in the new
	 *   translation, otherwise, this parameter is ignored.
	 * @mr_access_flags: If %IB_MR_REREG_ACCESS is set in flags, this
	 *   field specifies the new memory access rights, otherwise, this
	 *   parameter is ignored.
	 * @pd: If %IB_MR_REREG_PD is set in flags, this field specifies
	 *   the new protection domain to associated with the memory region,
	 *   otherwise, this parameter is ignored.
	 */
	int			(*exp_rereg_user_mr)(struct ib_mr *mr,
						     int flags,
						     u64 start, u64 length,
						     u64 virt_addr,
						     int mr_access_flags,
						     struct ib_pd *pd);

	int			(*exp_prefetch_mr)(struct ib_mr *mr,
						   u64 start, u64 length,
						   u32 flags);

	u64			uverbs_exp_cmd_mask;
};

enum ib_poll_context {
       IB_POLL_DIRECT,         /* caller context, no hw completions */
       IB_POLL_SOFTIRQ,        /* poll from softirq context */
       IB_POLL_WORKQUEUE,      /* poll from workqueue */
};

struct backport_ib_cq {
	struct ib_cq		*cq;

	void			*cq_context;
	enum ib_poll_context	poll_ctx;
	struct backport_ib_wc	*wc;
	union {
		struct irq_poll		iop;
		struct work_struct	work;
	};
};

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
	struct backport_ib_device	*device;
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

struct backport_ib_wc {
	union {
		u64		wr_id;
		struct ib_cqe	*wr_cqe;
	};
	enum ib_wc_status	status;
	enum ib_wc_opcode	opcode;
	u32			vendor_err;
	u32			byte_len;
	struct ib_qp	       *qp;
	union {
		__be32		imm_data;
		u32		invalidate_rkey;
	} ex;
	u32			src_qp;
	int			wc_flags;
	u16			pkey_index;
	u32			slid;
	u8			sl;
	u8			dlid_path_bits;
	u8			port_num;	/* valid only for DR SMPs on switches */
	u8			smac[ETH_ALEN];
	u16			vlan_id;
	u8			network_hdr_type;
};

struct ib_cqe {
       void (*done)(struct backport_ib_cq *cq, struct backport_ib_wc *wc);
};

struct backport_ib_send_wr {
	struct backport_ib_send_wr      *next;
	union {
		u64		wr_id;
		struct ib_cqe	*wr_cqe;
	};
	struct ib_sge	       *sg_list;
	int			num_sge;
	enum ib_wr_opcode	opcode;
	int			send_flags;
	union {
		__be32		imm_data;
		u32		invalidate_rkey;
	} ex;
	union {
		struct {
			u64	remote_addr;
			u32	rkey;
		} rdma;
		struct {
			u64	remote_addr;
			u64	compare_add;
			u64	swap;
			u64	compare_add_mask;
			u64	swap_mask;
			u32	rkey;
		} atomic;
		struct {
			struct ib_ah *ah;
			void   *header;
			int     hlen;
			int     mss;
			u32	remote_qpn;
			u32	remote_qkey;
			u16	pkey_index; /* valid for GSI only */
			u8	port_num;   /* valid for DR SMPs on switch only */
		} ud;
		struct {
			u64				iova_start;
			struct ib_fast_reg_page_list   *page_list;
			unsigned int			page_shift;
			unsigned int			page_list_len;
			u64				length;
			int				access_flags;
			u32				rkey;
		} fast_reg;
		struct {
			int		npages;
			int		access_flags;
			u32		mkey;
			struct ib_pd   *pd;
			u64		virt_addr;
			u64		length;
			int		page_shift;
		} umr;
		struct {
			struct ib_mw            *mw;
			/* The new rkey for the memory window. */
			u32                      rkey;
			struct ib_mw_bind_info   bind_info;
		} bind_mw;
		struct {
			struct ib_sig_attrs    *sig_attrs;
			struct ib_mr	       *sig_mr;
			int			access_flags;
			struct ib_sge	       *prot;
		} sig_handover;
		struct {
			u64				iova_start;
			struct ib_indir_reg_list       *indir_list;
			unsigned int			indir_list_len;
			u64				length;
			unsigned int			access_flags;
			u32				mkey;
		} indir_reg;
	} wr;
	u32			xrc_remote_srq_num;	/* XRC TGT QPs only */
};

struct backport_ib_recv_wr {
	struct backport_ib_recv_wr      *next;
	union {
		u64		wr_id;
		struct ib_cqe	*wr_cqe;
	};
	struct ib_sge	       *sg_list;
	int			num_sge;
};

struct ib_rdma_wr {
	struct backport_ib_send_wr	wr;
	u64			remote_addr;
	u32			rkey;
};

#define IB_WR_REG_MR IB_WR_FAST_REG_MR

struct ib_reg_wr {
	struct backport_ib_send_wr	wr;
	struct backport_ib_mr		*mr;
	u32			key;
	int			access;
};

static inline int backport_ib_post_send(struct ib_qp *qp,
					struct backport_ib_send_wr *send_wr,
					struct backport_ib_send_wr **bad_send_wr)
{
	struct backport_ib_send_wr *wr = send_wr, *prev = NULL;
	struct ib_rdma_wr *rdma_wr;

	BUILD_BUG_ON(sizeof(struct ib_send_wr) !=
		     sizeof(struct backport_ib_send_wr));

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

	return ib_post_send(qp, (struct ib_send_wr *)send_wr,
			    (struct ib_send_wr **)bad_send_wr);
}

static inline int backport_ib_post_recv(struct ib_qp *qp,
					struct backport_ib_recv_wr *recv_wr,
					struct backport_ib_recv_wr **bad_recv_wr)
{
	BUILD_BUG_ON(sizeof(struct ib_recv_wr) !=
		     sizeof(struct backport_ib_recv_wr));

	return ib_post_recv(qp, (struct ib_recv_wr *)recv_wr,
			    (struct ib_recv_wr **)bad_recv_wr);
}

static inline struct backport_rdma_cm_id *backport_rdma_create_id(
	struct net *net,
	backport_rdma_cm_event_handler event_handler,
	void *context, enum rdma_port_space ps,
	enum ib_qp_type qp_type)
{
	(void)net;

	BUILD_BUG_ON(sizeof(struct ib_wc) !=
		     sizeof(struct backport_ib_wc));

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

struct backport_ib_qp_init_attr {
	void                  (*event_handler)(struct ib_event *, void *);
	void		       *qp_context;
	struct backport_ib_cq  *send_cq;
	struct backport_ib_cq  *recv_cq;
	struct ib_srq	       *srq;
	struct ib_xrcd	       *xrcd;     /* XRC TGT QPs only */
	struct ib_qp_cap	cap;
	union {
		struct ib_qp *qpg_parent; /* see qpg_type */
		struct ib_qpg_init_attrib parent_attrib;
	};
	enum ib_sig_type	sq_sig_type;
	enum ib_qp_type		qp_type;
	enum ib_qp_create_flags	create_flags;
	enum ib_qpg_type	qpg_type;
	u8			port_num; /* special QP types only */
};

static inline int
backport_rdma_create_qp(struct backport_rdma_cm_id *id,
			struct backport_ib_pd *bpd,
			struct backport_ib_qp_init_attr *bqp_init_attr)
{
	struct backport_ib_cq *send_bcq = bqp_init_attr->send_cq;
	struct backport_ib_cq *recv_bcq = bqp_init_attr->recv_cq;
	struct ib_qp_init_attr *qp_init_attr =
		(struct ib_qp_init_attr *)bqp_init_attr;
	int err;

	qp_init_attr->send_cq = send_bcq->cq;
	qp_init_attr->recv_cq = recv_bcq->cq;
	err = rdma_create_qp((struct rdma_cm_id *)id, bpd->__pd, qp_init_attr);
	bqp_init_attr->send_cq = send_bcq;
	bqp_init_attr->recv_cq = recv_bcq;

	return err;
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
backport_ib_alloc_pd(struct backport_ib_device *device,
		     unsigned int flags)
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

static inline u64 backport_ib_dma_map_single(struct backport_ib_device *dev,
					     void *cpu_addr, size_t size,
					     enum dma_data_direction direction)
{
	return ib_dma_map_single((struct ib_device *)dev,
				 cpu_addr, size, direction);
}

static inline void backport_ib_dma_unmap_single(struct backport_ib_device *dev,
						u64 addr, size_t size,
						enum dma_data_direction direction)
{
	return ib_dma_unmap_single((struct ib_device *)dev, addr,
				   size, direction);
}

static inline u64 backport_ib_dma_map_page(struct backport_ib_device *dev,
					   struct page *page,
					   unsigned long offset, size_t size,
					   enum dma_data_direction direction)
{
	return ib_dma_map_page((struct ib_device *)dev, page,
			       offset, size, direction);
}

static inline void backport_ib_dma_unmap_page(struct backport_ib_device *dev,
					      u64 addr, size_t size,
					      enum dma_data_direction direction)
{
	return ib_dma_unmap_page((struct ib_device *)dev, addr,
				 size, direction);
}

static inline int backport_ib_dma_map_sg(struct backport_ib_device *dev,
					 struct scatterlist *sg, int nents,
					 enum dma_data_direction direction)
{
	return ib_dma_map_sg((struct ib_device *)dev,
			     sg, nents, direction);
}

static inline void backport_ib_dma_unmap_sg(struct backport_ib_device *dev,
					    struct scatterlist *sg, int nents,
					    enum dma_data_direction direction)
{
	return ib_dma_unmap_sg((struct ib_device *)dev, sg,
			       nents, direction);
}

static inline unsigned int backport_ib_sg_dma_len(struct backport_ib_device *dev,
						  struct scatterlist *sg)
{
	return ib_sg_dma_len((struct ib_device *)dev, sg);
}

static inline u64 backport_ib_sg_dma_address(struct backport_ib_device *dev,
					     struct scatterlist *sg)
{
	return ib_sg_dma_address((struct ib_device *)dev, sg);
}

static inline int backport_ib_dma_mapping_error(struct backport_ib_device *dev,
						u64 dma_addr)
{
	return ib_dma_mapping_error((struct ib_device *)dev, dma_addr);
}

static inline void
backport_ib_dma_sync_single_for_cpu(struct backport_ib_device *dev,
				    u64 addr, size_t size,
				    enum dma_data_direction dir)
{
	ib_dma_sync_single_for_cpu((struct ib_device *)dev,
				   addr, size, dir);
}

static inline void
backport_ib_dma_sync_single_for_device(struct backport_ib_device *dev,
			      u64 addr, size_t size,
			      enum dma_data_direction dir)
{
	ib_dma_sync_single_for_device((struct ib_device *)dev,
				      addr, size, dir);
}

struct backport_ib_cq *ib_alloc_cq(struct backport_ib_device *dev,
			  void *private,
			  int nr_cqe, int comp_vector,
			  enum ib_poll_context poll_ctx);
void ib_free_cq(struct backport_ib_cq *cq);
void ib_drain_qp(struct ib_qp *qp);

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

static inline bool rdma_ib_or_roce(const struct backport_ib_device *device,
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
 * rdma/ib_verbs.h
 * rdma/rdma_cm.h
 * rdma/ib_cm.h
 * rdma/ib_fmr_pool.h
 */
#define ib_device backport_ib_device
#define ib_cq backport_ib_cq
#define ib_mr backport_ib_mr
#define ib_create_fmr_pool backport_ib_create_fmr_pool
#define ib_dereg_mr backport_ib_dereg_mr
#define ib_update_fast_reg_key backport_ib_update_fast_reg_key
#define ib_qp_init_attr backport_ib_qp_init_attr
#define ib_dma_mapping_error backport_ib_dma_mapping_error
#define ib_dma_map_single backport_ib_dma_map_single
#define ib_dma_unmap_single backport_ib_dma_unmap_single
#define ib_dma_map_page backport_ib_dma_map_page
#define ib_dma_unmap_page backport_ib_dma_unmap_page
#define ib_dma_map_sg backport_ib_dma_map_sg
#define ib_dma_unmap_sg backport_ib_dma_unmap_sg
#define ib_dma_sync_single_for_device backport_ib_dma_sync_single_for_device
#define ib_dma_sync_single_for_cpu backport_ib_dma_sync_single_for_cpu
#define ib_sg_dma_len backport_ib_sg_dma_len
#define ib_sg_dma_address backport_ib_sg_dma_address
#define ib_post_send backport_ib_post_send
#define ib_post_recv backport_ib_post_recv
#define ib_send_wr backport_ib_send_wr
#define ib_recv_wr backport_ib_recv_wr
#define ib_alloc_pd backport_ib_alloc_pd
#define ib_dealloc_pd backport_ib_dealloc_pd
#define ib_wc backport_ib_wc
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

#endif /* ifndef COMPAT */
#endif /* IBTRS_4_4_73_COMPAT_H */
