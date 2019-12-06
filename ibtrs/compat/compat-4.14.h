/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2018 - 2019 1&1 IONOS Cloud GmbH. All rights reserved.
 * Authors: Roman Penyaev <roman.penyaev@profitbricks.com>
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

#include <rdma/ib_verbs.h>
#include <rdma/ib_cm.h>

static inline int backport_ib_post_send(struct ib_qp *qp,
					struct ib_send_wr *send_wr,
					const struct ib_send_wr **bad_send_wr)
{
	return ib_post_send(qp, send_wr, (struct ib_send_wr **)bad_send_wr);
}
#define ib_post_send backport_ib_post_send
static inline int backport_ib_post_recv(struct ib_qp *qp,
					struct ib_recv_wr *recv_wr,
					const struct ib_recv_wr **bad_recv_wr)
{
	return ib_post_recv(qp, recv_wr, (struct ib_recv_wr **)bad_recv_wr);
}
#define ib_post_recv backport_ib_post_recv

static inline void backport_iov_iter_kvec(struct iov_iter *i, int direction,
					  const struct kvec *kvec,
					  unsigned long nr_segs,
					  size_t count)
{
	if (direction == READ)
		direction = ITER_KVEC;
	iov_iter_kvec(i, direction, kvec, nr_segs, count);
}
#define iov_iter_kvec backport_iov_iter_kvec

/*
 * FIXME ugly and dangerous
 */
#define max_send_sge max_sge
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
