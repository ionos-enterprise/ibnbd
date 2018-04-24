#ifndef __COMPAT_LIST__
#define __COMPAT_LIST__

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

/**
 * list_next_or_null_rr_rcu - get next list element in round-robin fashion.
 * @head:	the head for the list.
 * @ptr:        the list head to take the next element from.
 * @type:       the type of the struct this is embedded in.
 * @memb:       the name of the list_head within the struct.
 *
 * Next element returned in round-robin fashion, i.e. head will be skipped,
 * but if list is observed as empty, NULL will be returned.
 *
 * This primitive may safely run concurrently with the _rcu list-mutation
 * primitives such as list_add_rcu() as long as it's guarded by rcu_read_lock().
 */
#define list_next_or_null_rr_rcu(head, ptr, type, memb) \
({ \
	list_next_or_null_rcu(head, ptr, type, memb) ?: \
		list_next_or_null_rcu(head, READ_ONCE((ptr)->next), type, memb); \
})

#endif /* __COMPAT_LIST__ */
