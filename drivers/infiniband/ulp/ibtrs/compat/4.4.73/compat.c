#include <linux/module.h>
#include "irq_poll.h"

MODULE_DESCRIPTION("IBTRS compat layer");
MODULE_LICENSE("GPL");

struct workqueue_struct *ib_comp_wq;

static __init int compat_init(void)
{
	int err;

	ib_comp_wq = alloc_workqueue("ib-comp-wq",
				     WQ_HIGHPRI | WQ_MEM_RECLAIM | WQ_SYSFS, 0);
	if (unlikely(!ib_comp_wq))
		return -ENOMEM;

	err = irq_poll_start();
	if (unlikely(err)) {
		destroy_workqueue(ib_comp_wq);
		return err;
	}

	return 0;
}

static void __exit compat_exit(void)
{
	irq_poll_stop();
	destroy_workqueue(ib_comp_wq);
}

module_init(compat_init);
module_exit(compat_exit);
