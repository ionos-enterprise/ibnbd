/*
 * Functions related to interrupt-poll handling in the block layer. This
 * is similar to NAPI for network devices.
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/bio.h>
#include <linux/interrupt.h>
#include <linux/cpu.h>
#include <linux/delay.h>
#include "irq_poll.h"

static unsigned int irq_poll_budget __read_mostly = 256;

struct irq_poll_tasklet {
	struct list_head list;
	struct tasklet_struct tasklet;
};

static DEFINE_PER_CPU(struct irq_poll_tasklet, cpu_tasklets);

/**
 * irq_poll_sched - Schedule a run of the iopoll handler
 * @iop:      The parent iopoll structure
 *
 * Description:
 *     Add this irq_poll structure to the pending poll list and trigger the
 *     tasklet.
 **/
void irq_poll_sched(struct irq_poll *iop)
{
	struct irq_poll_tasklet *tasklet;
	unsigned long flags;

	if (test_bit(IRQ_POLL_F_DISABLE, &iop->state))
		return;
	if (test_and_set_bit(IRQ_POLL_F_SCHED, &iop->state))
		return;

	local_irq_save(flags);
	tasklet = this_cpu_ptr(&cpu_tasklets);
	list_add_tail(&iop->list, &tasklet->list);
	tasklet_schedule(&tasklet->tasklet);
	local_irq_restore(flags);
}
EXPORT_SYMBOL(irq_poll_sched);

/**
 * __irq_poll_complete - Mark this @iop as un-polled again
 * @iop:      The parent iopoll structure
 *
 * Description:
 *     See irq_poll_complete(). This function must be called with interrupts
 *     disabled.
 **/
static void __irq_poll_complete(struct irq_poll *iop)
{
	list_del(&iop->list);
	smp_mb__before_atomic();
	clear_bit_unlock(IRQ_POLL_F_SCHED, &iop->state);
}

/**
 * irq_poll_complete - Mark this @iop as un-polled again
 * @iop:      The parent iopoll structure
 *
 * Description:
 *     If a driver consumes less than the assigned budget in its run of the
 *     iopoll handler, it'll end the polled mode by calling this function. The
 *     iopoll handler will not be invoked again before irq_poll_sched()
 *     is called.
 **/
void irq_poll_complete(struct irq_poll *iop)
{
	unsigned long flags;

	local_irq_save(flags);
	__irq_poll_complete(iop);
	local_irq_restore(flags);
}
EXPORT_SYMBOL(irq_poll_complete);

static void irq_poll_task(unsigned long data)
{
	struct irq_poll_tasklet *tasklet;
	int rearm = 0, budget = irq_poll_budget;
	unsigned long start_time = jiffies;

	local_irq_disable();
	tasklet = this_cpu_ptr(&cpu_tasklets);
	while (!list_empty(&tasklet->list)) {
		struct irq_poll *iop;
		int work, weight;

		/*
		 * If softirq window is exhausted then punt.
		 */
		if (budget <= 0 || time_after(jiffies, start_time)) {
			rearm = 1;
			break;
		}

		local_irq_enable();

		/* Even though interrupts have been re-enabled, this
		 * access is safe because interrupts can only add new
		 * entries to the tail of this list, and only ->poll()
		 * calls can remove this head entry from the list.
		 */
		iop = list_entry(tasklet->list.next, struct irq_poll, list);

		weight = iop->weight;
		work = 0;
		if (test_bit(IRQ_POLL_F_SCHED, &iop->state))
			work = iop->poll(iop, weight);

		budget -= work;

		local_irq_disable();

		/*
		 * Drivers must not modify the iopoll state, if they
		 * consume their assigned weight (or more, some drivers can't
		 * easily just stop processing, they have to complete an
		 * entire mask of commands).In such cases this code
		 * still "owns" the iopoll instance and therefore can
		 * move the instance around on the list at-will.
		 */
		if (work >= weight) {
			if (test_bit(IRQ_POLL_F_DISABLE, &iop->state))
				__irq_poll_complete(iop);
			else
				list_move_tail(&iop->list, &tasklet->list);
		}
	}

	if (rearm)
		tasklet_schedule(&tasklet->tasklet);

	local_irq_enable();
}

/**
 * irq_poll_disable - Disable iopoll on this @iop
 * @iop:      The parent iopoll structure
 *
 * Description:
 *     Disable io polling and wait for any pending callbacks to have completed.
 **/
void irq_poll_disable(struct irq_poll *iop)
{
	set_bit(IRQ_POLL_F_DISABLE, &iop->state);
	while (test_and_set_bit(IRQ_POLL_F_SCHED, &iop->state))
		msleep(1);
	clear_bit(IRQ_POLL_F_DISABLE, &iop->state);
}
EXPORT_SYMBOL(irq_poll_disable);

/**
 * irq_poll_enable - Enable iopoll on this @iop
 * @iop:      The parent iopoll structure
 *
 * Description:
 *     Enable iopoll on this @iop. Note that the handler run will not be
 *     scheduled, it will only mark it as active.
 **/
void irq_poll_enable(struct irq_poll *iop)
{
	BUG_ON(!test_bit(IRQ_POLL_F_SCHED, &iop->state));
	smp_mb__before_atomic();
	clear_bit_unlock(IRQ_POLL_F_SCHED, &iop->state);
}
EXPORT_SYMBOL(irq_poll_enable);

/**
 * irq_poll_init - Initialize this @iop
 * @iop:      The parent iopoll structure
 * @weight:   The default weight (or command completion budget)
 * @poll_fn:  The handler to invoke
 *
 * Description:
 *     Initialize and enable this irq_poll structure.
 **/
void irq_poll_init(struct irq_poll *iop, int weight, irq_poll_fn *poll_fn)
{
	memset(iop, 0, sizeof(*iop));
	INIT_LIST_HEAD(&iop->list);
	iop->weight = weight;
	iop->poll = poll_fn;
}
EXPORT_SYMBOL(irq_poll_init);

static int cpu_notify(struct notifier_block *self, unsigned long action,
		      void *hcpu)
{
	/*
	 * If a CPU goes away, splice its entries to the current CPU
	 * and trigger a run of the tasklet
	 */
	if (action == CPU_DEAD || action == CPU_DEAD_FROZEN) {
		struct irq_poll_tasklet *tasklet, *tasklet_this;
		int cpu = (unsigned long) hcpu;

		local_irq_disable();
		tasklet_this = this_cpu_ptr(&cpu_tasklets);
		tasklet = &per_cpu(cpu_tasklets, cpu);
		list_splice_init(&tasklet->list, &tasklet_this->list);
		tasklet_schedule(&tasklet_this->tasklet);
		local_irq_enable();
	}

	return NOTIFY_OK;
}

static struct notifier_block cpu_notifier = {
	.notifier_call	= cpu_notify,
};

int irq_poll_start(void)
{
	int i;

	for_each_possible_cpu(i) {
		struct irq_poll_tasklet *tasklet;

		tasklet = &per_cpu(cpu_tasklets, i);
		INIT_LIST_HEAD(&tasklet->list);
		tasklet_init(&tasklet->tasklet, irq_poll_task, 0);
	}
	register_hotcpu_notifier(&cpu_notifier);

	return 0;
}
EXPORT_SYMBOL(irq_poll_start);

void irq_poll_stop(void)
{
	int i;

	for_each_possible_cpu(i) {
		struct irq_poll_tasklet *tasklet;

		tasklet = &per_cpu(cpu_tasklets, i);
		tasklet_kill(&tasklet->tasklet);
		WARN_ON(!list_empty(&tasklet->list));
	}
	unregister_hotcpu_notifier(&cpu_notifier);
}
EXPORT_SYMBOL(irq_poll_stop);
