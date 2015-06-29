/*
 * Copyright (c) 2009 The Regents of the University of California
 * Barret Rhoden <brho@cs.berkeley.edu>
 * See LICENSE for details.
 */

#ifdef __SHARC__
#pragma nosharc
#endif

#include <arch/arch.h>
#include <atomic.h>
#include <smp.h>
#include <error.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <pmap.h>
#include <process.h>
#include <manager.h>
#include <trap.h>

struct per_cpu_info per_cpu_info[MAX_NUM_CPUS];

// tracks number of global waits on smp_calls, must be <= NUM_HANDLER_WRAPPERS
atomic_t outstanding_calls = 0;

/* All cores end up calling this whenever there is nothing left to do.  Non-zero
 * cores call it when they are done booting.  Other cases include after getting
 * a DEATH IPI.
 * - Management cores (core 0 for now) call manager, which should never return.
 * - Worker cores halt and wake up when interrupted, do any work on their work
 *   queue, then halt again.
 * TODO: think about unifying the manager into a workqueue function, so we don't
 * need to check mgmt_core in here.  it gets a little ugly, since there are
 * other places where we check for mgmt and might not smp_idle / call manager.
 */
static void __smp_idle(void)
{
	int8_t state = 0;
	struct per_cpu_info *pcpui;
	int try = 10;
	int i; 
	pcpui = &per_cpu_info[core_id()];

	/* There was a process running here, and we should return to it */
	if (pcpui->cur_tf) {			/* aka, current_tf */
		assert(pcpui->cur_proc);	/* aka, current */
		proc_restartcore();
		assert(0);
	}
	/* if we made it here, we truly want to idle */
	/* in the future, we may need to proactively leave process context here.
	 * for now, it is possible to have a current loaded, even if we are idle
	 * (and presumably about to execute a kmsg or fire up a vcore). */
	if (!management_core()) {
		enable_irq();
		while (1) {
			process_routine_kmsg(0);
			cpu_halt();
		}
	} else {
		do
		{
			udelay(3000);
			try -= 1;
			for(i=0; i<num_cpus; ++i)
			{
				pcpui = &per_cpu_info[i];
				if (pcpui->cur_tf)
				{
					if(try<75)try += 15;
				}
			}
		}while(try);
		enable_irqsave(&state);
		/* this makes us wait to enter the manager til any IO is done (totally
		 * arbitrary 10ms), so we can handle the routine message that we
		 * currently use to do the completion.  Note this also causes us to wait
		 * 10ms regardless of how long the IO takes.  This all needs work. */
		//udelay(10000); /* done in the manager for now */
		process_routine_kmsg(0);
		disable_irqsave(&state);
		manager();
	}
	assert(0);
}

void smp_idle(void)
{
	#ifdef __CONFIG_RESET_STACKS__
	set_stack_pointer(get_stack_top());
	#endif /* __CONFIG_RESET_STACKS__ */
	__smp_idle();
	assert(0);
}

/* Arch-independent per-cpu initialization.  This will call the arch dependent
 * init first. */
void smp_percpu_init(void)
{
	uint32_t coreid = core_id();
	/* Do this first */
	__arch_pcpu_init(coreid);
	per_cpu_info[coreid].spare = 0;
	/* Init relevant lists */
	spinlock_init(&per_cpu_info[coreid].immed_amsg_lock);
	STAILQ_INIT(&per_cpu_info[coreid].immed_amsgs);
	spinlock_init(&per_cpu_info[coreid].routine_amsg_lock);
	STAILQ_INIT(&per_cpu_info[coreid].routine_amsgs);
	/* Initialize the per-core timer chain */
	init_timer_chain(&per_cpu_info[coreid].tchain, set_pcpu_alarm_interrupt);
}
