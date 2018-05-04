#include "nat64/mod/stateful/timer.h"

#include "nat64/mod/common/linux_version.h"
#include "nat64/mod/common/xlator.h"
#include "nat64/mod/stateful/fragment_db.h"
#include "nat64/mod/stateful/joold.h"
#include "nat64/mod/stateful/bib/db.h"

/*
 * TODO We don't cancel the timer much at all; it seems like we should be using
 * a hrtimer instead.
 *
 * 	the kernel has two core timer mechanisms. One of those — the
 * 	high-resolution timer (or "hrtimer") — subsystem, is focused on
 * 	near-term events where the timer is expected to run to completion. The
 * 	other subsystem is just called "kernel timers"; it offers less precision
 * 	but is more efficient in situations where the timer will probably be
 * 	canceled before it fires.
 * 		(Jonathan Corbet, 2017)
 */

#define TIMER_PERIOD msecs_to_jiffies(2000)

static struct timer_list timer;

static int clean_state(struct xlator *jool, void *args)
{
	fragdb_clean(jool->nat64.frag);
	bib_clean(jool->nat64.bib, jool->ns);
	joold_clean(jool->nat64.joold, jool->nat64.bib);
	return 0;
}

static void timer_function(
#if LINUX_VERSION_AT_LEAST(4, 15, 0, 9999, 0)
		struct timer_list *arg
#else
		unsigned long arg
#endif
		)
{
	xlator_foreach(clean_state, NULL);
	mod_timer(&timer, jiffies + TIMER_PERIOD);
}

/**
 * This function should be always called *after* other init()s.
 */
int jtimer_setup(void)
{
#if LINUX_VERSION_AT_LEAST(4, 15, 0, 9999, 0)
	timer_setup(&timer, timer_function, 0);
#else
	init_timer(&timer);
	timer.function = timer_function;
	timer.expires = 0;
	timer.data = 0;
#endif
	mod_timer(&timer, jiffies + TIMER_PERIOD);
	return 0;
}

/**
 * This function should be always called *before* other destroy()s.
 */
void jtimer_teardown(void)
{
	del_timer_sync(&timer);
}
