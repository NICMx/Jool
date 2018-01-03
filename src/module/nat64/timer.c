#include "nat64/timer.h"

#include "xlator.h"
#include "nat64/joold.h"
#include "nat64/bib/db.h"

#define TIMER_PERIOD msecs_to_jiffies(2000)

static struct timer_list timer;

static int clean_state(struct xlator *jool, void *args)
{
	bib_clean(jool->bib);
	joold_clean(jool->joold, jool->bib);
	return 0;
}

static void timer_function(unsigned long arg)
{
	xlator_foreach(clean_state, NULL);
	mod_timer(&timer, jiffies + TIMER_PERIOD);
}

/**
 * This function should be always called *after* other init()s.
 */
int timer_init(void)
{
	init_timer(&timer);
	timer.function = timer_function;
	timer.expires = 0;
	timer.data = 0;
	mod_timer(&timer, jiffies + TIMER_PERIOD);
	return 0;
}

/**
 * This function should be always called *before* other destroy()s.
 */
void timer_destroy(void)
{
	del_timer_sync(&timer);
}
