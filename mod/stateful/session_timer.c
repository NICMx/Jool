#include "nat64/mod/stateful/session_timer.h"

#include "nat64/mod/common/xlator.h"
#include "nat64/mod/stateful/bib/db.h"

#define INITIAL_TIMER_PERIOD msecs_to_jiffies(2000)
#define MAX_SESSIONS_RM 1024

static struct timer_list timer;

struct clean_params {
	bool pend_rm;
	u64 max_session_rm;
};

static struct clean_params sess_params;

static int clean_state(struct xlator *jool, void *args)
{
	struct clean_params *params = args;
	bib_clean(jool->nat64.bib, jool->ns, &params->max_session_rm,
			&params->pend_rm);
	return 0;
}

static void update_params(unsigned long arg)
{
	if (sess_params.pend_rm) {
		timer.data = msecs_to_jiffies(jiffies_to_msecs(arg) / 2);
		sess_params.max_session_rm <<= 1;
		log_debug("+ Session timer NEW msecs and max_sess_rm: %u - %llu",
				(jiffies_to_msecs(arg) / 2), sess_params.max_session_rm);
	} else {
		timer.data = INITIAL_TIMER_PERIOD;
		sess_params.max_session_rm = MAX_SESSIONS_RM;
		log_debug("+ Session timer RESET msecs and max_sess_rm: %u - %llu",
				jiffies_to_msecs(INITIAL_TIMER_PERIOD),
				sess_params.max_session_rm);
	}
	sess_params.pend_rm = 0;
}

static void timer_function(unsigned long arg)
{
	xlator_foreach(clean_state, &sess_params);
	update_params(arg);
	mod_timer(&timer, jiffies + timer.data);
}

/**
 * This function should be always called *after* other init()s.
 */
int session_timer_init(void)
{
	init_timer(&timer);
	timer.function = timer_function;
	timer.expires = 0;
	timer.data = 0;
	sess_params.pend_rm = 0;
	sess_params.max_session_rm = MAX_SESSIONS_RM;
	mod_timer(&timer, jiffies + INITIAL_TIMER_PERIOD);
	return 0;
}

/**
 * This function should be always called *before* other destroy()s.
 */
void session_timer_destroy(void)
{
	del_timer_sync(&timer);
}
