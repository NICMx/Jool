#include "xlation.h"
#include "module-stats.h"

void xlation_init(struct xlation *state, struct xlator *jool)
{
	xlator_get(jool);
	memcpy(&state->jool, jool, sizeof(*jool));

	memset(&state->in.debug, 0, sizeof(state->in.debug));
	memset(&state->out.debug, 0, sizeof(state->out.debug));

	bib_session_init(&state->entries);
}

void xlation_put(struct xlation *state)
{
	xlator_put(&state->jool);
}

/**
 * This is just a convenience wrapper for the paperwork that needs to be done
 * whenever some sort of error forces us to cancel translation, sans debug log
 * message.
 */
int breakdown(struct xlation *state, jstat_type stat, int result)
{
	kfree_skb(state->in.skb);
	state->in.skb = NULL; /* For check_skb_leak(). */
	jstat_inc(state->jool.stats, stat);
	return result;
}

int einval(struct xlation *state, jstat_type stat)
{
	return breakdown(state, stat, -EINVAL);
}

int eunsupported(struct xlation *state, jstat_type stat)
{
	return breakdown(state, stat, -EUNSUPPORTED);
}

int enomem(struct xlation *state, jstat_type stat)
{
	return breakdown(state, stat, -ENOMEM);
}
