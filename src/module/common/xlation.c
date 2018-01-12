#include "xlation.h"
#include "module-stats.h"

void xlation_init(struct xlation *state, struct xlator *jool)
{
	xlator_get(jool);
	/* TODO doesn't this need locking? */
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
	if (state) {
		kfree_skb(state->in.skb);
		state->in.skb = NULL; /* For check_skb_leak(). */
		jstat_inc(state->jool.stats, stat);
	}

	return result;
}

int eexist(struct xlation *state, jstat_type stat)
{
	return breakdown(state, stat, -EEXIST);
}

int einval(struct xlation *state, jstat_type stat)
{
	return breakdown(state, stat, -EINVAL);
}

/**
 * Note: ENOMEMs probably never need log_debug()s because kmalloc() already left
 * a massive stack trace in the logs anyway.
 */
int enomem(struct xlation *state)
{
	return breakdown(state, JOOL_MIB_MALLOC_FAIL, -ENOMEM);
}

int enospc(struct xlation *state, jstat_type stat)
{
	return breakdown(state, stat, -ENOSPC);
}

int eperm(struct xlation *state, jstat_type stat)
{
	return breakdown(state, stat, -EPERM);
}

int esrch(struct xlation *state, jstat_type stat)
{
	return breakdown(state, stat, -ESRCH);
}

int eunknown4(struct xlation *state, int error)
{
	return breakdown(state, JOOL_MIB_UNKNOWN4, error);
}

int eunknown6(struct xlation *state, int error)
{
	return breakdown(state, JOOL_MIB_UNKNOWN6, error);
}

int eunsupported(struct xlation *state, jstat_type stat)
{
	return breakdown(state, stat, -EUNSUPPORTED);
}
