#include "nat64/mod/common/translation_state.h"
#include "nat64/mod/stateful/bib/entry.h"

void xlation_init(struct xlation *state, struct xlator *jool)
{
	memcpy(&state->jool, jool, sizeof(*jool));
	memset(&state->in.debug, 0, sizeof(state->in.debug));
	memset(&state->out.debug, 0, sizeof(state->out.debug));
	bib_session_init(&state->entries);
}

void xlation_clean(struct xlation *state)
{
	/* Nothing needed. */
}
