#include "xlation.h"

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
