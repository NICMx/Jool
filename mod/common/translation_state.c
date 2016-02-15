#include "nat64/mod/common/translation_state.h"
#include "nat64/mod/stateful/session/entry.h"

void xlation_put(struct xlation *state)
{
	xlator_put(&state->jool);
	if (state->session)
		session_put(state->session, false);
}
