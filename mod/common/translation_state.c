#include "nat64/mod/common/translation_state.h"
#include "nat64/mod/stateful/bib/entry.h"

void xlation_init(struct xlation *state)
{
	bib_session_init(&state->entries);
}

void xlation_put(struct xlation *state)
{
	xlator_put(&state->jool);
}
