#include "nat64/mod/common/translation_state.h"
#include "nat64/mod/stateful/bib/entry.h"

void xlation_init(struct xlation *state)
{
	state->entries.bib_set = false;
	state->entries.session_set = false;
}

void xlation_put(struct xlation *state)
{
	xlator_put(&state->jool);
}
