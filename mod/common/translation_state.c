#include "nat64/mod/common/translation_state.h"

void xlation_put(struct xlation *state)
{
	joolns_put(&state->jool);
}
