#include "mod/common/nl/global.h"

int global_update(struct globals *cfg, xlator_type xt, bool force,
		struct global_value *request, size_t request_size)
{
	return -EINVAL;
}

verdict translating_the_packet(struct xlation *state)
{
	return VERDICT_DROP;
}
