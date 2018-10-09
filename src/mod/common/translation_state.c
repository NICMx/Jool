#include "mod/common/translation_state.h"

void xlation_init(struct xlation *state, struct xlator *jool)
{
	memcpy(&state->jool, jool, sizeof(*jool));
	memset(&state->in.debug, 0, sizeof(state->in.debug));
	memset(&state->out.debug, 0, sizeof(state->out.debug));
	state->entries.bib_set = false;
	state->entries.session_set = false;
	state->result.icmp = ICMPERR_NONE;
	state->result.info = 0;
}

verdict untranslatable(struct xlation *state, enum jool_stat stat)
{
	jstat_inc(state->jool.stats, stat);
	return VERDICT_UNTRANSLATABLE;
}

verdict drop(struct xlation *state, enum jool_stat stat)
{
	jstat_inc(state->jool.stats, stat);
	return VERDICT_DROP;
}

verdict drop_icmp(struct xlation *state, enum jool_stat stat,
		enum icmp_errcode icmp, __u32 info)
{
	jstat_inc(state->jool.stats, stat);
	state->result.icmp = icmp;
	state->result.info = info;
	return VERDICT_DROP;
}

verdict stolen(struct xlation *state, enum jool_stat stat)
{
	jstat_inc(state->jool.stats, stat);
	return VERDICT_STOLEN;
}
