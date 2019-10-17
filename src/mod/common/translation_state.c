#include "mod/common/translation_state.h"

#include "mod/common/wkmalloc.h"

static struct kmem_cache *xlation_cache;

int xlation_setup(void)
{
	xlation_cache = kmem_cache_create("jool_xlations",
			sizeof(struct xlation), 0, 0, NULL);
	return xlation_cache? 0 : -ENOMEM;
}

void xlation_teardown(void)
{
	kmem_cache_destroy(xlation_cache);
}

struct xlation *xlation_create(struct xlator *jool)
{
	struct xlation *state;

	state = wkmem_cache_alloc("xlation", xlation_cache, GFP_ATOMIC);
	if (!state)
		return NULL;

	xlation_init(state, jool);
	return state;
}

void xlation_init(struct xlation *state, struct xlator *jool)
{
	if (jool)
		memcpy(&state->jool, jool, sizeof(*jool));
	memset(&state->in.debug, 0, sizeof(state->in.debug));
	memset(&state->out.debug, 0, sizeof(state->out.debug));
	state->entries.bib_set = false;
	state->entries.session_set = false;
	state->result.icmp = ICMPERR_NONE;
	state->result.info = 0;
}

void xlation_destroy(struct xlation *state)
{
	wkmem_cache_free("xlation", xlation_cache, state);
}

verdict untranslatable(struct xlation *state, enum jool_stat_id stat)
{
	jstat_inc(state->jool.stats, stat);
	return VERDICT_UNTRANSLATABLE;
}

verdict untranslatable_icmp(struct xlation *state, enum jool_stat_id stat,
		enum icmp_errcode icmp, __u32 info)
{
	jstat_inc(state->jool.stats, stat);
	state->result.icmp = icmp;
	state->result.info = info;
	return VERDICT_UNTRANSLATABLE;
}

verdict drop(struct xlation *state, enum jool_stat_id stat)
{
	jstat_inc(state->jool.stats, stat);
	return VERDICT_DROP;
}

verdict drop_icmp(struct xlation *state, enum jool_stat_id stat,
		enum icmp_errcode icmp, __u32 info)
{
	jstat_inc(state->jool.stats, stat);
	state->result.icmp = icmp;
	state->result.info = info;
	return VERDICT_DROP;
}

verdict stolen(struct xlation *state, enum jool_stat_id stat)
{
	jstat_inc(state->jool.stats, stat);
	return VERDICT_STOLEN;
}
