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
	memset(state, 0, sizeof(*state));
	if (jool)
		memcpy(&state->jool, jool, sizeof(*jool));
}

void xlation_destroy(struct xlation *state)
{
	if (state->dst)
		dst_release(state->dst);
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

void xlation_check_382(struct xlation *state, unsigned int len_flag,
		unsigned int version_flag)
{
	struct sk_buff *skb = state->out.skb;
	__u8 version;

	if (skb->len > 0xFFFF)
		state->debug_flags |= len_flag;
	else
		state->debug_flags &= ~len_flag;

	version = (skb->data[0] >> 4);
	if ((version != 4) && (version != 6))
		state->debug_flags |= version_flag;
	else
		state->debug_flags &= ~version_flag;
}

static void check_len(struct xlation *state, struct sk_buff *skb,
		char const *src_file, unsigned int src_line,
		char const *src_function)
{
	if (state->debug_flags & DBGFLAG_BAD_LEN_REPORTED)
		return;

	if (skb->len > 0xFFFFu) {
		pr_err("%s:%d (%s()): skb length is %u.\n", src_file, src_line,
				src_function, skb->len);
		state->debug_flags |= DBGFLAG_BAD_LEN_REPORTED;
	}
}

static void check_data_len(struct xlation *state, struct sk_buff *skb,
		char const *src_file, unsigned int src_line,
		char const *src_function)
{
	if (state->debug_flags & DBGFLAG_BAD_DATALEN_REPORTED)
		return;

	if (skb->data_len > 0xFFFFu) {
		pr_err("%s:%d (%s()): skb data_len is %u.\n", src_file,
				src_line, src_function, skb->data_len);
		state->debug_flags |= DBGFLAG_BAD_DATALEN_REPORTED;
	}
}

void check_skb_len(struct xlation *state, struct sk_buff *skb,
		char const *src_file, unsigned int src_line,
		char const *src_function)
{
	if (skb == NULL)
		return;

	check_len(state, skb, src_file, src_line, src_function);
	check_data_len(state, skb, src_file, src_line, src_function);
}
