#include "mod/common/nl/fmr.h"

#include "mod/common/log.h"
#include "mod/common/xlator.h"
#include "mod/common/nl/attribute.h"
#include "mod/common/nl/nl_common.h"
#include "mod/common/db/fmr.h"

static int serialize_fmr_entry(struct mapping_rule const *entry, void *arg)
{
	struct config_mapping_rule rule;

	if (entry) {
		rule.set = true;
		rule.rule = *entry;
	} else {
		rule.set = false;
		memset(&rule.rule, 0, sizeof(rule.rule));
	}

	return jnla_put_mapping_rule(arg, JNLAL_ENTRY, &rule) ? 1 : 0;
}

int handle_fmrt_foreach(struct sk_buff *skb, struct genl_info *info)
{
	struct jnl_state *state;
	struct ipv4_prefix offset, *offset_ptr;
	int error;

	error = jnl_start(&state, info, XT_MAPT, true);
	if (error)
		return jnl_reply(state, error);

	jnls_debug(state, "Sending FMR table to userspace.");

	offset_ptr = NULL;
	if (info->attrs[JNLAR_OFFSET]) {
		error = jnla_get_prefix4(info->attrs[JNLAR_OFFSET],
				"Iteration offset", &offset, state);
		if (error)
			return jnl_reply(state, error);
		offset_ptr = &offset;
		jnls_debug(state, "Offset: [%pI4/%u]", &offset.addr,
				offset.len);
	}

	return jnl_reply_array(state, fmrt_foreach(
		jnls_xlator(state)->mapt.fmrt,
		serialize_fmr_entry,
		jnls_skb(state),
		offset_ptr
	));
}

int handle_fmrt_add(struct sk_buff *skb, struct genl_info *info)
{
	struct jnl_state *state;
	struct config_mapping_rule addend;
	int error;

	error = jnl_start(&state, info, XT_MAPT, true);
	if (error)
		return jnl_reply(state, error);

	jnls_debug(state, "Adding FMR entry.");

	error = jnla_get_mapping_rule(info->attrs[JNLAR_OPERAND], "Operand",
			&addend, state);
	if (error)
		return jnl_reply(state, error);
	if (!addend.set) {
		return jnl_reply(state, jnls_err(state,
				"Request contains an empty FMR."));
	}

	return jnl_reply(state, fmrt_add(
		jnls_xlator(state)->mapt.fmrt,
		&addend.rule,
		state
	));
}

int handle_fmrt_rm(struct sk_buff *skb, struct genl_info *info)
{
	struct jnl_state *state;
	struct config_mapping_rule subtrahend;
	int error;

	error = jnl_start(&state, info, XT_MAPT, true);
	if (error)
		return jnl_reply(state, error);

	jnls_debug(state, "Removing FMR entry.");

	error = jnla_get_mapping_rule(info->attrs[JNLAR_OPERAND], "Operand",
			&subtrahend, state);
	if (error)
		return jnl_reply(state, error);
	if (!subtrahend.set) {
		return jnl_reply(state, jnls_err(state,
				"Request contains an empty FMR."));
	}

	return jnl_reply(state, fmrt_rm(
		jnls_xlator(state)->mapt.fmrt,
		&subtrahend.rule,
		state
	));
}

int handle_fmrt_flush(struct sk_buff *skb, struct genl_info *info)
{
	struct jnl_state *state;
	int error;

	error = jnl_start(&state, info, XT_MAPT, true);
	if (error)
		return jnl_reply(state, error);

	jnls_debug(state, "Flushing FMR table.");

	fmrt_flush(jnls_xlator(state)->mapt.fmrt);
	return jnl_reply(state, 0);
}
