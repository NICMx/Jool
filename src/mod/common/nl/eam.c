#include "mod/common/nl/eam.h"

#include "common/types.h"
#include "mod/common/log.h"
#include "mod/common/xlator.h"
#include "mod/common/nl/attribute.h"
#include "mod/common/nl/nl_common.h"
#include "mod/common/db/eam.h"

static int serialize_eam_entry(struct eamt_entry const *entry, void *arg)
{
	return jnla_put_eam(arg, JNLAL_ENTRY, entry) ? 1 : 0;
}

int handle_eamt_foreach(struct sk_buff *skb, struct genl_info *info)
{
	struct jnl_state *state;
	struct ipv4_prefix offset, *offset_ptr;
	int error;

	error = jnl_start(&state, info, XT_SIIT, true);
	if (error)
		return jnl_reply(state, error);

	jnls_debug(state, "Sending EAMT to userspace.");

	offset_ptr = NULL;
	if (info->attrs[JNLAR_OFFSET]) {
		error = jnla_get_prefix4(info->attrs[JNLAR_OFFSET],
				"Iteration offset", &offset, state);
		if (error)
			return jnl_reply(state, error);
		offset_ptr = &offset;
		jnls_debug(state, "Offset: [%pI4/%u]", &offset.addr, offset.len);
	}

	return jnl_reply_array(state, eamt_foreach(
		jnls_xlator(state)->siit.eamt,
		serialize_eam_entry,
		jnls_skb(state),
		offset_ptr
	));
}

int handle_eamt_add(struct sk_buff *skb, struct genl_info *info)
{
	struct jnl_state *state;
	struct eamt_entry addend;
	int error;

	error = jnl_start(&state, info, XT_SIIT, true);
	if (error)
		return jnl_reply(state, error);

	jnls_debug(state, "Adding EAM entry.");

	error = jnla_get_eam(info->attrs[JNLAR_OPERAND], "Operand", &addend,
			state);
	if (error)
		return jnl_reply(state, error);

	return jnl_reply(state, eamt_add(
		jnls_xlator(state)->siit.eamt,
		&addend,
		true,
		state
	));
}

int handle_eamt_rm(struct sk_buff *skb, struct genl_info *info)
{
	struct jnl_state *state;
	struct nlattr *attrs[JNLAE_COUNT];
	struct ipv6_prefix prefix6, *prefix6_ptr;
	struct ipv4_prefix prefix4, *prefix4_ptr;
	int error;

	error = jnl_start(&state, info, XT_SIIT, true);
	if (error)
		return jnl_reply(state, error);

	jnls_debug(state, "Removing EAM entry.");

	if (!info->attrs[JNLAR_OPERAND]) {
		return jnl_reply(state, jnls_err(state,
				"The request is missing the 'Operand' attribute."));
	}
	error = jnla_parse_nested(attrs, JNLAE_MAX, info->attrs[JNLAR_OPERAND],
			joolnl_eam_policy, "EAM", state);
	if (error)
		return jnl_reply(state, error);

	if (!attrs[JNLAE_PREFIX6] && !attrs[JNLAE_PREFIX4]) {
		jnls_err(state, "The request contains no prefixes.");
		return jnl_reply(state, -ENOENT);
	}
	prefix6_ptr = NULL;
	if (attrs[JNLAE_PREFIX6]) {
		error = jnla_get_prefix6(attrs[JNLAE_PREFIX6], "IPv6 prefix",
				&prefix6, state);
		if (error)
			return jnl_reply(state, error);
		prefix6_ptr = &prefix6;
	}
	prefix4_ptr = NULL;
	if (attrs[JNLAE_PREFIX4]) {
		error = jnla_get_prefix4(attrs[JNLAE_PREFIX4], "IPv4 prefix",
				&prefix4, state);
		if (error)
			return jnl_reply(state, error);
		prefix4_ptr = &prefix4;
	}

	return jnl_reply(state, eamt_rm(
		jnls_xlator(state)->siit.eamt,
		prefix6_ptr,
		prefix4_ptr,
		state
	));
}

int handle_eamt_flush(struct sk_buff *skb, struct genl_info *info)
{
	struct jnl_state *state;
	int error;

	error = jnl_start(&state, info, XT_SIIT, true);
	if (error)
		return jnl_reply(state, error);

	jnls_debug(state, "Flushing the EAMT.");

	eamt_flush(jnls_xlator(state)->siit.eamt);
	return jnl_reply(state, 0);
}
