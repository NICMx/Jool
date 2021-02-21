#include "mod/common/nl/denylist4.h"

#include "common/types.h"
#include "mod/common/log.h"
#include "mod/common/xlator.h"
#include "mod/common/nl/attribute.h"
#include "mod/common/nl/nl_common.h"
#include "mod/common/db/denylist4.h"

static int serialize_bl4_entry(struct ipv4_prefix *prefix, void *arg)
{
	return jnla_put_prefix4(arg, JNLAL_ENTRY, prefix) ? 1 : 0;
}

int handle_denylist4_foreach(struct sk_buff *skb, struct genl_info *info)
{
	struct jnl_state *state;
	struct ipv4_prefix offset, *offset_ptr;
	int error;

	error = jnl_start(&state, info, XT_SIIT, true);
	if (error)
		return jnl_reply(state, error);

	jnls_debug(state, "Sending the denylist4 to userspace.");

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

	return jnl_reply_array(state, denylist4_foreach(
		jnls_xlator(state)->siit.denylist4,
		serialize_bl4_entry,
		jnls_skb(state),
		offset_ptr
	));
}

int handle_denylist4_add(struct sk_buff *skb, struct genl_info *info)
{
	struct jnl_state *state;
	struct ipv4_prefix operand;
	int error;

	error = jnl_start(&state, info, XT_SIIT, true);
	if (error)
		return jnl_reply(state, error);

	jnls_debug(state, "Adding Denylist4 entry.");

	error = jnla_get_prefix4(info->attrs[JNLAR_OPERAND], "Operand",
			&operand, state);
	if (error)
		return jnl_reply(state, error);

	return jnl_reply(state, denylist4_add(
		jnls_xlator(state)->siit.denylist4,
		&operand,
		jnls_jhdr(state)->flags & JOOLNLHDR_FLAGS_FORCE,
		state
	));
}

int handle_denylist4_rm(struct sk_buff *skb, struct genl_info *info)
{
	struct jnl_state *state;
	struct ipv4_prefix operand;
	int error;

	error = jnl_start(&state, info, XT_SIIT, true);
	if (error)
		return jnl_reply(state, error);

	jnls_debug(state, "Removing Denylist4 entry.");

	error = jnla_get_prefix4(info->attrs[JNLAR_OPERAND], "Operand",
			&operand, state);
	if (error)
		return jnl_reply(state, error);

	return jnl_reply(state, denylist4_rm(
		jnls_xlator(state)->siit.denylist4,
		&operand,
		state
	));
}

int handle_denylist4_flush(struct sk_buff *skb, struct genl_info *info)
{
	struct jnl_state *state;
	int error;

	error = jnl_start(&state, info, XT_SIIT, true);
	if (error)
		return jnl_reply(state, error);

	jnls_debug(state, "Flushing the denylist4...");

	return jnl_reply(state, denylist4_flush(
		jnls_xlator(state)->siit.denylist4
	));
}
