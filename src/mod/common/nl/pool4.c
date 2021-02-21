#include "mod/common/nl/pool4.h"

#include "mod/common/log.h"
#include "mod/common/xlator.h"
#include "mod/common/nl/attribute.h"
#include "mod/common/nl/nl_common.h"
#include "mod/common/db/pool4/db.h"
#include "mod/common/db/bib/db.h"

static int serialize_pool4_entry(struct pool4_entry const *entry, void *arg)
{
	return jnla_put_pool4(arg, JNLAL_ENTRY, entry) ? 1 : 0;
}

int handle_pool4_foreach(struct sk_buff *skb, struct genl_info *info)
{
	struct jnl_state *state;
	struct pool4_entry offset, *offset_ptr;
	int error;

	error = jnl_start(&state, info, XT_NAT64, true);
	if (error)
		return jnl_reply(state, error);

	jnls_debug(state, "Sending pool4 to userspace.");

	if (info->attrs[JNLAR_OFFSET]) {
		error = jnla_get_pool4(info->attrs[JNLAR_OFFSET],
				"Iteration offset", &offset, state);
		if (error)
			return jnl_reply(state, error);
		offset_ptr = &offset;
		jnls_debug(state, "Offset: [%pI4/%u %u-%u %u %u %u %u]",
				&offset.range.prefix.addr,
				offset.range.prefix.len,
				offset.range.ports.min,
				offset.range.ports.max,
				offset.mark,
				offset.iterations,
				offset.flags,
				offset.proto);
	} else if (info->attrs[JNLAR_PROTO]) {
		offset.proto = nla_get_u8(info->attrs[JNLAR_PROTO]);
		offset_ptr = NULL;
	} else {
		return jnl_reply(state, jnls_err(state,
				"The request is missing a protocol."));
	}

	return jnl_reply_array(state, pool4db_foreach_sample(
		jnls_xlator(state)->nat64.pool4,
		offset.proto,
		serialize_pool4_entry,
		jnls_skb(state),
		offset_ptr,
		state
	));
}

int handle_pool4_add(struct sk_buff *skb, struct genl_info *info)
{
	struct jnl_state *state;
	struct pool4_entry entry;
	int error;

	error = jnl_start(&state, info, XT_NAT64, true);
	if (error)
		return jnl_reply(state, error);

	jnls_debug(state, "Adding elements to pool4.");

	error = jnla_get_pool4(info->attrs[JNLAR_OPERAND], "Operand", &entry,
			state);
	if (error)
		return jnl_reply(state, error);

	return jnl_reply(state, pool4db_add(
		jnls_xlator(state)->nat64.pool4,
		&entry,
		state
	));
}

/*
int handle_pool4_update(struct sk_buff *skb, struct genl_info *info)
{
	log_debug("Updating pool4 table.");
	return nlcore_respond(info, pool4db_update(pool, &request->update));
}
*/

int handle_pool4_rm(struct sk_buff *skb, struct genl_info *info)
{
	struct jnl_state *state;
	struct xlator *jool;
	struct pool4_entry entry;
	int error;

	error = jnl_start(&state, info, XT_NAT64, true);
	if (error)
		return jnl_reply(state, error);

	jnls_debug(state, "Removing elements from pool4.");

	error = jnla_get_pool4(info->attrs[JNLAR_OPERAND], "Operand", &entry,
			state);
	if (error)
		return jnl_reply(state, error);

	jool = jnls_xlator(state);
	error = pool4db_rm_usr(jool->nat64.pool4, &entry, state);
	if (!(jnls_jhdr(state)->flags & JOOLNLHDR_FLAGS_QUICK))
		bib_rm_range(jool->nat64.bib, entry.proto, &entry.range, state);

	return jnl_reply(state, error);
}

int handle_pool4_flush(struct sk_buff *skb, struct genl_info *info)
{
	struct jnl_state *state;
	struct xlator *jool;
	int error;

	error = jnl_start(&state, info, XT_NAT64, true);
	if (error)
		return jnl_reply(state, error);

	jnls_debug(state, "Flushing pool4.");

	jool = jnls_xlator(state);
	pool4db_flush(jool->nat64.pool4);
	if (!(jnls_jhdr(state)->flags & JOOLNLHDR_FLAGS_QUICK)) {
		/*
		 * This will also clear *previously* orphaned entries, but given
		 * that "not quick" generally means "please clean up," this is
		 * more likely what people wants.
		 */
		bib_flush(jool->nat64.bib, state);
	}

	return jnl_reply(state, 0);
}
