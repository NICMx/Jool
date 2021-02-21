#include "mod/common/nl/bib.h"

#include "mod/common/log.h"
#include "mod/common/xlator.h"
#include "mod/common/nl/attribute.h"
#include "mod/common/nl/nl_common.h"
#include "mod/common/db/pool4/db.h"
#include "mod/common/db/bib/db.h"

static int serialize_bib_entry(struct bib_entry const *entry, void *arg)
{
	return jnla_put_bib(arg, JNLAL_ENTRY, entry) ? 1 : 0;
}

int handle_bib_foreach(struct sk_buff *skb, struct genl_info *info)
{
	struct jnl_state *state;
	struct bib_entry offset, *offset_ptr;
	int error;

	error = jnl_start(&state, info, XT_NAT64, true);
	if (error)
		return jnl_reply(state, error);

	jnls_debug(state, "Sending BIB to userspace.");

	if (info->attrs[JNLAR_OFFSET]) {
		error = jnla_get_bib(info->attrs[JNLAR_OFFSET],
				"Iteration offset", &offset, state);
		if (error)
			return jnl_reply(state, error);
		offset_ptr = &offset;
		jnls_debug(state, "Offset: [%pI6c#%u %pI4#%u %u %u]",
				&offset.addr6.l3, offset.addr6.l4,
				&offset.addr4.l3, offset.addr4.l4,
				offset.is_static, offset.l4_proto);
	} else if (info->attrs[JNLAR_PROTO]) {
		offset.l4_proto = nla_get_u8(info->attrs[JNLAR_PROTO]);
		offset_ptr = NULL;
	} else {
		return jnl_reply(state, jnls_err(state,
				"The request is missing a protocol."));
	}

	return jnl_reply_array(state, bib_foreach(
		jnls_xlator(state)->nat64.bib,
		offset.l4_proto,
		serialize_bib_entry,
		jnls_skb(state),
		offset_ptr ? &offset_ptr->addr4 : NULL
	));
}

int handle_bib_add(struct sk_buff *skb, struct genl_info *info)
{
	struct jnl_state *state;
	struct xlator *jool;
	struct bib_entry new;
	int error;

	error = jnl_start(&state, info, XT_NAT64, true);
	if (error)
		return jnl_reply(state, error);

	jnls_debug(state, "Adding BIB entry.");

	error = jnla_get_bib(info->attrs[JNLAR_OPERAND], "Operand", &new,
			state);
	if (error)
		return jnl_reply(state, error);

	jool = jnls_xlator(state);
	if (!pool4db_contains(jool->nat64.pool4, jool->ns, new.l4_proto, &new.addr4)) {
		return jnl_reply(state, jnls_err(
			state,
			"The transport address '%pI4#%u' does not belong to pool4. Please add it there first.",
			&new.addr4.l3,
			new.addr4.l4
		));
	}

	return jnl_reply(state, bib_add_static(jool->nat64.bib, &new, state));
}

int handle_bib_rm(struct sk_buff *skb, struct genl_info *info)
{
	struct jnl_state *state;
	struct bib *db;
	struct nlattr *attrs[JNLAB_COUNT];
	struct bib_entry entry;
	int error;

	error = jnl_start(&state, info, XT_NAT64, true);
	if (error)
		return jnl_reply(state, error);

	jnls_debug(state, "Removing BIB entry.");

	if (!info->attrs[JNLAR_OPERAND]) {
		return jnl_reply(state, jnls_err(state,
				"The request lacks an operand attribute."));
	}

	error = jnla_parse_nested(attrs, JNLAB_MAX, info->attrs[JNLAR_OPERAND],
			joolnl_bib_entry_policy, "BIB entry", state);
	if (error)
		return jnl_reply(state, error);

	if (!attrs[JNLAB_SRC6] && !attrs[JNLAB_SRC4]) {
		return jnl_reply(state, jnls_err(
			state,
			"The request lacks both IPv6 address and IPv4 address."
		));
	}

	if (attrs[JNLAB_SRC6]) {
		error = jnla_get_taddr6(attrs[JNLAB_SRC6],
				"IPv6 transport address", &entry.addr6, state);
		if (error)
			return jnl_reply(state, -EINVAL);
	}
	if (attrs[JNLAB_SRC4]) {
		error = jnla_get_taddr4(attrs[JNLAB_SRC4],
				"IPv4 transport address", &entry.addr4, state);
		if (error)
			return jnl_reply(state, -EINVAL);
	}

	if (attrs[JNLAB_PROTO])
		entry.l4_proto = nla_get_u8(attrs[JNLAB_PROTO]);
	if (attrs[JNLAB_STATIC])
		entry.is_static = nla_get_u8(attrs[JNLAB_STATIC]);

	db = jnls_xlator(state)->nat64.bib;
	if (!attrs[JNLAB_SRC4])
		error = bib_find6(db, entry.l4_proto, &entry.addr6, &entry);
	else if (!attrs[JNLAB_SRC6])
		error = bib_find4(db, entry.l4_proto, &entry.addr4, &entry);

	switch (error) {
	case 0:
		error = bib_rm(db, &entry, state);
		break;
	case -ESRCH:
		jnls_err(state, "The entry wasn't in the database.");
		break;
	default:
		jnls_err(state, "Unknown error: %d", error);
	}

	return jnl_reply(state, error);
}
