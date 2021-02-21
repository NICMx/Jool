#include "mod/common/nl/session.h"

#include "mod/common/log.h"
#include "mod/common/xlator.h"
#include "mod/common/nl/attribute.h"
#include "mod/common/nl/nl_common.h"
#include "mod/common/db/bib/db.h"

static int parse_offset(struct nlattr *root,
		struct session_foreach_offset *entry,
		struct jnl_state *state)
{
	struct nlattr *attrs[JNLASE_COUNT];
	int error;

	error = jnla_parse_nested(attrs, JNLASE_MAX, root,
			joolnl_session_entry_policy, "session entry", state);
	if (error)
		return error;

	memset(entry, 0, sizeof(*entry));

	if (attrs[JNLASE_SRC4]) {
		error = jnla_get_taddr4(attrs[JNLASE_SRC4],
				"IPv4 source address", &entry->offset.src,
				state);
		if (error)
			return error;
	}
	if (attrs[JNLASE_DST4]) {
		error = jnla_get_taddr4(attrs[JNLASE_DST4],
				"IPv4 destination address", &entry->offset.dst,
				state);
		if (error)
			return error;
	}

	entry->include_offset = false;
	return 0;
}

static int serialize_session_entry(struct session_entry const *entry, void *arg)
{
	return jnla_put_session(arg, JNLAL_ENTRY, entry) ? 1 : 0;
}

int handle_session_foreach(struct sk_buff *skb, struct genl_info *info)
{
	struct jnl_state *state;
	struct session_foreach_offset offset, *offset_ptr;
	l4_protocol proto;
	int error;

	error = jnl_start(&state, info, XT_NAT64, true);
	if (error)
		return jnl_reply(state, error);

	jnls_debug(state, "Sending session to userspace.");

	if (!info->attrs[JNLAR_PROTO]) {
		return jnl_reply(state, jnls_err(state,
				"The request is missing a transport protocol."));
	}
	proto = nla_get_u8(info->attrs[JNLAR_PROTO]);

	if (!info->attrs[JNLAR_OFFSET]) {
		offset_ptr = NULL;
	} else {
		error = parse_offset(info->attrs[JNLAR_OFFSET], &offset, state);
		if (error)
			return jnl_reply(state, -EINVAL);
		offset_ptr = &offset;
		jnls_debug(state, "Offset: [%pI4/%u %pI4/%u]",
				&offset.offset.src.l3, offset.offset.src.l4,
				&offset.offset.dst.l3, offset.offset.dst.l4);
	}

	return jnl_reply_array(state, bib_foreach_session(
		jnls_xlator(state),
		proto,
		serialize_session_entry,
		jnls_skb(state),
		offset_ptr
	));
}
