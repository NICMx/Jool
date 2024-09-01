#include "mod/common/nl/instance.h"

#include "common/types.h"
#include "mod/common/log.h"
#include "mod/common/xlator.h"
#include "mod/common/compat_32_64.h"
#include "mod/common/db/global.h"
#include "mod/common/nl/attribute.h"
#include "mod/common/nl/nl_common.h"

static int parse_instance(struct nlattr *root, struct instance_entry_usr *entry,
		struct jnl_state *state)
{
	struct nlattr *attrs[JNLAIE_COUNT];
	int error;

	error = jnla_parse_nested(attrs, JNLAIE_MAX, root,
			joolnl_instance_entry_policy, "instance", state);
	if (error)
		return error;

	error = jnla_get_u32(attrs[JNLAIE_NS], "namespace", &entry->ns, state);
	if (error)
		return error;
	error = jnla_get_u8(attrs[JNLAIE_XF], "framework", &entry->xf, state);
	if (error)
		return error;
	return jnla_get_str(attrs[JNLAIE_INAME], "instance name",
			INAME_MAX_SIZE, entry->iname, state);
}

static int serialize_instance(struct xlator *entry, void *arg)
{
	struct sk_buff *skb = arg;
	struct nlattr *root;
	int error;

	root = nla_nest_start(skb, JNLAL_ENTRY);
	if (!root)
		return 1;

	error = nla_put_u32(skb, JNLAIE_NS, ((PTR_AS_UINT_TYPE)entry->ns) & 0xFFFFFFFF);
	if (error)
		goto cancel;
	error = nla_put_u8(skb, JNLAIE_XF, xlator_flags2xf(entry->flags));
	if (error)
		goto cancel;
	error = nla_put_string(skb, JNLAIE_INAME, entry->iname);
	if (error)
		goto cancel;

	nla_nest_end(skb, root);
	return 0;

cancel:
	nla_nest_cancel(skb, root);
	return 1;
}

int handle_instance_foreach(struct sk_buff *skb, struct genl_info *info)
{
	struct jnl_state *state;
	struct instance_entry_usr offset, *offset_ptr;
	int error;

	LOG_DEBUG("Sending instance table to userspace.");

	error = __jnl_start(&state, info, XT_ANY, true);
	if (error)
		return jnl_reply(state, error);

	offset_ptr = NULL;
	if (info->attrs[JNLAR_OFFSET]) {
		error = parse_instance(info->attrs[JNLAR_OFFSET], &offset,
				state);
		if (error)
			return jnl_reply(state, error);
		offset_ptr = &offset;
		LOG_DEBUG("Offset: [%x %s %u]", offset.ns, offset.iname,
				offset.xf);
	}

	return jnl_reply_array(state, xlator_foreach(
		jnls_jhdr(state)->xt,
		serialize_instance,
		jnls_skb(state),
		offset_ptr
	));
}

int handle_instance_add(struct sk_buff *skb, struct genl_info *info)
{
	struct jnl_state *state;
	struct joolnlhdr *jhdr;
	struct nlattr *attrs[JNLAIA_COUNT];
	struct jool_globals globals;
	__u8 xf;
	int error;

	LOG_DEBUG("Adding Jool instance.");

	error = __jnl_start(&state, info, XT_ANY, true);
	if (error)
		return jnl_reply(state, error);

	if (!info->attrs[JNLAR_OPERAND]) {
		return jnl_reply(state, jnls_err(state,
				"The request is missing an 'Operand' attribute."));
	}

	error = jnla_parse_nested(attrs, JNLAIA_MAX, info->attrs[JNLAR_OPERAND],
			joolnl_instance_add_policy, "Operand", state);
	if (error)
		return jnl_reply(state, error);

	error = jnla_get_u8(attrs[JNLAIA_XF], "framework", &xf, state);
	if (error)
		return jnl_reply(state, error);

	jhdr = jnls_jhdr(state);
	error = globals_init(&globals, jhdr->xt, state);
	if (error)
		return jnl_reply(state, error);

	error = jnla_get_prefix6_optional(attrs[JNLAIA_POOL6], "pool6",
			&globals.pool6, state);
	if (error)
		return jnl_reply(state, error);

	return jnl_reply(state, xlator_add(
		xf | jhdr->xt,
		jhdr->iname,
		&globals,
		NULL,
		state
	));
}

int handle_instance_hello(struct sk_buff *skb, struct genl_info *info)
{
	struct jnl_state *state;
	struct joolnlhdr *jhdr;
	int error;

	LOG_DEBUG("Handling instance Hello.");

	error = __jnl_start(&state, info, XT_ANY, true);
	if (error)
		return jnl_reply(state, error);

	jhdr = jnls_jhdr(state);
	error = xlator_find_current(jhdr->iname, XF_ANY | jhdr->xt, NULL, state);
	switch (error) {
	case 0:
		error = nla_put_u8(jnls_skb(state), JNLAIS_STATUS, IHS_ALIVE);
		break;
	case -ESRCH:
		error = nla_put_u8(jnls_skb(state), JNLAIS_STATUS, IHS_DEAD);
		break;
	default:
		return jnl_reply(state, jnls_err(state, "Unknown status."));
	}

	return jnl_reply(state, error);
}

int handle_instance_rm(struct sk_buff *skb, struct genl_info *info)
{
	struct jnl_state *state;
	struct joolnlhdr *jhdr;
	int error;

	LOG_DEBUG("Removing Jool instance.");

	error = __jnl_start(&state, info, XT_ANY, true);
	if (error)
		return jnl_reply(state, error);

	jhdr = jnls_jhdr(state);
	return jnl_reply(state, xlator_rm(jhdr->xt, jhdr->iname, state));
}

int handle_instance_flush(struct sk_buff *skb, struct genl_info *info)
{
	struct jnl_state *state;
	int error;

	LOG_DEBUG("Flushing all instances from this namespace.");

	error = __jnl_start(&state, info, XT_ANY, true);
	if (error)
		return jnl_reply(state, error);

	return jnl_reply(state, xlator_flush(jnls_jhdr(state)->xt, state));
}
