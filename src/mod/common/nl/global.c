#include "mod/common/nl/global.h"

#include "common/constants.h"
#include "mod/common/log.h"
#include "mod/common/nl/nl_common.h"
#include "mod/common/nl/attribute.h"
#include "mod/common/db/eam.h"
#include "mod/common/db/global.h"

static int serialize_global(struct joolnl_global_meta const *meta, void *global,
		void *_state)
{
	struct jnl_state *state = _state;
	return !!joolnl_global_raw2nl(meta, global, jnls_skb(state), state);
}

int handle_global_foreach(struct sk_buff *skb, struct genl_info *info)
{
	struct jnl_state *state;
	struct xlator *jool;
	enum joolnl_attr_global offset;
	int error;

	error = jnl_start(&state, info, XT_ANY, true);
	if (error)
		return jnl_reply(state, error);

	jnls_debug(state, "Returning 'Global' options.");

	offset = 0;
	if (info->attrs[JNLAR_OFFSET_U8]) {
		offset = nla_get_u8(info->attrs[JNLAR_OFFSET_U8]);
		jnls_debug(state, "Offset: [%u]", offset);
	}

	jool = jnls_xlator(state);
	return jnl_reply_array(state, globals_foreach(
		&jool->globals,
		xlator_get_type(jool),
		serialize_global,
		state,
		offset
	));
}

int handle_global_update(struct sk_buff *skb, struct genl_info *info)
{
	struct jnl_state *state;
	struct xlator *jool;
	struct joolnlhdr *jhdr;
	int error;

	/*
	 * This is implemented as an atomic configuration run with only a single
	 * globals modification.
	 *
	 * Why?
	 *
	 * First, I can't just modify the value directly because ongoing
	 * translations could be using it. Making those values atomic is
	 * awkward because not all of them are basic data types.
	 *
	 * Protecting the values by a spinlock is feasible but dirty and not
	 * very performant. The translating code wants to query the globals
	 * often and I don't think that locking all the time is very healthy.
	 *
	 * [Also, the global values should ideally]
	 * remain constant through a translation, because bad things might
	 * happen if a value is queried at the beginning of the pipeline, some
	 * stuff is done based on it, and a different value pops when queried
	 * later. We could ask the code to query every value just once, but
	 * really that's not intuitive and won't sit well for new coders.
	 *
	 * So really, we don't want to edit values. We want to replace the
	 * entire structure via RCU so ongoing translations will keep their
	 * current configurations and future ones will have the new config from
	 * the beginning.
	 *
	 * Which leads to the second point: I don't want to protect
	 * xlator.globals with RCU either because I don't want to lock RCU every
	 * single time I want to query a global. Now I know that RCU-locking is
	 * faster than spin-locking, but hear me out:
	 *
	 * We could just change the entire xlator. Not only because we already
	 * need to support that for atomic configuration, but also because it
	 * literally does not impose any additional synchronization rules
	 * whatsoever for the translating code. The only overhead over replacing
	 * only xlator.globals is that we need to allocate an extra xlator
	 * during this operation. Which is not a recurrent operation at all.
	 *
	 * So let's STFU and do that.
	 */

	error = jnl_start(&state, info, XT_ANY, true);
	if (error)
		return jnl_reply(state, error);

	jnls_debug(state, "Updating 'Global' value.");

	if (!info->attrs[JNLAR_GLOBALS]) {
		return jnl_reply(state, jnls_err(state,
				"Request is missing a globals container."));
	}

	jool = jnls_xlator(state);
	jhdr = jnls_jhdr(state);
	error = global_update(&jool->globals, jhdr->xt,
			jhdr->flags & JOOLNLHDR_FLAGS_FORCE,
			info->attrs[JNLAR_GLOBALS], state);
	if (error)
		return jnl_reply(state, error);

	if (jool->globals.nat64.joold.flush_asap)
		log_warn_once("ss-flush-asap is deprecated.");

	/*
	 * Notice that this @jool is also a clone and we're the only thread
	 * with access to it.
	 */
	return jnl_reply(state, xlator_replace(jool, state));
}

int global_update(struct jool_globals *cfg, xlator_type xt, bool force,
		struct nlattr *root, struct jnl_state *state)
{
	const struct nla_policy *policy;
	struct nlattr *attrs[JNLAG_COUNT];
	struct joolnl_global_meta const *meta;
	enum joolnl_attr_global id;
	int error;

	switch (xt) {
	case XT_SIIT:
		policy = siit_globals_policy;
		break;
	case XT_NAT64:
		policy = nat64_globals_policy;
		break;
	case XT_MAPT:
		policy = mapt_globals_policy;
		break;
	default:
		return jnls_err(state, XT_VALIDATE_ERRMSG);
	}

	error = jnla_parse_nested(attrs, JNLAG_MAX, root, policy,
			"Globals Container", state);
	if (error)
		return error;

	joolnl_global_foreach_meta(meta) {
		if (!(joolnl_global_meta_xt(meta) & xt))
			continue;
		id = joolnl_global_meta_id(meta);
		if (!attrs[id])
			continue;

		error = joolnl_global_nl2raw(meta, attrs[id],
				joolnl_global_get(meta, cfg),
				force, state);
		if (error)
			return error;
	}

	return 0;
}
