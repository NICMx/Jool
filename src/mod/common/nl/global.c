#include "mod/common/nl/global.h"

#include "mod/common/log.h"
#include "mod/common/nl/nl_common.h"
#include "mod/common/nl/nl_core.h"
#include "mod/common/nl/attribute.h"
#include "mod/common/db/eam.h"

static int put_optional_prefix6(struct sk_buff *skb, int attrtype,
		struct config_prefix6 *prefix6)
{
	return prefix6->set
		? jnla_put_prefix6(skb, attrtype, &prefix6->prefix)
		: nla_put(skb, attrtype, 0, NULL);
}

static int put_optional_prefix4(struct sk_buff *skb, int attrtype,
		struct config_prefix4 *prefix4)
{
	return prefix4->set
		? jnla_put_prefix4(skb, attrtype, &prefix4->prefix)
		: nla_put(skb, attrtype, 0, NULL);
}

static int put_common_values(struct sk_buff *skb, struct xlator *jool)
{
	struct globals *values;
	bool pools_empty;

	values = &jool->globals;
	pools_empty = !values->pool6.set;
	if (xlator_is_siit(jool))
		pools_empty &= eamt_is_empty(jool->siit.eamt);

	return nla_put_u8(skb, GA_STATUS, values->enabled && !pools_empty)
		|| nla_put_u8(skb, GA_ENABLED, values->enabled)
		|| nla_put_u8(skb, GA_TRACE, values->trace)
		|| put_optional_prefix6(skb, GA_POOL6, &values->pool6)
		|| nla_put_u8(skb, GA_RESET_TC, values->reset_traffic_class)
		|| nla_put_u8(skb, GA_RESET_TOS, values->reset_tos)
		|| nla_put_u8(skb, GA_TOS, values->new_tos)
		|| jnla_put_plateaus(skb, GA_PLATEAUS, &values->plateaus);
}

static int put_siit_values(struct sk_buff *skb, struct globals *values)
{
	return nla_put_u8(skb, GA_COMPUTE_CSUM_ZERO, values->siit.compute_udp_csum_zero)
		|| nla_put_u8(skb, GA_HAIRPIN_MODE, values->siit.eam_hairpin_mode)
		|| nla_put_u8(skb, GA_RANDOMIZE_ERROR_ADDR, values->siit.randomize_error_addresses)
		|| put_optional_prefix6(skb, GA_POOL6791V6, &values->siit.rfc6791_prefix6)
		|| put_optional_prefix4(skb, GA_POOL6791V4, &values->siit.rfc6791_prefix4);
}

static int put_nat64_values(struct sk_buff *skb, struct globals *values)
{
	return nla_put_u8(skb, GA_DROP_ICMP6_INFO, values->nat64.drop_icmp6_info)
		|| nla_put_u8(skb, GA_SRC_ICMP6_BETTER, values->nat64.src_icmp6errs_better)
		|| nla_put_u8(skb, GA_F_ARGS, values->nat64.f_args)
		|| nla_put_u8(skb, GA_HANDLE_RST, values->nat64.handle_rst_during_fin_rcv)
		|| nla_put_u32(skb, GA_TTL_TCP_EST, values->nat64.bib.ttl.tcp_est)
		|| nla_put_u32(skb, GA_TTL_TCP_TRANS, values->nat64.bib.ttl.tcp_trans)
		|| nla_put_u32(skb, GA_TTL_UDP, values->nat64.bib.ttl.udp)
		|| nla_put_u32(skb, GA_TTL_ICMP, values->nat64.bib.ttl.icmp)
		|| nla_put_u8(skb, GA_BIB_LOGGING, values->nat64.bib.bib_logging)
		|| nla_put_u8(skb, GA_SESSION_LOGGING, values->nat64.bib.session_logging)
		|| nla_put_u8(skb, GA_DROP_BY_ADDR, values->nat64.bib.drop_by_addr)
		|| nla_put_u8(skb, GA_DROP_EXTERNAL_TCP, values->nat64.bib.drop_external_tcp)
		|| nla_put_u32(skb, GA_MAX_STORED_PKTS, values->nat64.bib.max_stored_pkts)
		|| nla_put_u8(skb, GA_JOOLD_ENABLED, values->nat64.joold.enabled)
		|| nla_put_u8(skb, GA_JOOLD_FLUSH_ASAP, values->nat64.joold.flush_asap)
		|| nla_put_u32(skb, GA_JOOLD_FLUSH_DEADLINE, values->nat64.joold.flush_deadline)
		|| nla_put_u32(skb, GA_JOOLD_CAPACITY, values->nat64.joold.capacity)
		|| nla_put_u32(skb, GA_JOOLD_MAX_PAYLOAD, values->nat64.joold.max_payload);
}

int handle_global_foreach(struct sk_buff *skb, struct genl_info *info)
{
	struct xlator jool;
	struct jool_response response;
	int error;

	log_debug("Returning 'Global' options.");

	error = request_handle_start(info, XT_ANY, &jool);
	if (error)
		goto end;
	error = jresponse_init(&response, info);
	if (error)
		goto revert_start;

	error = put_common_values(response.skb, &jool);
	if (error)
		goto put_failure;
	switch (xlator_flags2xt(jool.flags)) {
	case XT_SIIT:
		error = put_siit_values(response.skb, &jool.globals);
		if (error)
			goto put_failure;
		break;
	case XT_NAT64:
		error = put_nat64_values(response.skb, &jool.globals);
		if (error)
			goto put_failure;
		break;
	default:
		log_err("Unknown translator type: %u", xlator_flags2xt(jool.flags));
		error = -EINVAL;
		goto revert_response;
	}

	request_handle_end(&jool);
	return jresponse_send(&response);

put_failure:
	report_put_failure();
revert_response:
	jresponse_cleanup(&response);
revert_start:
	request_handle_end(&jool);
end:
	return jresponse_send_simple(info, error);
}

static const struct nla_policy globals_policy[GA_COUNT] = {
	[GA_ENABLED] = { .type = NLA_U8 },
	[GA_TRACE] = { .type = NLA_U8 },
	[GA_POOL6] = { .type = NLA_UNSPEC },
	[GA_RESET_TC] = { .type = NLA_U8 },
	[GA_RESET_TOS] = { .type = NLA_U8 },
	[GA_TOS] = { .type = NLA_U8 },
	[GA_PLATEAUS] = { .type = NLA_NESTED },
	[GA_COMPUTE_CSUM_ZERO] = { .type = NLA_U8 },
	[GA_HAIRPIN_MODE] = { .type = NLA_U8 },
	[GA_RANDOMIZE_ERROR_ADDR] = { .type = NLA_U8 },
	[GA_POOL6791V6] = { .type = NLA_UNSPEC },
	[GA_POOL6791V4] = { .type = NLA_UNSPEC },
	[GA_DROP_ICMP6_INFO] = { .type = NLA_U8 },
	[GA_SRC_ICMP6_BETTER] = { .type = NLA_U8 },
	[GA_F_ARGS] = { .type = NLA_U8 },
	[GA_HANDLE_RST] = { .type = NLA_U8 },
	[GA_TTL_TCP_EST] = { .type = NLA_U32 },
	[GA_TTL_TCP_TRANS] = { .type = NLA_U32 },
	[GA_TTL_UDP] = { .type = NLA_U32 },
	[GA_TTL_ICMP] = { .type = NLA_U32 },
	[GA_BIB_LOGGING] = { .type = NLA_U8 },
	[GA_SESSION_LOGGING] = { .type = NLA_U8 },
	[GA_DROP_BY_ADDR] = { .type = NLA_U8 },
	[GA_DROP_EXTERNAL_TCP] = { .type = NLA_U8 },
	[GA_MAX_STORED_PKTS] = { .type = NLA_U32 },
	[GA_JOOLD_ENABLED] = { .type = NLA_U8 },
	[GA_JOOLD_FLUSH_ASAP] = { .type = NLA_U8 },
	[GA_JOOLD_FLUSH_DEADLINE] = { .type = NLA_U32 },
	[GA_JOOLD_CAPACITY] = { .type = NLA_U32 },
	[GA_JOOLD_MAX_PAYLOAD] = { .type = NLA_U32 },
};

static int get_optional_prefix6(struct nlattr *attr, char const *name, struct config_prefix6 *prefix)
{
	if (nla_len(attr) > 0) {
		prefix->set = true;
		return jnla_get_prefix6(attr, name, &prefix->prefix);
	}

	prefix->set = false;
	memset(&prefix->prefix, 0, sizeof(prefix->prefix));
	return 0;
}

static int get_optional_prefix4(struct nlattr *attr, char const *name, struct config_prefix4 *prefix)
{
	if (nla_len(attr) > 0) {
		prefix->set = true;
		return jnla_get_prefix4(attr, name, &prefix->prefix);
	}

	prefix->set = false;
	memset(&prefix->prefix, 0, sizeof(prefix->prefix));
	return 0;
}

static int get_common_values(struct nlattr *attrs[], struct globals *values)
{
	int error;

	if (attrs[GA_ENABLED])
		values->enabled = nla_get_u8(attrs[GA_ENABLED]);
	if (attrs[GA_TRACE])
		values->trace = nla_get_u8(attrs[GA_TRACE]);
	if (attrs[GA_POOL6]) {
		error = get_optional_prefix6(attrs[GA_POOL6], "pool6", &values->pool6);
		if (error)
			return error;
	}
	if (attrs[GA_RESET_TC])
		values->reset_traffic_class = nla_get_u8(attrs[GA_RESET_TC]);
	if (attrs[GA_RESET_TOS])
		values->reset_tos = nla_get_u8(attrs[GA_RESET_TOS]);
	if (attrs[GA_TOS])
		values->new_tos = nla_get_u8(attrs[GA_TOS]);
	if (attrs[GA_PLATEAUS]) {
		error = jnla_get_plateaus(attrs[GA_PLATEAUS], &values->plateaus);
		if (error)
			return error;
	}

	return 0;
}

static int get_siit_values(struct nlattr *attrs[], struct globals *values)
{
	int error;

	if (attrs[GA_COMPUTE_CSUM_ZERO])
		values->siit.compute_udp_csum_zero = nla_get_u8(attrs[GA_COMPUTE_CSUM_ZERO]);
	if (attrs[GA_HAIRPIN_MODE])
		values->siit.eam_hairpin_mode = nla_get_u8(attrs[GA_HAIRPIN_MODE]);
	if (attrs[GA_RANDOMIZE_ERROR_ADDR])
		values->siit.randomize_error_addresses = nla_get_u8(attrs[GA_RANDOMIZE_ERROR_ADDR]);
	if (attrs[GA_POOL6791V6]) {
		error = get_optional_prefix6(attrs[GA_POOL6791V6], "RFC 6791 prefix v6", &values->siit.rfc6791_prefix6);
		if (error)
			return error;
	}
	if (attrs[GA_POOL6791V4]) {
		error = get_optional_prefix4(attrs[GA_POOL6791V4], "RFC 6791 prefix v4", &values->siit.rfc6791_prefix4);
		if (error)
			return error;
	}

	return 0;
}

static int get_nat64_values(struct nlattr *attrs[], struct globals *values)
{
	if (attrs[GA_DROP_ICMP6_INFO])
		values->nat64.drop_icmp6_info = nla_get_u8(attrs[GA_DROP_ICMP6_INFO]);
	if (attrs[GA_SRC_ICMP6_BETTER])
		values->nat64.src_icmp6errs_better = nla_get_u8(attrs[GA_SRC_ICMP6_BETTER]);
	if (attrs[GA_F_ARGS])
		values->nat64.f_args = nla_get_u8(attrs[GA_F_ARGS]);
	if (attrs[GA_HANDLE_RST])
		values->nat64.handle_rst_during_fin_rcv = nla_get_u8(attrs[GA_HANDLE_RST]);
	if (attrs[GA_TTL_TCP_EST])
		values->nat64.bib.ttl.tcp_est = nla_get_u32(attrs[GA_TTL_TCP_EST]);
	if (attrs[GA_TTL_TCP_TRANS])
		values->nat64.bib.ttl.tcp_trans = nla_get_u32(attrs[GA_TTL_TCP_TRANS]);
	if (attrs[GA_TTL_UDP])
		values->nat64.bib.ttl.udp = nla_get_u32(attrs[GA_TTL_UDP]);
	if (attrs[GA_TTL_ICMP])
		values->nat64.bib.ttl.icmp = nla_get_u32(attrs[GA_TTL_ICMP]);
	if (attrs[GA_BIB_LOGGING])
		values->nat64.bib.bib_logging = nla_get_u8(attrs[GA_BIB_LOGGING]);
	if (attrs[GA_SESSION_LOGGING])
		values->nat64.bib.session_logging = nla_get_u8(attrs[GA_SESSION_LOGGING]);
	if (attrs[GA_DROP_BY_ADDR])
		values->nat64.bib.drop_by_addr = nla_get_u8(attrs[GA_DROP_BY_ADDR]);
	if (attrs[GA_DROP_EXTERNAL_TCP])
		values->nat64.bib.drop_external_tcp = nla_get_u8(attrs[GA_DROP_EXTERNAL_TCP]);
	if (attrs[GA_MAX_STORED_PKTS])
		values->nat64.bib.max_stored_pkts = nla_get_u32(attrs[GA_MAX_STORED_PKTS]);
	if (attrs[GA_JOOLD_ENABLED])
		values->nat64.joold.enabled = nla_get_u8(attrs[GA_JOOLD_ENABLED]);
	if (attrs[GA_JOOLD_FLUSH_ASAP])
		values->nat64.joold.flush_asap = nla_get_u8(attrs[GA_JOOLD_FLUSH_ASAP]);
	if (attrs[GA_JOOLD_FLUSH_DEADLINE])
		values->nat64.joold.flush_deadline = nla_get_u32(attrs[GA_JOOLD_FLUSH_DEADLINE]);
	if (attrs[GA_JOOLD_CAPACITY])
		values->nat64.joold.capacity = nla_get_u32(attrs[GA_JOOLD_CAPACITY]);
	if (attrs[GA_JOOLD_MAX_PAYLOAD])
		values->nat64.joold.max_payload = nla_get_u32(attrs[GA_JOOLD_MAX_PAYLOAD]);

	return 0;
}

int handle_global_update(struct sk_buff *skb, struct genl_info *info)
{
	struct xlator jool;
	int error;

	log_debug("Updating 'Global' value.");

	error = request_handle_start(info, XT_ANY, &jool);
	if (error)
		goto end;

	if (!info->attrs[RA_GLOBALS]) {
		log_err("Request is missing a globals container.");
		error = -EINVAL;
		goto revert_start;
	}

	error = global_update(&jool.globals, jool.flags, info->attrs[RA_GLOBALS]);
	if (error)
		goto revert_start;

	error = xlator_replace(&jool);

revert_start:
	request_handle_end(&jool);
end:
	return jresponse_send_simple(info, error);
}

int global_update(struct globals *cfg, xlator_type xt, struct nlattr *root)
{
	/* TODO the old code had force, but I don't see it anymore. */
	struct nlattr *attrs[GA_COUNT];
	int error;

	error = nla_parse_nested(attrs, GA_MAX, root, globals_policy, NULL);
	if (error) {
		log_err("The 'Globals Container' attribute is malformed.");
		return error;
	}

	error = get_common_values(attrs, cfg);
	if (error)
		return error;
	switch (xlator_flags2xt(xt)) {
	case XT_SIIT:
		return get_siit_values(attrs, cfg);
	case XT_NAT64:
		return get_nat64_values(attrs, cfg);
	}

	log_err("Unknown translator type: %d", xt);
	return -EINVAL;
}

//static int handle_global_update(struct xlator *jool, struct genl_info *info,
//		struct request_hdr *hdr)
//{
//	int error;
//
//	log_debug("Updating 'Global' option.");
//
//	/*
//	 * This is implemented as an atomic configuration run with only a single
//	 * globals modification.
//	 *
//	 * Why?
//	 *
//	 * First, I can't just modify the value directly because ongoing
//	 * translations could be using it. Making those values atomic is
//	 * awkward because not all of them are basic data types and atomic_t is
//	 * not exported to userspace. (struct globals needs to be.)
//	 *
//	 * Protecting the values by a spinlock is feasible but dirty and not
//	 * very performant. The translating code wants to query the globals
//	 * often and I don't think that locking all the time is very healthy.
//	 *
//	 * remain constant through a translation, because bad things might
//	 * happen if a value is queried at the beginning of the pipeline, some
//	 * stuff is done based on it, and a different value pops when queried
//	 * later. We could ask the code to query every value just once, but
//	 * really that's not intuitive and won't sit well for new coders.
//	 *
//	 * So really, we don't want to edit values. We want to replace the
//	 * entire structure via RCU so ongoing translations will keep their
//	 * current configurations and future ones will have the new config from
//	 * the beginning.
//	 *
//	 * Which leads to the second point: I don't want to protect
//	 * xlator.globals with RCU either because I don't want to lock RCU every
//	 * single time I want to query a global. Now I know that RCU-locking is
//	 * faster than spin-locking, but hear me out:
//	 *
//	 * We could just change the entire xlator. Not only because we already
//	 * need to support that for atomic configuration, but also because it
//	 * literally does not impose any additional synchronization rules
//	 * whatsoever for the translating code. The only overhead over replacing
//	 * only xlator.globals is that we need to allocate an extra xlator
//	 * during this operation. Which is not a recurrent operation at all.
//	 *
//	 * So let's STFU and do that.
//	 */
//
//	/*
//	 * Notice that this @jool is also a clone and we're the only thread
//	 * with access to it.
//	 */
//	error = global_update(&jool->globals, xlator_get_type(jool), hdr->force,
//			(struct global_value *)(hdr + 1),
//			nla_len(info->attrs[ATTR_DATA]) - sizeof(*hdr));
//	return nlcore_respond(info, (error < 0) ? error : xlator_replace(jool));
//}
