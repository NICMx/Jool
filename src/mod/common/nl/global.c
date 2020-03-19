#include "mod/common/nl/global.h"

#include "common/constants.h"
#include "mod/common/log.h"
#include "mod/common/nl/nl_common.h"
#include "mod/common/nl/nl_core.h"
#include "mod/common/nl/attribute.h"
#include "mod/common/db/eam.h"
#include "mod/common/db/config.h"

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

	return nla_put_u8(skb, JNLAG_STATUS, values->enabled && !pools_empty)
		|| nla_put_u8(skb, JNLAG_ENABLED, values->enabled)
		|| nla_put_u8(skb, JNLAG_TRACE, values->trace)
		|| put_optional_prefix6(skb, JNLAG_POOL6, &values->pool6)
		|| nla_put_u8(skb, JNLAG_RESET_TC, values->reset_traffic_class)
		|| nla_put_u8(skb, JNLAG_RESET_TOS, values->reset_tos)
		|| nla_put_u8(skb, JNLAG_TOS, values->new_tos)
		|| jnla_put_plateaus(skb, JNLAG_PLATEAUS, &values->plateaus);
}

static int put_siit_values(struct sk_buff *skb, struct globals *values)
{
	return nla_put_u8(skb, JNLAG_COMPUTE_CSUM_ZERO, values->siit.compute_udp_csum_zero)
		|| nla_put_u8(skb, JNLAG_HAIRPIN_MODE, values->siit.eam_hairpin_mode)
		|| nla_put_u8(skb, JNLAG_RANDOMIZE_ERROR_ADDR, values->siit.randomize_error_addresses)
		|| put_optional_prefix6(skb, JNLAG_POOL6791V6, &values->siit.rfc6791_prefix6)
		|| put_optional_prefix4(skb, JNLAG_POOL6791V4, &values->siit.rfc6791_prefix4);
}

static int put_nat64_values(struct sk_buff *skb, struct globals *values)
{
	return nla_put_u8(skb, JNLAG_DROP_ICMP6_INFO, values->nat64.drop_icmp6_info)
		|| nla_put_u8(skb, JNLAG_SRC_ICMP6_BETTER, values->nat64.src_icmp6errs_better)
		|| nla_put_u8(skb, JNLAG_F_ARGS, values->nat64.f_args)
		|| nla_put_u8(skb, JNLAG_HANDLE_RST, values->nat64.handle_rst_during_fin_rcv)
		|| nla_put_u32(skb, JNLAG_TTL_TCP_EST, values->nat64.bib.ttl.tcp_est)
		|| nla_put_u32(skb, JNLAG_TTL_TCP_TRANS, values->nat64.bib.ttl.tcp_trans)
		|| nla_put_u32(skb, JNLAG_TTL_UDP, values->nat64.bib.ttl.udp)
		|| nla_put_u32(skb, JNLAG_TTL_ICMP, values->nat64.bib.ttl.icmp)
		|| nla_put_u8(skb, JNLAG_BIB_LOGGING, values->nat64.bib.bib_logging)
		|| nla_put_u8(skb, JNLAG_SESSION_LOGGING, values->nat64.bib.session_logging)
		|| nla_put_u8(skb, JNLAG_DROP_BY_ADDR, values->nat64.bib.drop_by_addr)
		|| nla_put_u8(skb, JNLAG_DROP_EXTERNAL_TCP, values->nat64.bib.drop_external_tcp)
		|| nla_put_u32(skb, JNLAG_MAX_STORED_PKTS, values->nat64.bib.max_stored_pkts)
		|| nla_put_u8(skb, JNLAG_JOOLD_ENABLED, values->nat64.joold.enabled)
		|| nla_put_u8(skb, JNLAG_JOOLD_FLUSH_ASAP, values->nat64.joold.flush_asap)
		|| nla_put_u32(skb, JNLAG_JOOLD_FLUSH_DEADLINE, values->nat64.joold.flush_deadline)
		|| nla_put_u32(skb, JNLAG_JOOLD_CAPACITY, values->nat64.joold.capacity)
		|| nla_put_u32(skb, JNLAG_JOOLD_MAX_PAYLOAD, values->nat64.joold.max_payload);
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

static const struct nla_policy globals_policy[JNLAG_COUNT] = {
	[JNLAG_ENABLED] = { .type = NLA_U8 },
	[JNLAG_TRACE] = { .type = NLA_U8 },
	[JNLAG_POOL6] = { .type = NLA_UNSPEC },
	[JNLAG_RESET_TC] = { .type = NLA_U8 },
	[JNLAG_RESET_TOS] = { .type = NLA_U8 },
	[JNLAG_TOS] = { .type = NLA_U8 },
	[JNLAG_PLATEAUS] = { .type = NLA_NESTED },
	[JNLAG_COMPUTE_CSUM_ZERO] = { .type = NLA_U8 },
	[JNLAG_HAIRPIN_MODE] = { .type = NLA_U8 },
	[JNLAG_RANDOMIZE_ERROR_ADDR] = { .type = NLA_U8 },
	[JNLAG_POOL6791V6] = { .type = NLA_UNSPEC },
	[JNLAG_POOL6791V4] = { .type = NLA_UNSPEC },
	[JNLAG_DROP_ICMP6_INFO] = { .type = NLA_U8 },
	[JNLAG_SRC_ICMP6_BETTER] = { .type = NLA_U8 },
	[JNLAG_F_ARGS] = { .type = NLA_U8 },
	[JNLAG_HANDLE_RST] = { .type = NLA_U8 },
	[JNLAG_TTL_TCP_EST] = { .type = NLA_U32 },
	[JNLAG_TTL_TCP_TRANS] = { .type = NLA_U32 },
	[JNLAG_TTL_UDP] = { .type = NLA_U32 },
	[JNLAG_TTL_ICMP] = { .type = NLA_U32 },
	[JNLAG_BIB_LOGGING] = { .type = NLA_U8 },
	[JNLAG_SESSION_LOGGING] = { .type = NLA_U8 },
	[JNLAG_DROP_BY_ADDR] = { .type = NLA_U8 },
	[JNLAG_DROP_EXTERNAL_TCP] = { .type = NLA_U8 },
	[JNLAG_MAX_STORED_PKTS] = { .type = NLA_U32 },
	[JNLAG_JOOLD_ENABLED] = { .type = NLA_U8 },
	[JNLAG_JOOLD_FLUSH_ASAP] = { .type = NLA_U8 },
	[JNLAG_JOOLD_FLUSH_DEADLINE] = { .type = NLA_U32 },
	[JNLAG_JOOLD_CAPACITY] = { .type = NLA_U32 },
	[JNLAG_JOOLD_MAX_PAYLOAD] = { .type = NLA_U32 },
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

static int get_common_values(struct nlattr *attrs[], struct globals *values, bool force)
{
	int error;

	if (attrs[JNLAG_ENABLED])
		values->enabled = nla_get_u8(attrs[JNLAG_ENABLED]);
	if (attrs[JNLAG_TRACE])
		values->trace = nla_get_u8(attrs[JNLAG_TRACE]);
	if (attrs[JNLAG_POOL6]) {
		error = get_optional_prefix6(attrs[JNLAG_POOL6], "pool6", &values->pool6);
		if (error)
			return error;
		error = validate_pool6(&values->pool6, force);
		if (error)
			return error;
	}
	if (attrs[JNLAG_RESET_TC])
		values->reset_traffic_class = nla_get_u8(attrs[JNLAG_RESET_TC]);
	if (attrs[JNLAG_RESET_TOS])
		values->reset_tos = nla_get_u8(attrs[JNLAG_RESET_TOS]);
	if (attrs[JNLAG_TOS])
		values->new_tos = nla_get_u8(attrs[JNLAG_TOS]);
	if (attrs[JNLAG_PLATEAUS]) {
		error = jnla_get_plateaus(attrs[JNLAG_PLATEAUS], &values->plateaus);
		if (error)
			return error;
	}

	return 0;
}

int validate_hairpin_mode(__u8 value)
{
	if (value == EHM_OFF || value == EHM_SIMPLE || value == EHM_INTRINSIC)
		return 0;

	log_err("Unknown hairpinning mode: %u", value);
	return -EINVAL;
}

static int validate_prefix6791v4(struct config_prefix4 *prefix, bool force)
{
	int error;

	if (!prefix->set)
		return 0;

	error = prefix4_validate(&prefix->prefix);
	if (error)
		return error;

	return prefix4_validate_scope(&prefix->prefix, force);
}

static int get_siit_values(struct nlattr *attrs[], struct globals *values, bool force)
{
	int error;

	if (attrs[JNLAG_COMPUTE_CSUM_ZERO])
		values->siit.compute_udp_csum_zero = nla_get_u8(attrs[JNLAG_COMPUTE_CSUM_ZERO]);
	if (attrs[JNLAG_HAIRPIN_MODE]) {
		values->siit.eam_hairpin_mode = nla_get_u8(attrs[JNLAG_HAIRPIN_MODE]);
		error = validate_hairpin_mode(values->siit.eam_hairpin_mode);
		if (error)
			return error;
	}
	if (attrs[JNLAG_RANDOMIZE_ERROR_ADDR])
		values->siit.randomize_error_addresses = nla_get_u8(attrs[JNLAG_RANDOMIZE_ERROR_ADDR]);
	if (attrs[JNLAG_POOL6791V6]) {
		error = get_optional_prefix6(attrs[JNLAG_POOL6791V6], "RFC 6791 prefix v6", &values->siit.rfc6791_prefix6);
		if (error)
			return error;
		error = prefix6_validate(&values->siit.rfc6791_prefix6.prefix);
		if (error)
			return error;
	}
	if (attrs[JNLAG_POOL6791V4]) {
		error = get_optional_prefix4(attrs[JNLAG_POOL6791V4], "RFC 6791 prefix v4", &values->siit.rfc6791_prefix4);
		if (error)
			return error;
		error = validate_prefix6791v4(&values->siit.rfc6791_prefix4, force);
		if (error)
			return error;
	}

	return 0;
}

static int validate_f_args(__u8 f_args)
{
	if (f_args > 0x0Fu) {
		log_err("f-args (%u) is out of range. (0-%u)", f_args, 0x0Fu);
		return -EINVAL;
	}

	return 0;
}

static int validate_timeout(const char *what, __u32 timeout, unsigned int min)
{
	if (timeout < min) {
		log_err("The '%s' timeout (%u) is too small. (min: %u)", what,
				timeout, min);
		return -EINVAL;
	}

	return 0;
}

static int get_nat64_values(struct nlattr *attrs[], struct globals *values)
{
	int error;

	if (attrs[JNLAG_DROP_ICMP6_INFO])
		values->nat64.drop_icmp6_info = nla_get_u8(attrs[JNLAG_DROP_ICMP6_INFO]);
	if (attrs[JNLAG_SRC_ICMP6_BETTER])
		values->nat64.src_icmp6errs_better = nla_get_u8(attrs[JNLAG_SRC_ICMP6_BETTER]);
	if (attrs[JNLAG_F_ARGS]) {
		values->nat64.f_args = nla_get_u8(attrs[JNLAG_F_ARGS]);
		error = validate_f_args(values->nat64.f_args);
		if (error)
			return error;
	}
	if (attrs[JNLAG_HANDLE_RST])
		values->nat64.handle_rst_during_fin_rcv = nla_get_u8(attrs[JNLAG_HANDLE_RST]);
	if (attrs[JNLAG_TTL_TCP_EST]) {
		values->nat64.bib.ttl.tcp_est = nla_get_u32(attrs[JNLAG_TTL_TCP_EST]);
		error = validate_timeout("tcp-est",
				values->nat64.bib.ttl.tcp_est,
				1000 * TCP_EST);
		if (error)
			return error;
	}
	if (attrs[JNLAG_TTL_TCP_TRANS]) {
		values->nat64.bib.ttl.tcp_trans = nla_get_u32(attrs[JNLAG_TTL_TCP_TRANS]);
		error = validate_timeout("tcp-trans",
				values->nat64.bib.ttl.tcp_trans,
				1000 * TCP_TRANS);
		if (error)
			return error;
	}
	if (attrs[JNLAG_TTL_UDP]) {
		values->nat64.bib.ttl.udp = nla_get_u32(attrs[JNLAG_TTL_UDP]);
		error = validate_timeout("udp",
				values->nat64.bib.ttl.udp,
				1000 * UDP_MIN);
		if (error)
			return error;
	}
	if (attrs[JNLAG_TTL_ICMP])
		values->nat64.bib.ttl.icmp = nla_get_u32(attrs[JNLAG_TTL_ICMP]);
	if (attrs[JNLAG_BIB_LOGGING])
		values->nat64.bib.bib_logging = nla_get_u8(attrs[JNLAG_BIB_LOGGING]);
	if (attrs[JNLAG_SESSION_LOGGING])
		values->nat64.bib.session_logging = nla_get_u8(attrs[JNLAG_SESSION_LOGGING]);
	if (attrs[JNLAG_DROP_BY_ADDR])
		values->nat64.bib.drop_by_addr = nla_get_u8(attrs[JNLAG_DROP_BY_ADDR]);
	if (attrs[JNLAG_DROP_EXTERNAL_TCP])
		values->nat64.bib.drop_external_tcp = nla_get_u8(attrs[JNLAG_DROP_EXTERNAL_TCP]);
	if (attrs[JNLAG_MAX_STORED_PKTS])
		values->nat64.bib.max_stored_pkts = nla_get_u32(attrs[JNLAG_MAX_STORED_PKTS]);
	if (attrs[JNLAG_JOOLD_ENABLED])
		values->nat64.joold.enabled = nla_get_u8(attrs[JNLAG_JOOLD_ENABLED]);
	if (attrs[JNLAG_JOOLD_FLUSH_ASAP])
		values->nat64.joold.flush_asap = nla_get_u8(attrs[JNLAG_JOOLD_FLUSH_ASAP]);
	if (attrs[JNLAG_JOOLD_FLUSH_DEADLINE])
		values->nat64.joold.flush_deadline = nla_get_u32(attrs[JNLAG_JOOLD_FLUSH_DEADLINE]);
	if (attrs[JNLAG_JOOLD_CAPACITY])
		values->nat64.joold.capacity = nla_get_u32(attrs[JNLAG_JOOLD_CAPACITY]);
	if (attrs[JNLAG_JOOLD_MAX_PAYLOAD])
		values->nat64.joold.max_payload = nla_get_u32(attrs[JNLAG_JOOLD_MAX_PAYLOAD]);

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

	if (!info->attrs[JNLAR_GLOBALS]) {
		log_err("Request is missing a globals container.");
		error = -EINVAL;
		goto revert_start;
	}

	error = global_update(&jool.globals, get_jool_hdr(info)->xt,
			get_jool_hdr(info)->flags & JOOLNLHDR_FLAGS_FORCE,
			info->attrs[JNLAR_GLOBALS]);
	if (error)
		goto revert_start;

	error = xlator_replace(&jool);

revert_start:
	request_handle_end(&jool);
end:
	return jresponse_send_simple(info, error);
}

int global_update(struct globals *cfg, xlator_type xt, bool force,
		struct nlattr *root)
{
	struct nlattr *attrs[JNLAG_COUNT];
	int error;

	error = NLA_PARSE_NESTED(attrs, JNLAG_MAX, root, globals_policy);
	if (error) {
		log_err("The 'Globals Container' attribute is malformed.");
		return error;
	}

	error = get_common_values(attrs, cfg, force);
	if (error)
		return error;
	switch (xt) {
	case XT_SIIT:
		return get_siit_values(attrs, cfg, force);
	case XT_NAT64:
		return get_nat64_values(attrs, cfg);
	}

	log_err("Unknown translator type: %d", xt);
	return -EINVAL;
}
