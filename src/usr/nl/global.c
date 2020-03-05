#include "usr/nl/global.h"

#include <errno.h>
#include <netlink/msg.h>
#include "usr/nl/attribute.h"

static struct jool_result parse_common_globals(struct nlattr *attrs[],
		struct globals *out)
{
	struct jool_result result;

	out->status = nla_get_u8(attrs[GA_STATUS]);
	out->enabled = nla_get_u8(attrs[GA_ENABLED]);
	out->trace = nla_get_u8(attrs[GA_TRACE]);
	out->reset_traffic_class = nla_get_u8(attrs[GA_RESET_TC]);
	out->reset_tos = nla_get_u8(attrs[GA_RESET_TOS]);
	out->new_tos = nla_get_u8(attrs[GA_TOS]);

	result = nla_get_plateaus(attrs[GA_PLATEAUS], &out->plateaus);
	if (result.error)
		return result;

	if (attrs[GA_POOL6]) {
		out->pool6.set = true;
		return nla_get_prefix6(attrs[GA_POOL6], &out->pool6.prefix);
	} else {
		out->pool6.set = false;
		return result_success();
	}
}

static struct jool_result handle_query_response_siit(struct nl_msg *response,
		void *_args)
{
	struct nlattr *attrs[GA_COUNT];
	struct globals *out = _args;
	struct jool_result result;

	/* TODO not validating NULLs */

	result = jnla_parse_msg(response, attrs, GA_MAX, siit_globals_policy, false);
	if (result.error)
		return result;

	result = parse_common_globals(attrs, out);
	if (result.error)
		return result;

	out->siit.compute_udp_csum_zero = nla_get_u8(attrs[GA_COMPUTE_CSUM_ZERO]);
	out->siit.eam_hairpin_mode = nla_get_u8(attrs[GA_HAIRPIN_MODE]);
	out->siit.randomize_error_addresses = nla_get_u8(attrs[GA_RANDOMIZE_ERROR_ADDR]);

	if (attrs[GA_POOL6791V6]) {
		out->siit.rfc6791_prefix6.set = true;
		result = nla_get_prefix6(attrs[GA_POOL6791V6], &out->siit.rfc6791_prefix6.prefix);
		if (result.error)
			return result;
	} else {
		out->siit.rfc6791_prefix6.set = false;
	}

	if (attrs[GA_POOL6791V4]) {
		out->siit.rfc6791_prefix4.set = true;
		result = nla_get_prefix4(attrs[GA_POOL6791V4], &out->siit.rfc6791_prefix4.prefix);
		if (result.error)
			return result;
	} else {
		out->siit.rfc6791_prefix4.set = false;
	}

	return result_success();
}

static struct jool_result handle_query_response_nat64(struct nl_msg *response,
		void *_args)
{
	struct nlattr *attrs[GA_COUNT];
	struct globals *out = _args;
	struct jool_result result;

	result = jnla_parse_msg(response, attrs, GA_MAX, nat64_globals_policy, false);
	if (result.error)
		return result;

	result = parse_common_globals(attrs, out);
	if (result.error)
		return result;

	out->nat64.drop_icmp6_info = nla_get_u8(attrs[GA_DROP_ICMP6_INFO]);
	out->nat64.src_icmp6errs_better = nla_get_u8(attrs[GA_SRC_ICMP6_BETTER]);
	out->nat64.f_args = nla_get_u8(attrs[GA_F_ARGS]);
	out->nat64.handle_rst_during_fin_rcv = nla_get_u8(attrs[GA_HANDLE_RST]);
	out->nat64.bib.ttl.tcp_est = nla_get_u32(attrs[GA_TTL_TCP_EST]);
	out->nat64.bib.ttl.tcp_trans = nla_get_u32(attrs[GA_TTL_TCP_TRANS]);
	out->nat64.bib.ttl.udp = nla_get_u32(attrs[GA_TTL_UDP]);
	out->nat64.bib.ttl.icmp = nla_get_u32(attrs[GA_TTL_ICMP]);
	out->nat64.bib.bib_logging = nla_get_u8(attrs[GA_BIB_LOGGING]);
	out->nat64.bib.session_logging = nla_get_u8(attrs[GA_SESSION_LOGGING]);
	out->nat64.bib.drop_by_addr = nla_get_u8(attrs[GA_DROP_BY_ADDR]);
	out->nat64.bib.drop_external_tcp = nla_get_u8(attrs[GA_DROP_EXTERNAL_TCP]);
	out->nat64.bib.max_stored_pkts = nla_get_u32(attrs[GA_MAX_STORED_PKTS]);
	out->nat64.joold.enabled = nla_get_u8(attrs[GA_JOOLD_ENABLED]);
	out->nat64.joold.flush_asap = nla_get_u8(attrs[GA_JOOLD_FLUSH_ASAP]);
	out->nat64.joold.flush_deadline = nla_get_u32(attrs[GA_JOOLD_FLUSH_DEADLINE]);
	out->nat64.joold.capacity = nla_get_u32(attrs[GA_JOOLD_CAPACITY]);
	out->nat64.joold.max_payload = nla_get_u32(attrs[GA_JOOLD_MAX_PAYLOAD]);
	return result_success();
}

struct jool_result global_query(struct jool_socket *sk, char *iname,
		struct globals *out)
{
	struct nl_msg *msg;
	struct jool_result result;

	result = allocate_jool_nlmsg(sk, iname, JOP_GLOBAL_FOREACH, 0, &msg);
	if (result.error)
		return result;

	switch (sk->xt) {
	case XT_SIIT:
		return netlink_request(sk, msg, handle_query_response_siit, out);
	case XT_NAT64:
		return netlink_request(sk, msg, handle_query_response_nat64, out);
	}

	return result_from_error(-EINVAL, "Unknown translator type: %u", sk->xt);
}

struct jool_result global_update(struct jool_socket *sk, char *iname,
		struct global_field *field, char const *value, bool force)
{
	struct nl_msg *msg;
	struct nlattr *root;
	struct jool_result result;

	/*
	 * TODO BTW: We're not validating @field.
	 * Update: kernelspace has validation functions.
	 */

	result = allocate_jool_nlmsg(sk, iname, JOP_GLOBAL_UPDATE,
			force ? HDRFLAGS_FORCE : 0, &msg);
	if (result.error)
		return result;

	root = nla_nest_start(msg, RA_GLOBALS);
	if (!root)
		return packet_too_small();

	result = field->type->packetize(msg, field, value);
	if (result.error) {
		nlmsg_free(msg);
		return result;
	}

	nla_nest_end(msg, root);

	return netlink_request(sk, msg, NULL, NULL);
}
