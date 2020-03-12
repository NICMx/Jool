#include "usr/nl/address.h"

#include <errno.h>
#include "usr/nl/common.h"
#include "usr/nl/attribute.h"

static struct jool_result handle_method(struct nlattr *attrs[],
		struct address_translation_entry *out)
{
	if (attrs[AQA_PREFIX6052] && attrs[AQA_EAM]) {
		return result_from_error(
			-EINVAL,
			"The kernel's response has too many translation methods."
		);
	}

	if (attrs[AQA_PREFIX6052]) {
		out->method = AXM_RFC6052;
		return nla_get_prefix6(attrs[AQA_PREFIX6052], &out->prefix6052);
	}
	if (attrs[AQA_EAM]) {
		out->method = AXM_EAMT;
		return nla_get_eam(attrs[AQA_EAM], &out->eam);
	}

	return result_from_error(
		-EINVAL,
		"The kernel's response lacks the translation method."
	);
}

static struct jool_result query64_response_cb(struct nl_msg *response, void *args)
{
	static struct nla_policy query64_policy[AQA_COUNT] = {
		[AQA_ADDR4] = ADDR4_POLICY,
		[AQA_PREFIX6052] = { .type = NLA_NESTED, },
		[AQA_EAM] = { .type = NLA_NESTED, },
	};
	struct nlattr *attrs[AQA_COUNT];
	struct jool_result result;
	struct result_addrxlat64 *out = args;

	result = jnla_parse_msg(response, attrs, AQA_MAX, query64_policy, false);
	if (result.error)
		return result;

	if (!attrs[AQA_ADDR4]) {
		return result_from_error(
			-ESRCH,
			"The kernel's response lacks the result."
		);
	}

	nla_get_addr4(attrs[AQA_ADDR4], &out->addr);
	return handle_method(attrs, &out->entry);
}

struct jool_result joolnl_address_query64(struct joolnl_socket *sk,
		char const *iname, struct in6_addr const *addr,
		struct result_addrxlat64 *out)
{
	struct nl_msg *msg;
	struct jool_result result;

	result = joolnl_alloc_msg(sk, iname, JOP_ADDRESS_QUERY64, 0, &msg);
	if (result.error)
		return result;

	NLA_PUT(msg, RA_ADDR_QUERY, sizeof(*addr), addr);

	return joolnl_request(sk, msg, query64_response_cb, out);

nla_put_failure:
	return result_from_error(
		-NLE_NOMEM,
		"Cannot build Netlink request: Packet is too small."
	);
}

static struct jool_result query46_response_cb(struct nl_msg *response, void *args)
{
	static struct nla_policy query46_policy[AQA_COUNT] = {
		[AQA_ADDR6] = ADDR6_POLICY,
		[AQA_PREFIX6052] = { .type = NLA_NESTED, },
		[AQA_EAM] = { .type = NLA_NESTED, },
	};
	struct nlattr *attrs[AQA_COUNT];
	struct jool_result result;
	struct result_addrxlat46 *out = args;

	result = jnla_parse_msg(response, attrs, AQA_MAX, query46_policy, false);
	if (result.error)
		return result;

	if (!attrs[AQA_ADDR6]) {
		return result_from_error(
			-ESRCH,
			"The kernel's response lacks the result."
		);
	}

	nla_get_addr6(attrs[AQA_ADDR6], &out->addr);
	return handle_method(attrs, &out->entry);
}

struct jool_result joolnl_address_query46(struct joolnl_socket *sk,
		char const *iname, struct in_addr const *addr,
		struct result_addrxlat46 *out)
{
	struct nl_msg *msg;
	struct jool_result result;

	result = joolnl_alloc_msg(sk, iname, JOP_ADDRESS_QUERY46, 0, &msg);
	if (result.error)
		return result;

	NLA_PUT(msg, RA_ADDR_QUERY, sizeof(*addr), addr);

	return joolnl_request(sk, msg, query46_response_cb, out);

nla_put_failure:
	return joolnl_err_msgsize();
}
