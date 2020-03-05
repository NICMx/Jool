#include "usr/nl/attribute.h"

#include <errno.h>
#include <netlink/msg.h>
#include <netlink/genl/genl.h>

#include "common/config.h"

static struct jool_result validate_mandatory_attrs(struct nlattr *attrs[],
		int maxtype, struct nla_policy *policy)
{
	int i;

	/* All defined attributes are mandatory */
	for (i = 0; i < maxtype; i++) {
		if (policy[i].type && !attrs[i]) {
			return result_from_error(
				-EINVAL,
				"Jool's response is missing attribute %u.", i
			);
		}
	}

	return result_success();
}

/* Wrapper for jnla_parse_msg(). */
struct jool_result jnla_parse_msg(struct nl_msg *msg, struct nlattr *tb[],
		int maxtype, struct nla_policy *policy,
		bool validate_mandatories)
{
	int error;

	/* TODO validate the netlink header */
	error = genlmsg_parse(nlmsg_hdr(msg), sizeof(struct request_hdr),
				tb, maxtype, policy);
	if (!error) {
		return validate_mandatories
				? validate_mandatory_attrs(tb, maxtype, policy)
				: result_success();
	}

	return result_from_error(
		error,
		"Could not parse Jool's Netlink response: %s",
		nl_geterror(error)
	);
}

/* Wrapper for nla_parse_nested(). */
struct jool_result jnla_parse_nested(struct nlattr *tb[], int maxtype,
		struct nlattr *root, struct nla_policy *policy)
{
	int error;

//	{
//		struct nlattr *pos;
//		int rem;
//
//		printf("Root: %d %d\n", nla_type(root), nla_len(root));
//		nla_for_each_nested(pos, root, rem)
//			printf("%d %d\n", nla_type(pos), nla_len(pos));
//	}

	error = nla_parse_nested(tb, maxtype, root, policy);
	if (!error)
		return validate_mandatory_attrs(tb, maxtype, policy);

	return result_from_error(
		error,
		"Could not parse a nested attribute in Jool's Netlink response: %s",
		nl_geterror(error)
	);
}

void nla_get_addr6(struct nlattr *attr, struct in6_addr *addr)
{
	memcpy(addr, nla_data(attr), sizeof(*addr));
}

void nla_get_addr4(struct nlattr *attr, struct in_addr *addr)
{
	memcpy(addr, nla_data(attr), sizeof(*addr));
}

struct jool_result nla_get_prefix6(struct nlattr *root, struct ipv6_prefix *out)
{
	struct nlattr *attrs[PA_COUNT];
	struct jool_result result;

	result = jnla_parse_nested(attrs, PA_MAX, root, prefix6_policy);
	if (result.error)
		return result;

	nla_get_addr6(attrs[PA_ADDR], &out->addr);
	out->len = nla_get_u8(attrs[PA_LEN]);
	return result_success();
}

struct jool_result nla_get_prefix4(struct nlattr *root, struct ipv4_prefix *out)
{
	struct nlattr *attrs[PA_COUNT];
	struct jool_result result;

	result = jnla_parse_nested(attrs, PA_MAX, root, prefix4_policy);
	if (result.error)
		return result;

	nla_get_addr4(attrs[PA_ADDR], &out->addr);
	out->len = nla_get_u8(attrs[PA_LEN]);
	return result_success();
}

struct jool_result nla_get_taddr6(struct nlattr *root, struct ipv6_transport_addr *out)
{
	struct nlattr *attrs[TAA_COUNT];
	struct jool_result result;

	result = jnla_parse_nested(attrs, TAA_MAX, root, taddr6_policy);
	if (result.error)
		return result;

	nla_get_addr6(attrs[TAA_ADDR], &out->l3);
	out->l4 = nla_get_u16(attrs[TAA_PORT]);
	return result_success();
}

struct jool_result nla_get_taddr4(struct nlattr *root, struct ipv4_transport_addr *out)
{
	struct nlattr *attrs[TAA_COUNT];
	struct jool_result result;

	result = jnla_parse_nested(attrs, TAA_MAX, root, taddr4_policy);
	if (result.error)
		return result;

	nla_get_addr4(attrs[TAA_ADDR], &out->l3);
	out->l4 = nla_get_u16(attrs[TAA_PORT]);
	return result_success();
}

struct jool_result nla_get_eam(struct nlattr *attr, struct eamt_entry *out)
{
	struct nlattr *attrs[EA_COUNT];
	struct jool_result result;

	result = jnla_parse_nested(attrs, EA_MAX, attr, eam_policy);
	if (result.error)
		return result;

	result = nla_get_prefix6(attrs[EA_PREFIX6], &out->prefix6);
	if (result.error)
		return result;

	return nla_get_prefix4(attrs[EA_PREFIX4], &out->prefix4);
}

struct jool_result nla_get_plateaus(struct nlattr *root,
		struct mtu_plateaus *plateaus)
{
	struct nlattr *attr;
	int rem;

	plateaus->count = 0;
	nla_for_each_nested(attr, root, rem) {
		if (plateaus->count >= PLATEAUS_MAX) {
			return result_from_error(
				-EINVAL,
				"The kernel's response has too many plateaus."
			);
		}
		plateaus->values[plateaus->count] = nla_get_u16(attr);
		plateaus->count++;
	}

	return result_success();
}

int nla_put_addr6(struct nl_msg *msg, int attrtype, struct in6_addr *addr)
{
	return nla_put(msg, attrtype, sizeof(*addr), addr);
}

int nla_put_addr4(struct nl_msg *msg, int attrtype, struct in_addr *addr)
{
	return nla_put(msg, attrtype, sizeof(*addr), addr);
}

int nla_put_prefix6(struct nl_msg *msg, int attrtype, struct ipv6_prefix *prefix)
{
	struct nlattr *root;

	if (!prefix) {
		if (nla_put(msg, attrtype, 0, NULL))
			goto abort;
		return 0;
	}

	root = nla_nest_start(msg, attrtype);
	if (!root)
		goto abort;

	if (nla_put_addr6(msg, PA_ADDR, &prefix->addr))
		goto cancel;
	if (nla_put_u8(msg, PA_LEN, prefix->len))
		goto cancel;

	nla_nest_end(msg, root);
	return 0;

cancel:	nla_nest_cancel(msg, root);
abort:	return -ENOSPC;
}

int nla_put_prefix4(struct nl_msg *msg, int attrtype, struct ipv4_prefix *prefix)
{
	struct nlattr *root;

	if (!prefix) {
		if (nla_put(msg, attrtype, 0, NULL))
			goto abort;
		return 0;
	}

	root = nla_nest_start(msg, attrtype);
	if (!root)
		goto abort;

	if (nla_put_addr4(msg, PA_ADDR, &prefix->addr))
		goto cancel;
	if (nla_put_u8(msg, PA_LEN, prefix->len))
		goto cancel;

	nla_nest_end(msg, root);
	return 0;

cancel:	nla_nest_cancel(msg, root);
abort:	return -ENOSPC;
}

int nla_put_taddr6(struct nl_msg *msg, int attrtype, struct ipv6_transport_addr *taddr)
{
	struct nlattr *root;

	root = nla_nest_start(msg, attrtype);
	if (!root)
		goto abort;

	if (nla_put_addr6(msg, TAA_ADDR, &taddr->l3))
		goto cancel;
	if (nla_put_u16(msg, TAA_PORT, taddr->l4))
		goto cancel;

	nla_nest_end(msg, root);
	return 0;

cancel:	nla_nest_cancel(msg, root);
abort:	return -ENOSPC;
}

int nla_put_taddr4(struct nl_msg *msg, int attrtype, struct ipv4_transport_addr *taddr)
{
	struct nlattr *root;

	root = nla_nest_start(msg, attrtype);
	if (!root)
		goto abort;

	if (nla_put_addr4(msg, TAA_ADDR, &taddr->l3))
		goto cancel;
	if (nla_put_u16(msg, TAA_PORT, taddr->l4))
		goto cancel;

	nla_nest_end(msg, root);
	return 0;

cancel:	nla_nest_cancel(msg, root);
abort:	return -ENOSPC;
}

int nla_put_plateaus(struct nl_msg *msg, int attrtype, struct mtu_plateaus *plateaus)
{
	struct nlattr *root;
	unsigned int i;

	root = nla_nest_start(msg, attrtype);
	if (!root)
		goto abort;

	for (i = 0; i < plateaus->count; i++)
		if (nla_put_u16(msg, PLATTR_PLATEAU, plateaus->values[i]))
			goto cancel;

	nla_nest_end(msg, root);
	return 0;

cancel:	nla_nest_cancel(msg, root);
abort:	return -ENOSPC;
}

struct jool_result packet_too_small(void)
{
	return result_from_error(
		-NLE_NOMEM,
		"Cannot build Netlink request: Packet is too small."
	);
}
