#include "netlink/nl-attr.h"

static int validate_attr(struct nlattr *attr, jool_nlattr type, size_t size)
{
	if (!attr)
		return -EINVAL; /* Error msg already printed by __nla_ok() */

	if (type != attr->nla_type) {
		log_err("Expected attribute type %d, but kernel response has a %d instead.",
				type, attr->nla_type);
		goto fail;
	}
	if (size != nla_len(attr)) {
		log_err("Expected attribute length %zu, but data field has %d bytes instead.",
				size, nla_len(attr));
		goto fail;
	}

	return 0;

fail:
	log_err("Skipping...");
	return -EINVAL;
}

int jnla_get_addr6(struct nlattr *attr, jool_nlattr type, struct in6_addr *addr)
{
	if (validate_attr(attr, type, sizeof(struct in6_addr)))
		return -EINVAL;

	memcpy(addr, nla_data(attr), sizeof(*addr));
	return 0;
}

int jnla_get_addr4(struct nlattr *attr, jool_nlattr type, struct in_addr *addr)
{
	if (validate_attr(attr, type, sizeof(struct in_addr)))
		return -EINVAL;

	memcpy(addr, nla_data(attr), sizeof(*addr));
	return 0;
}

int jnla_get_port(struct nlattr *attr, jool_nlattr type, __u16 *result)
{
	if (validate_attr(attr, type, sizeof(__u16)))
		return -EINVAL;

	*result = nla_get_u16(attr);
	return 0;
}

int jnla_get_bool(struct nlattr *attr, jool_nlattr type, bool *result)
{
	if (validate_attr(attr, type, sizeof(__u8)))
		return -EINVAL;

	*result = !!nla_get_u8(attr);
	return 0;
}

/**
 * Same as nla_ok(), except it also standard error messages on error.
 */
static bool __nla_ok(struct nlattr *attr, int remaining)
{
	if (nla_ok(attr, remaining))
		return true;

	log_err("The response from the kernel appears to be truncated.");
	return false;
}

struct nlattr *jnla_nested_first(struct nlattr *super_attr, int *remaining)
{
	struct nlattr *result;

	result = nla_data(super_attr);
	*remaining = nla_len(super_attr);

	return __nla_ok(result, *remaining) ? result : NULL;
}

struct nlattr *jnla_next(struct nlattr *attr, int *remaining)
{
	return __nla_ok(attr, *remaining) ? nla_next(attr, remaining) : NULL;
}

int jnla_put_addr6(struct nl_msg *msg, jool_nlattr type, struct in6_addr *addr)
{
	return nla_put(msg, type, sizeof(struct in6_addr), addr);
}

int jnla_put_addr4(struct nl_msg *msg, jool_nlattr type, struct in_addr *addr)
{
	return nla_put(msg, type, sizeof(struct in_addr), addr);
}

int jnla_put_port(struct nl_msg *msg, jool_nlattr type, __u16 port)
{
	return nla_put_u16(msg, type, port);
}

int jnla_put_src_taddr6(struct nl_msg *msg, struct ipv6_transport_addr *addr)
{
	return jnla_put_addr6(msg, JNLA_SADDR6, &addr->l3)
			|| jnla_put_port(msg, JNLA_SPORT6, addr->l4);
}

int jnla_put_src_taddr4(struct nl_msg *msg, struct ipv4_transport_addr *addr)
{
	return jnla_put_addr4(msg, JNLA_SADDR4, &addr->l3)
			|| jnla_put_port(msg, JNLA_SPORT4, addr->l4);
}

int jnla_put_proto(struct nl_msg *request, l4_protocol proto)
{
	return nla_put_u8(request, JNLA_L4PROTO, proto);
}
