#include "mod/common/nl/attribute.h"

#include "mod/common/log.h"

static int validate_attr(struct nlattr *attr, char const *name,
		size_t expected_len)
{
	if (!attr) {
		log_err("Invalid request: Missing %s argument.", name);
		return -EINVAL;
	}

	if (nla_len(attr) < expected_len) {
		log_err("Invalid request: %s has %zu bytes instead of %d.",
				name, expected_len, nla_len(attr));
		return -EINVAL;
	}

	return 0;
}

int jnla_get_u8(struct nlattr *attr, char const *name, __u8 *out)
{
	int error;

	error = validate_attr(attr, name, sizeof(__u8));
	if (error)
		return error;

	*out = nla_get_u8(attr);
	return 0;
}

int jnla_get_u32(struct nlattr *attr, char const *name, __u32 *out)
{
	int error;

	error = validate_attr(attr, name, sizeof(__u32));
	if (error)
		return error;

	*out = nla_get_u32(attr);
	return 0;
}

static int validate_str(char const *str, size_t expected_len)
{
	size_t i;

	for (i = 0; i <= expected_len; i++)
		if (str[i] == '\0')
			return 0;

	return -EINVAL;
}

int jnla_get_str(struct nlattr *attr, char const *name, size_t len, char *out)
{
	int error;

	error = validate_attr(attr, name, len);
	if (error)
		return error;
	error = validate_str(nla_data(attr), len);
	if (error)
		return error;

	strcpy(out, nla_data(attr));
	return 0;
}

int jnla_get_addr6(struct nlattr *attr, char const *name, struct in6_addr *out)
{
	int error;

	error = validate_attr(attr, name, sizeof(struct in6_addr));
	if (error)
		return error;

	memcpy(out, nla_data(attr), sizeof(*out));
	return 0;
}

int jnla_get_addr4(struct nlattr *attr, char const *name, struct in_addr *out)
{
	int error;

	error = validate_attr(attr, name, sizeof(struct in_addr));
	if (error)
		return error;

	memcpy(out, nla_data(attr), sizeof(*out));
	return 0;
}

int jnla_get_prefix6(struct nlattr *attr, char const *name, struct ipv6_prefix *out)
{
	struct nlattr *attrs[PA_COUNT];
	int error;

	error = nla_parse_nested(attrs, PA_MAX, attr, prefix6_policy, NULL);
	if (error) {
		log_err("The '%s' attribute is malformed.", name);
		return error;
	}

	out->len = nla_get_u8(attrs[PA_LEN]);
	return jnla_get_addr6(attrs[PA_ADDR], "IPv6 prefix address", &out->addr);
}

int jnla_get_prefix4(struct nlattr *attr, char const *name, struct ipv4_prefix *out)
{
	struct nlattr *attrs[PA_COUNT];
	int error;

	error = nla_parse_nested(attrs, PA_MAX, attr, prefix4_policy, NULL);
	if (error) {
		log_err("The '%s' attribute is malformed", name);
		return error;
	}

	out->len = nla_get_u8(attrs[PA_LEN]);
	return jnla_get_addr4(attrs[PA_ADDR], "IPv4 prefix address", &out->addr);
}

int jnla_get_taddr6(struct nlattr *attr, char const *name, struct ipv6_transport_addr *out)
{
	struct nlattr *attrs[TAA_COUNT];
	int error;

	error = nla_parse_nested(attrs, TAA_MAX, attr, taddr6_policy, NULL);
	if (error) {
		log_err("The '%s' attribute is malformed.", name);
		return error;
	}

	out->l4 = nla_get_u16(attrs[TAA_PORT]);
	return jnla_get_addr6(attrs[TAA_ADDR], "IPv6 address", &out->l3);
}

int jnla_get_taddr4(struct nlattr *attr, char const *name, struct ipv4_transport_addr *out)
{
	struct nlattr *attrs[TAA_COUNT];
	int error;

	error = nla_parse_nested(attrs, TAA_MAX, attr, taddr4_policy, NULL);
	if (error) {
		log_err("The '%s' attribute is malformed.", name);
		return error;
	}

	out->l4 = nla_get_u16(attrs[TAA_PORT]);
	return jnla_get_addr4(attrs[TAA_ADDR], "IPv4 address", &out->l3);
}

int jnla_get_eam(struct nlattr *attr, char const *name, struct eamt_entry *eam)
{
	struct nlattr *attrs[EA_COUNT];
	int error;

	error = nla_parse_nested(attrs, EA_MAX, attr, eam_policy, NULL);
	if (error) {
		log_err("The '%s' attribute is malformed.", name);
		return error;
	}

	error = jnla_get_prefix6(attrs[EA_PREFIX6], "IPv6 prefix", &eam->prefix6);
	if (error)
		return error;

	return jnla_get_prefix4(attrs[EA_PREFIX4], "IPv4 prefix", &eam->prefix4);
}

int jnla_get_plateaus(struct nlattr *root, struct mtu_plateaus *out)
{
	struct nlattr *attr;
	int rem;

	out->count = 0;
	nla_for_each_nested(attr, root, rem) {
		if (out->count >= PLATEAUS_MAX) {
			log_err("Too many plateaus.");
			return -EINVAL;
		}

		out->values[out->count] = nla_get_u16(attr);
		out->count++;
	}

	return 0;
}

int jnla_put_addr6(struct sk_buff *skb, int attrtype, struct in6_addr const *addr)
{
	return nla_put(skb, attrtype, sizeof(*addr), addr);
}

int jnla_put_addr4(struct sk_buff *skb, int attrtype, struct in_addr const *addr)
{
	return nla_put(skb, attrtype, sizeof(*addr), addr);
}

int jnla_put_prefix6(struct sk_buff *skb, int attrtype, struct ipv6_prefix const *prefix)
{
	struct nlattr *root;
	int error;

	root = nla_nest_start(skb, attrtype);
	if (!root)
		return -ENOSPC;

	error = jnla_put_addr6(skb, PA_ADDR, &prefix->addr);
	if (error)
		goto cancel;
	error = nla_put_u8(skb, PA_LEN, prefix->len);
	if (error)
		goto cancel;

	nla_nest_end(skb, root);
	return 0;

cancel:
	nla_nest_cancel(skb, root);
	return error;
}

int jnla_put_prefix4(struct sk_buff *skb, int attrtype, struct ipv4_prefix const *prefix)
{
	struct nlattr *root;
	int error;

	root = nla_nest_start(skb, attrtype);
	if (!root)
		return -ENOSPC;

	error = jnla_put_addr4(skb, PA_ADDR, &prefix->addr);
	if (error)
		goto cancel;
	error = nla_put_u8(skb, PA_LEN, prefix->len);
	if (error)
		goto cancel;

	nla_nest_end(skb, root);
	return 0;

cancel:
	nla_nest_cancel(skb, root);
	return error;
}

int jnla_put_taddr6(struct sk_buff *skb, int attrtype, struct ipv6_transport_addr const *taddr)
{
	struct nlattr *root;
	int error;

	root = nla_nest_start(skb, attrtype);
	if (!root)
		return -ENOSPC;

	error = jnla_put_addr6(skb, TAA_ADDR, &taddr->l3);
	if (error)
		goto cancel;
	error = nla_put_u16(skb, TAA_PORT, taddr->l4);
	if (error)
		goto cancel;

	nla_nest_end(skb, root);
	return 0;

cancel:
	nla_nest_cancel(skb, root);
	return error;
}

int jnla_put_taddr4(struct sk_buff *skb, int attrtype, struct ipv4_transport_addr const *taddr)
{
	struct nlattr *root;
	int error;

	root = nla_nest_start(skb, attrtype);
	if (!root)
		return -ENOSPC;

	error = jnla_put_addr4(skb, TAA_ADDR, &taddr->l3);
	if (error)
		goto cancel;
	error = nla_put_u16(skb, TAA_PORT, taddr->l4);
	if (error)
		goto cancel;

	nla_nest_end(skb, root);
	return 0;

cancel:
	nla_nest_cancel(skb, root);
	return error;
}

int jnla_put_eam(struct sk_buff *skb, int attrtype, struct eamt_entry const *eam)
{
	struct nlattr *root;
	int error;

	root = nla_nest_start(skb, attrtype);
	if (!root)
		return -ENOSPC;

	error = jnla_put_prefix6(skb, attrtype, &eam->prefix6);
	if (error)
		goto cancel;
	error = jnla_put_prefix4(skb, attrtype, &eam->prefix4);
	if (error)
		goto cancel;

	nla_nest_end(skb, root);
	return 0;

cancel:
	nla_nest_cancel(skb, root);
	return error;
}

int jnla_put_plateaus(struct sk_buff *skb, int attrtype, struct mtu_plateaus const *plateaus)
{
	struct nlattr *root;
	unsigned int i;
	int error;

	root = nla_nest_start(skb, attrtype);
	if (!root)
		return -ENOSPC;

	for (i = 0; i < plateaus->count; i++) {
		error = nla_put_u16(skb, PLATTR_PLATEAU, plateaus->values[i]);
		if (error)
			goto cancel;
	}

	nla_nest_end(skb, root);
	return 0;

cancel:
	/* TODO error messages? */
	nla_nest_cancel(skb, root);
	return error;
}
