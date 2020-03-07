#include "mod/common/nl/attribute.h"

#include "mod/common/log.h"

static int validate_attr(struct nlattr *attr, char const *name,
		size_t expected_len)
{
	if (!attr) {
		log_err("Invalid request: '%s' attribute is missing.", name);
		return -EINVAL;
	}

	if (nla_len(attr) < expected_len) {
		log_err("Invalid request: %s has %d bytes instead of %zu.",
				name, nla_len(attr), expected_len);
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

static int validate_str(char const *str, size_t max_size)
{
	size_t i;

	for (i = 0; i < max_size; i++)
		if (str[i] == '\0')
			return 0;

	return -EINVAL;
}

int jnla_get_str(struct nlattr *attr, char const *name, size_t size, char *out)
{
	int error;

	error = validate_attr(attr, name, 0);
	if (error)
		return error;
	error = validate_str(nla_data(attr), size);
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

	error = validate_attr(attr, name, 0);
	if (error)
		return error;

	error = NLA_PARSE_NESTED(attrs, PA_MAX, attr, prefix6_policy);
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

	error = validate_attr(attr, name, 0);
	if (error)
		return error;

	error = NLA_PARSE_NESTED(attrs, PA_MAX, attr, prefix4_policy);
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

	error = validate_attr(attr, name, 0);
	if (error)
		return error;

	error = NLA_PARSE_NESTED(attrs, TAA_MAX, attr, taddr6_policy);
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

	error = validate_attr(attr, name, 0);
	if (error)
		return error;

	error = NLA_PARSE_NESTED(attrs, TAA_MAX, attr, taddr4_policy);
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

	error = validate_attr(attr, name, 0);
	if (error)
		return error;

	error = NLA_PARSE_NESTED(attrs, EA_MAX, attr, eam_policy);
	if (error) {
		log_err("The '%s' attribute is malformed.", name);
		return error;
	}

	error = jnla_get_prefix6(attrs[EA_PREFIX6], "IPv6 prefix", &eam->prefix6);
	if (error)
		return error;

	return jnla_get_prefix4(attrs[EA_PREFIX4], "IPv4 prefix", &eam->prefix4);
}

int jnla_get_pool4(struct nlattr *attr, char const *name, struct pool4_entry *entry)
{
	struct nlattr *attrs[P4A_COUNT];
	int error;

	error = validate_attr(attr, name, 0);
	if (error)
		return error;

	error = NLA_PARSE_NESTED(attrs, P4A_MAX, attr, pool4_entry_policy);
	if (error) {
		log_err("The 'pool4 entry' attribute is malformed.");
		return error;
	}

	memset(entry, 0, sizeof(*entry));

	if (attrs[P4A_MARK])
		entry->mark = nla_get_u32(attrs[P4A_MARK]);
	if (attrs[P4A_ITERATIONS])
		entry->iterations = nla_get_u32(attrs[P4A_ITERATIONS]);
	if (attrs[P4A_FLAGS])
		entry->flags = nla_get_u8(attrs[P4A_FLAGS]);
	if (attrs[P4A_PROTO])
		entry->proto = nla_get_u8(attrs[P4A_PROTO]);
	if (attrs[P4A_PREFIX]) {
		error = jnla_get_prefix4(attrs[P4A_PREFIX], "IPv4 prefix", &entry->range.prefix);
		if (error)
			return error;
	}
	if (attrs[P4A_PORT_MIN])
		entry->range.ports.min = nla_get_u16(attrs[P4A_PORT_MIN]);
	if (attrs[P4A_PORT_MAX])
		entry->range.ports.max = nla_get_u16(attrs[P4A_PORT_MAX]);

	return 0;
}

int jnla_get_bib(struct nlattr *attr, char const *name, struct bib_entry *entry)
{
	struct nlattr *attrs[BA_COUNT];
	int error;

	error = validate_attr(attr, name, 0);
	if (error)
		return error;

	error = NLA_PARSE_NESTED(attrs, BA_MAX, attr, bib_entry_policy);
	if (error) {
		log_err("The '%s' attribute is malformed.", name);
		return error;
	}

	memset(entry, 0, sizeof(*entry));

	if (attrs[BA_SRC6]) {
		error = jnla_get_taddr6(attrs[BA_SRC6], "IPv6 transport address", &entry->addr6);
		if (error)
			return error;
	}
	if (attrs[BA_SRC4]) {
		error = jnla_get_taddr4(attrs[BA_SRC4], "IPv4 transport address", &entry->addr4);
		if (error)
			return error;
	}
	if (attrs[BA_PROTO])
		entry->l4_proto = nla_get_u8(attrs[BA_PROTO]);
	if (attrs[BA_STATIC])
		entry->is_static = nla_get_u8(attrs[BA_STATIC]);

	return 0;
}

int jnla_get_plateaus(struct nlattr *root, struct mtu_plateaus *out)
{
	struct nlattr *attr;
	int rem;
	int error;

	error = validate_attr(root, "MTU plateaus", 0);
	if (error)
		return error;

	out->count = 0;
	nla_for_each_nested(attr, root, rem) {
		if (out->count >= PLATEAUS_MAX) {
			log_err("Too many plateaus.");
			return -EINVAL;
		}

		/* TODO not validating type */
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

	root = nla_nest_start(skb, attrtype);
	if (!root)
		return -ENOSPC;

	if (jnla_put_prefix6(skb, EA_PREFIX6, &eam->prefix6))
		goto cancel;
	if (jnla_put_prefix4(skb, EA_PREFIX4, &eam->prefix4))
		goto cancel;

	nla_nest_end(skb, root);
	return 0;

cancel:
	nla_nest_cancel(skb, root);
	return -ENOSPC;
}

int jnla_put_pool4(struct sk_buff *skb, int attrtype, struct pool4_entry const *entry)
{
	struct nlattr *root;
	int error;

	root = nla_nest_start(skb, attrtype);
	if (!root)
		return -ENOSPC;

	error = nla_put_u32(skb, P4A_MARK, entry->mark)
		|| nla_put_u32(skb, P4A_ITERATIONS, entry->iterations)
		|| nla_put_u8(skb, P4A_FLAGS, entry->flags)
		|| nla_put_u8(skb, P4A_PROTO, entry->proto)
		|| jnla_put_prefix4(skb, P4A_PREFIX, &entry->range.prefix)
		|| nla_put_u16(skb, P4A_PORT_MIN, entry->range.ports.min)
		|| nla_put_u16(skb, P4A_PORT_MAX, entry->range.ports.max);
	if (error)
		goto cancel;

	nla_nest_end(skb, root);
	return 0;

cancel:
	nla_nest_cancel(skb, root);
	return -ENOSPC;
}

int jnla_put_bib(struct sk_buff *skb, int attrtype, struct bib_entry const *bib)
{
	struct nlattr *root;
	int error;

	root = nla_nest_start(skb, attrtype);
	if (!root)
		return -ENOSPC;

	error = jnla_put_taddr6(skb, BA_SRC6, &bib->addr6)
		|| jnla_put_taddr4(skb, BA_SRC4, &bib->addr4)
		|| nla_put_u8(skb, BA_PROTO, bib->l4_proto)
		|| nla_put_u8(skb, BA_STATIC, bib->is_static);
	if (error) {
		nla_nest_cancel(skb, root);
		return -ENOSPC;
	}

	nla_nest_end(skb, root);
	return 0;
}

int jnla_put_session(struct sk_buff *skb, int attrtype, struct session_entry_usr const *entry)
{
	struct nlattr *root;
	int error;

	root = nla_nest_start(skb, attrtype);
	if (!root)
		return -ENOSPC;

	error = jnla_put_taddr6(skb, SEA_SRC6, &entry->src6)
		|| jnla_put_taddr6(skb, SEA_DST6, &entry->dst6)
		|| jnla_put_taddr4(skb, SEA_SRC4, &entry->src4)
		|| jnla_put_taddr4(skb, SEA_DST4, &entry->dst4)
		|| nla_put_u8(skb, SEA_PROTO, entry->proto)
		|| nla_put_u8(skb, SEA_STATE, entry->state)
		|| nla_put_u32(skb, SEA_EXPIRATION, entry->dying_time);
	if (error)
		goto cancel;

	nla_nest_end(skb, root);
	return 0;

cancel:
	nla_nest_cancel(skb, root);
	return -ENOSPC;
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
		error = nla_put_u16(skb, LA_ENTRY, plateaus->values[i]);
		if (error)
			goto cancel;
	}

	nla_nest_end(skb, root);
	return 0;

cancel:
	nla_nest_cancel(skb, root);
	return error;
}

void report_put_failure(void)
{
	log_err("The allocated Netlink packet is too small to contain the response. This might be a bug; please report it. PAGE_SIZE is %lu.",
			PAGE_SIZE);
}
