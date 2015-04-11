#include "nat64/mod/common/address.h"
#include "nat64/mod/common/types.h"
#include <linux/inet.h>
#include <net/ipv6.h>

int prefix6_parse(char *str, struct ipv6_prefix *result)
{
	const char *slash_pos;

	if (in6_pton(str, -1, (u8 *) &result->address.in6_u.u6_addr8, '/', &slash_pos) != 1)
		goto fail;
	if (kstrtou8(slash_pos + 1, 0, &result->len) != 0)
		goto fail;

	return 0;

fail:
	log_err("IPv6 prefix is malformed: %s.", str);
	return -EINVAL;
}

bool addr4_equals(const struct in_addr *expected, const struct in_addr *actual)
{
	if (expected == actual)
		return true;
	if (expected == NULL || actual == NULL)
		return false;
	if (expected->s_addr != actual->s_addr)
		return false;

	return true;
}

bool addr6_equals(const struct in6_addr *expected, const struct in6_addr *actual)
{
	if (expected == actual)
		return true;
	if (expected == NULL || actual == NULL)
		return false;
	if (!ipv6_addr_equal(expected, actual))
		return false;

	return true;
}

bool ipv4_transport_addr_equals(const struct ipv4_transport_addr *expected,
		const struct ipv4_transport_addr *actual)
{
	if (expected == actual)
		return true;
	if (expected == NULL || actual == NULL)
		return false;
	if (expected->l3.s_addr != actual->l3.s_addr)
		return false;
	if (expected->l4 != actual->l4)
		return false;

	return true;
}

bool ipv6_transport_addr_equals(const struct ipv6_transport_addr *expected,
		const struct ipv6_transport_addr *actual)
{
	if (expected == actual)
		return true;
	if (expected == NULL || actual == NULL)
		return false;
	if (!ipv6_addr_equal(&expected->l3, &actual->l3))
		return false;
	if (expected->l4 != actual->l4)
		return false;

	return true;
}

bool prefix6_equals(const struct ipv6_prefix *expected, const struct ipv6_prefix *actual)
{
	if (expected == actual)
		return true;
	if (expected == NULL || actual == NULL)
		return false;
	if (!ipv6_addr_equal(&expected->address, &actual->address))
		return false;
	if (expected->len != actual->len)
		return false;

	return true;
}

bool prefix4_equals(const struct ipv4_prefix *expected, const struct ipv4_prefix *actual)
{
	if (expected == actual)
		return true;
	if (expected == NULL || actual == NULL)
		return false;
	if (expected->address.s_addr != actual->address.s_addr)
		return false;
	if (expected->len != actual->len)
		return false;

	return true;
}

static __u32 get_prefix4_mask(const struct ipv4_prefix *prefix)
{
	return ((__u64) 0xffffffffU) << (32 - prefix->len);
}

bool prefix4_contains(const struct ipv4_prefix *prefix, const struct in_addr *addr)
{
	__u32 maskbits = get_prefix4_mask(prefix);
	__u32 prefixbits = be32_to_cpu(prefix->address.s_addr) & maskbits;
	__u32 addrbits = be32_to_cpu(addr->s_addr) & maskbits;
	return prefixbits == addrbits;
}

bool prefix4_intersects(const struct ipv4_prefix *p1, const struct ipv4_prefix *p2)
{
	return prefix4_contains(p1, &p2->address) || prefix4_contains(p2, &p1->address);
}

__u64 prefix4_get_addr_count(struct ipv4_prefix *prefix)
{
	return ((__u64) 1U) << (32 - prefix->len);
}

bool prefix6_contains(const struct ipv6_prefix *prefix, const struct in6_addr *addr)
{
	return ipv6_prefix_equal(&prefix->address, addr, prefix->len);
}

int prefix4_validate(struct ipv4_prefix *prefix)
{
	__u32 suffix_mask;

	if (unlikely(!prefix)) {
		log_err("Prefix is NULL.");
		return -EINVAL;
	}

	if (prefix->len > 32) {
		log_err("Prefix length %u is too high.", prefix->len);
		return -EINVAL;
	}

	suffix_mask = ~get_prefix4_mask(prefix);
	if ((be32_to_cpu(prefix->address.s_addr) & suffix_mask) != 0) {
		log_err("'%pI4/%u' seems to have a suffix; please fix.", &prefix->address, prefix->len);
		return -EINVAL;
	}

	return 0;
}

int prefix6_validate(struct ipv6_prefix *prefix)
{
	unsigned int i;

	if (unlikely(!prefix)) {
		log_err("Prefix is NULL.");
		return -EINVAL;
	}

	if (prefix->len > 128) {
		log_err("Prefix length %u is too high.", prefix->len);
		return -EINVAL;
	}

	for (i = prefix->len; i < 128; i++) {
		if (addr6_get_bit(&prefix->address, i)) {
			log_err("'%pI6c/%u' seems to have a suffix; please fix.",
					&prefix->address, prefix->len);
			return -EINVAL;
		}
	}

	return 0;
}

__u32 addr4_get_bit(struct in_addr *addr, unsigned int pos)
{
	__u32 mask = 1U << (31 - pos);
	return be32_to_cpu(addr->s_addr) & mask;
}

void addr4_set_bit(struct in_addr *addr, unsigned int pos, bool value)
{
	__u32 mask = 1U << (31 - pos);

	if (value)
		addr->s_addr |= cpu_to_be32(mask);
	else
		addr->s_addr &= cpu_to_be32(~mask);
}

__u32 addr6_get_bit(struct in6_addr *addr, unsigned int pos)
{
	__u32 quadrant; /* As in, an IPv6 address has 4 "quadrants" of 32 bits each. */
	__u32 mask;

	/* "pos >> 5" is a more efficient version of "pos / 32". */
	quadrant = be32_to_cpu(addr->s6_addr32[pos >> 5]);
	/* "pos & 0x1FU" is a more efficient version of "pos % 32". */
	mask = 1U << (31 - (pos & 0x1FU));

	return quadrant & mask;
}

void addr6_set_bit(struct in6_addr *addr, unsigned int pos, bool value)
{
	__u32 *quadrant;
	__u32 mask;

	quadrant = &addr->s6_addr32[pos >> 5];
	mask = 1U << (31 - (pos & 0x1FU));

	if (value)
		*quadrant |= cpu_to_be32(mask);
	else
		*quadrant &= cpu_to_be32(~mask);
}
