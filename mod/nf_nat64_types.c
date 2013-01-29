#include "nf_nat64_types.h"

#ifndef __KERNEL__
	#include <stddef.h>
#endif


/** This is a slightly more versatile in_addr. */
union ipv4_addr_union {
	__be32 by32;
	__be16 by16[2];
};

bool ipv4_addr_equals(struct in_addr *expected, struct in_addr *actual)
{
	if (expected == actual)
		return true;
	if (expected == NULL || actual == NULL)
		return false;
	if (expected->s_addr != actual->s_addr)
		return false;

	return true;
}

bool ipv6_addr_equals(struct in6_addr *expected, struct in6_addr *actual)
{
	int i;

	if (expected == actual)
		return true;
	if (expected == NULL || actual == NULL)
		return false;
	for (i = 0; i < 4; i++)
		if (expected->s6_addr32[i] != expected->s6_addr32[i])
			return false;

	return true;
}

__u16 ipv4_addr_hashcode(struct in_addr *addr)
{
	union ipv4_addr_union addr_union;
	__u16 result = 1;

	if (addr == NULL)
		return 0;
	addr_union.by32 = addr->s_addr;

	result = 31 * result + ntohs(addr_union.by16[0]);
	result = 31 * result + ntohs(addr_union.by16[1]);

	return result;
}

bool ipv4_tuple_addr_equals(struct ipv4_tuple_address *expected, struct ipv4_tuple_address *actual)
{
	if (expected == actual)
		return true;
	if (expected == NULL || actual == NULL)
		return false;
	if (!ipv4_addr_equals(&expected->address, &actual->address))
		return false;
	if (expected->pi.port != actual->pi.port)
		return false;

	return true;
}

__u16 ipv4_tuple_addr_hashcode(struct ipv4_tuple_address *address)
{
	return (address != NULL) ? ntohs(address->pi.port) : 0;
}

bool ipv6_tuple_addr_equals(struct ipv6_tuple_address *expected, struct ipv6_tuple_address *actual)
{
	if (expected == actual)
		return true;
	if (expected == NULL || actual == NULL)
		return false;
	if (!ipv6_addr_equals(&expected->address, &actual->address))
		return false;
	if (expected->pi.port != actual->pi.port)
		return false;

	return true;
}

__u16 ipv6_tuple_addr_hashcode(struct ipv6_tuple_address *address)
{
	// address->pi.port would perhaps be the logical hash code, since it's usually random,
	// but during nat64_get_bib_entry_by_ipv6_only() we need to ignore it during lookup
	// so this needs to be a little more creative.

	__u16 i;
	__u16 result = 1;

	if (address == NULL)
		return 0;

	for (i = 0; i < 8; i++)
		result = 31 * result + ntohs(address->address.s6_addr16[i]);

	return result;
}

bool ipv4_pair_equals(struct ipv4_pair *pair_1, struct ipv4_pair *pair_2)
{
	if (pair_1 == NULL && pair_2 == NULL)
		return true;
	if (pair_1 == NULL || pair_2 == NULL)
		return false;
	if (!ipv4_tuple_addr_equals(&pair_1->local, &pair_2->local))
		return false;
	if (!ipv4_tuple_addr_equals(&pair_1->remote, &pair_2->remote))
		return false;

	return true;
}

bool ipv6_pair_equals(struct ipv6_pair *pair_1, struct ipv6_pair *pair_2)
{
	if (pair_1 == NULL && pair_2 == NULL)
		return true;
	if (pair_1 == NULL || pair_2 == NULL)
		return false;
	if (!ipv6_tuple_addr_equals(&pair_1->local, &pair_2->local))
		return false;
	if (!ipv6_tuple_addr_equals(&pair_1->remote, &pair_2->remote))
		return false;

	return true;
}

__u16 ipv4_pair_hashcode(struct ipv4_pair *pair)
{
	// pair->remote.pi.port would perhaps be the logical hash code, since it's usually random,
	// but during nat64_is_allowed_by_address_filtering() we need to ignore it during lookup
	// so this needs to be a little more creative.

	union ipv4_addr_union local, remote;
	__u16 result = 1;

	if (pair == NULL)
		return 0;

	local.by32 = pair->local.address.s_addr;
	remote.by32 = pair->remote.address.s_addr;

	result = 31 * result + ntohs(local.by16[0]);
	result = 31 * result + ntohs(remote.by16[0]);
	result = 31 * result + ntohs(local.by16[1]);
	result = 31 * result + ntohs(remote.by16[1]);

	return result;
}

__u16 ipv6_pair_hashcode(struct ipv6_pair *pair)
{
	return (pair != NULL) ? ntohs(pair->local.pi.port) : 0;
}

bool ipv6_prefix_equals(struct ipv6_prefix *expected, struct ipv6_prefix *actual)
{
	if (expected == actual)
		return true;
	if (expected == NULL || actual == NULL)
		return false;

	if (!ipv6_addr_equals(&expected->address, &actual->address))
		return false;
	if (expected->maskbits != actual->maskbits)
		return false;

	return true;
}

#ifdef __KERNEL__
#include <linux/inet.h>

bool str_to_addr4(const char *str, struct in_addr *result)
{
	return in4_pton(str, -1, (u8 *) result, '\0', NULL);
}

bool str_to_addr6(const char *str, struct in6_addr *result)
{
	return in6_pton(str, -1, (u8 *) result, '\0', NULL);
}

#else
#include <arpa/inet.h>

bool str_to_addr4(const char *str, struct in_addr *result)
{
	return inet_pton(AF_INET, str, result);
}

bool str_to_addr6(const char *str, struct in6_addr *result)
{
	return inet_pton(AF_INET6, str, result);
}

#endif
