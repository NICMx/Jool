#include "nf_nat64_types.h"

#define CHECK_NULLS(expected, actual) \
	if (expected == actual) return true; \
	if (expected == NULL || actual == NULL) return false;


bool ipv4_addr_equals(struct in_addr *expected, struct in_addr *actual)
{
	CHECK_NULLS(expected, actual);

	if (expected->s_addr != actual->s_addr)
		return false;

	return true;
}

bool ipv6_addr_equals(struct in6_addr *expected, struct in6_addr *actual)
{
	int i;

	CHECK_NULLS(expected, actual);

	for (i = 0; i < 4; i++)
		if (expected->in6_u.u6_addr32[i] != expected->in6_u.u6_addr32[i])
			return false;

	return true;
}

bool ipv4_tuple_address_equals(struct ipv4_tuple_address *expected, struct ipv4_tuple_address *actual)
{
	CHECK_NULLS(expected, actual);

	if (!ipv4_addr_equals(&expected->address, &actual->address))
		return false;
	if (expected->pi.port != actual->pi.port)
		return false;

	return true;
}

/** Regresa el hash code correspondiente a la direcction "address". */
__be16 ipv4_tuple_address_hash_code(struct ipv4_tuple_address *address)
{
	return (address != NULL) ? address->pi.port : 0;
}

bool ipv6_tuple_address_equals(struct ipv6_tuple_address *expected, struct ipv6_tuple_address *actual)
{
	CHECK_NULLS(expected, actual);

	if (!ipv6_addr_equals(&expected->address, &actual->address))
		return false;
	if (expected->pi.port != actual->pi.port)
		return false;

	return true;
}

/** Regresa el hash code correspondiente a la direcction "address". */
__be16 ipv6_tuple_address_hash_code(struct ipv6_tuple_address *address)
{
	return (address != NULL) ? address->pi.port : 0;
}

bool ipv4_pair_equals(struct ipv4_pair *pair_1, struct ipv4_pair *pair_2)
{
	if (pair_1 == NULL && pair_2 == NULL)
		return true;
	if (pair_1 == NULL || pair_2 == NULL)
		return false;

	if (!ipv4_tuple_address_equals(&pair_1->local, &pair_2->local))
		return false;
	if (!ipv4_tuple_address_equals(&pair_1->remote, &pair_2->remote))
		return false;

	return true;
}

bool ipv6_pair_equals(struct ipv6_pair *pair_1, struct ipv6_pair *pair_2)
{
	if (pair_1 == NULL && pair_2 == NULL)
		return true;
	if (pair_1 == NULL || pair_2 == NULL)
		return false;

	if (!ipv6_tuple_address_equals(&pair_1->local, &pair_2->local))
		return false;
	if (!ipv6_tuple_address_equals(&pair_1->remote, &pair_2->remote))
		return false;

	return true;
}

__be16 ipv4_pair_hash_code(struct ipv4_pair *pair)
{
	return (pair != NULL) ? pair->remote.pi.port : 0;
}

__be16 ipv6_pair_hash_code(struct ipv6_pair *pair)
{
	return (pair != NULL) ? pair->local.pi.port : 0;
}
