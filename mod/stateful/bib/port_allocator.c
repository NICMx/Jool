#include "nat64/mod/stateful/bib/port_allocator.h"


int palloc_allocate(const struct ipv6_transport_addr *addr6,
		struct ipv4_transport_addr *result)
{

}

struct iteration_args {
	struct tuple *tuple6;
	struct ipv4_transport_addr *result;
};


/**
 * Evaluates "bib", and returns whether it is a perfect match to "void_args"'s tuple.
 * See allocate_ipv4_transport_address().
 */
static int find_perfect_addr4(struct in_addr *host_addr, void *void_args)
{
	struct iteration_args *args = void_args;
	struct ipv4_transport_addr addr;
	int error;

	addr.l3 = *host_addr;
	addr.l4 = args->tuple6->src.addr6.l4;

	error = pool4_get_match(args->tuple6->l4_proto, &addr, &args->result->l4);
	if (error)
		return 0; /* Not a satisfactory match; keep looking.*/

	args->result->l3 = *host_addr;
	return 1; /* Found a match; break the iteration with a no-error (but still non-zero) status. */
}

/**
 * Evaluates "bib", and returns whether it is an acceptable match to "void_args"'s tuple.
 * See allocate_ipv4_transport_address().
 */
static int find_runnerup_addr4(struct in_addr *host_addr, void *void_args)
{
	struct iteration_args *args = void_args;
	int error;

	error = pool4_get_any_port(args->tuple6->l4_proto, host_addr, &args->result->l4);
	if (error)
		return 0; /* Not a satisfactory match; keep looking.*/

	args->result->l3 = *host_addr;
	return 1; /* Found a match; break the iteration with a no-error (but still non-zero) status. */
}

/**
 * "Allocates" from the IPv4 pool a new transport address. Attemps to make this address as similar
 * to "tuple6"'s contents as possible.
 *
 * Sorry, we're using the term "allocate" because the RFC does. A more appropriate name in this
 * context would be "borrow (from the IPv4 pool)".
 *
 * RFC6146 - Sections 3.5.1.1 and 3.5.2.3.
 *
 * @param[in] The table to iterate through.
 * @param[in] tuple6 this should contain the IPv6 source address you want the IPv4 address for.
 * @param[out] result the transport address we borrowed from the pool.
 * @return true if everything went OK, false otherwise.
 */
static int allocate_transport_address(struct host6_node *host_node, struct tuple *tuple6,
		struct ipv4_transport_addr *result)
{
	int error;
	struct iteration_args args = {
			.tuple6 = tuple6,
			.result = result
	};

	/* First, try to find a perfect match (Same address and a compatible port or id). */
	error = host6_node_for_each_addr4(host_node, find_perfect_addr4, &args);
	if (error > 0)
		return 0; /* A match was found and "result" is already populated, so report success. */
	else if (error < 0)
		return error; /* Something failed, report.*/

	/*
	 * Else, iteration ended with no perfect match. Find a good match instead...
	 * (good match = same address, any port or id)
	 */
	error = host6_node_for_each_addr4(host_node, find_runnerup_addr4, &args);
	if (error < 0)
		return error;
	else if (error > 0)
		return 0;

	/*
	 * There are no good matches. Just use any available IPv4 address and hope for the best.
	 * Alternatively, this could be the first BIB entry being created, so assign any address
	 * anyway.
	 */
	return pool4_get_any_addr(tuple6->l4_proto, tuple6->src.addr6.l4, result);
}
