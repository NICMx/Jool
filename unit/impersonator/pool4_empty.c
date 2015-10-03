#include "nat64/mod/stateful/pool4/db.h"

bool pool4empty_contains(const struct ipv4_transport_addr *addr)
{
	log_err("This function was called! The unit test is broken.");
	BUG();
	return false;
}

int pool4empty_foreach_taddr4(struct packet *in, struct in_addr *daddr,
		int (*func)(struct ipv4_transport_addr *, void *), void *arg,
		unsigned int offset)
{
	log_err("This function was called! The unit test is broken.");
	BUG();
	return 0;
}
