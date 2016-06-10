#include "nat64/mod/stateful/pool4/empty.h"

bool pool4empty_contains(struct net *ns, const struct ipv4_transport_addr *addr)
{
	return false;
}

int pool4empty_foreach_taddr4(struct net *ns,
		struct in_addr *daddr, __u8 tos, __u8 proto, __u32 mark,
		int (*cb)(struct ipv4_transport_addr *, void *), void *arg,
		unsigned int offset)
{
	log_err("This function was called! The unit test is broken.");
	BUG();
	return 0;
}
