#include "nat64/mod/stateful/pool4/db.h"

int pool4db_foreach_taddr4(struct pool4 *pool, struct net *ns,
		struct in_addr *daddr, __u8 tos, __u8 proto, __u32 mark,
		int (*func)(struct ipv4_transport_addr *, void *), void *arg,
		unsigned int offset)
{
	log_err("This function was called! The unit test is broken.");
	BUG();
}
