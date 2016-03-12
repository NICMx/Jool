#ifndef _JOOL_MOD_POOL4_EMPTY_H
#define _JOOL_MOD_POOL4_EMPTY_H

#include "nat64/common/types.h"
#include "nat64/mod/common/packet.h"

bool pool4empty_contains(struct net *ns, const struct ipv4_transport_addr *addr);
int pool4empty_foreach_taddr4(struct net *ns,
		struct in_addr *daddr, __u8 tos, __u8 proto, __u32 mark,
		int (*cb)(struct ipv4_transport_addr *, void *), void *arg,
		unsigned int offset);

#endif /* _JOOL_MOD_POOL4_EMPTY_H */
