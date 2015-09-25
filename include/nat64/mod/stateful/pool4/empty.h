#ifndef _JOOL_MOD_POOL4_EMPTY_H
#define _JOOL_MOD_POOL4_EMPTY_H

#include "nat64/mod/common/packet.h"
#include "nat64/mod/common/types.h"

bool pool4empty_contains(const struct ipv4_transport_addr *addr);
int pool4empty_foreach_taddr4(struct packet *in, const struct tuple *tuple6,
		int (*func)(struct ipv4_transport_addr *, void *), void *arg,
		unsigned int offset);

#endif /* _JOOL_MOD_POOL4_EMPTY_H */
