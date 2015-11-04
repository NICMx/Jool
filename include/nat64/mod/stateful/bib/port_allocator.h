#ifndef _JOOL_MOD_BIB_PORT_ALLOCATOR_H
#define _JOOL_MOD_BIB_PORT_ALLOCATOR_H

#include "nat64/mod/common/packet.h"
#include "nat64/mod/common/types.h"

int palloc_init(void);
void palloc_destroy(void);

int palloc_allocate(struct packet *in_pkt, const struct tuple *tuple6,
		struct in_addr *daddr, struct ipv4_transport_addr *result);

#endif /* _JOOL_MOD_BIB_PORT_ALLOCATOR_H */
