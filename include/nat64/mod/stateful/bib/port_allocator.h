#ifndef _JOOL_MOD_BIB_PORT_ALLOCATOR_H
#define _JOOL_MOD_BIB_PORT_ALLOCATOR_H

#include "nat64/mod/common/types.h"

int palloc_allocate(const struct tuple *tuple6, const __u32 mark,
		struct ipv4_transport_addr *result);
void palloc_return(const struct ipv4_transport_addr *addr);

#endif /* _JOOL_MOD_BIB_PORT_ALLOCATOR_H */
