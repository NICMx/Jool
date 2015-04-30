#ifndef _JOOL_MOD_BIB_PORT_ALLOCATOR_H
#define _JOOL_MOD_BIB_PORT_ALLOCATOR_H

#include "nat64/mod/common/types.h"

int palloc_allocate(const struct ipv6_transport_addr *addr6,
		struct ipv4_transport_addr *result);

#endif /* _JOOL_MOD_BIB_PORT_ALLOCATOR_H */
