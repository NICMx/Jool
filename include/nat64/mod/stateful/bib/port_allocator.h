#ifndef _JOOL_MOD_BIB_PORT_ALLOCATOR_H
#define _JOOL_MOD_BIB_PORT_ALLOCATOR_H

#include "nat64/mod/common/types.h"

int palloc_allocate(const struct tuple *tuple6, __u32 mark,
		struct ipv4_transport_addr *result);

#endif /* _JOOL_MOD_BIB_PORT_ALLOCATOR_H */
