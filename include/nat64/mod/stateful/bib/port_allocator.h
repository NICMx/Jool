#ifndef _JOOL_MOD_BIB_PORT_ALLOCATOR_H
#define _JOOL_MOD_BIB_PORT_ALLOCATOR_H

#include "nat64/common/types.h"
#include "nat64/mod/common/packet.h"
#include "nat64/mod/common/translation_state.h"

int palloc_init(void);
void palloc_destroy(void);

int palloc_allocate(struct xlation *state, struct in_addr *daddr,
		struct ipv4_transport_addr *result);

#endif /* _JOOL_MOD_BIB_PORT_ALLOCATOR_H */
