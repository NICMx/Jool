#ifndef _JOOL_MOD_POOL4_EMPTY_H
#define _JOOL_MOD_POOL4_EMPTY_H

#include "common/types.h"
#include "mod/common/packet.h"
#include "mod/common/route.h"

bool pool4empty_contains(struct net *ns, const struct ipv4_transport_addr *addr);
int pool4empty_find(struct route4_args *route_args, struct pool4_range *range);

#endif /* _JOOL_MOD_POOL4_EMPTY_H */
