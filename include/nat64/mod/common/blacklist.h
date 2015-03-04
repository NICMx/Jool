#ifndef _JOOL_MOD_BLACKLIST_H
#define _JOOL_MOD_BLACKLIST_H

#include "nat64/mod/common/types.h"

bool is_blacklisted4(const __be32 addr32);
bool is_blacklisted6(const struct in6_addr *addr);

#endif /* _JOOL_MOD_BLACKLIST_H */
