#ifndef _POOL6_H
#define _POOL6_H

#include "nat64/comm/types.h"


int pool6_display(void);
int pool6_count(void);
int pool6_add(struct ipv6_prefix *prefix);
int pool6_remove(struct ipv6_prefix *prefix);


#endif /* _POOL6_H */
