#ifndef _JOOL_USR_POOL6_H
#define _JOOL_USR_POOL6_H

#include "nat64/comm/types.h"


int pool6_display(void);
int pool6_count(void);
int pool6_add(struct ipv6_prefix *prefix);
int pool6_remove(struct ipv6_prefix *prefix, bool quick);
int pool6_flush(bool quick);


#endif /* _JOOL_USR_POOL6_H */
