#ifndef _JOOL_USR_POOL4_H
#define _JOOL_USR_POOL4_H

#include "nat64/common/types.h"


int pool4_display(void);
int pool4_count(void);
int pool4_add(struct ipv4_prefix *addrs);
int pool4_remove(struct ipv4_prefix *addrs, bool quick);
int pool4_flush(bool quick);


#endif /* _JOOL_USR_POOL4_H */
