#ifndef _JOOL_USR_POOL6_H
#define _JOOL_USR_POOL6_H

#include "nat64/common/types.h"


int pool6_display(bool csv);
int pool6_count(void);
int pool6_add(struct ipv6_prefix *prefix, bool force);
int pool6_update(struct ipv6_prefix *prefix);
int pool6_remove(struct ipv6_prefix *prefix);
int pool6_flush(void);


#endif /* _JOOL_USR_POOL6_H */
