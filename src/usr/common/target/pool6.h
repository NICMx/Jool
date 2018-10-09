#ifndef _JOOL_USR_POOL6_H
#define _JOOL_USR_POOL6_H

#include "common/types.h"
#include "usr/common/types.h"


int pool6_display(char *iname, display_flags flags);
int pool6_count(char *iname);
int pool6_add(char *iname, struct ipv6_prefix *prefix, bool force);
int pool6_update(char *iname, struct ipv6_prefix *prefix);
int pool6_remove(char *iname, struct ipv6_prefix *prefix);
int pool6_flush(char *iname);


#endif /* _JOOL_USR_POOL6_H */
