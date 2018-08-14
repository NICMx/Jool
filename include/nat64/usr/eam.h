#ifndef _JOOL_USR_EAM_H
#define _JOOL_USR_EAM_H

#include "nat64/common/types.h"
#include "nat64/usr/types.h"

int eam_display(char *iname, display_flags flags);
int eam_count(char *iname);
int eam_add(char *iname, struct ipv6_prefix *prefix6,
		struct ipv4_prefix *prefix4, bool force);
int eam_remove(char *iname, struct ipv6_prefix *prefix6,
		struct ipv4_prefix *prefix4);
int eam_flush(char *iname);

#endif /* _JOOL_USR_EAM_H */
