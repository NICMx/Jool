#ifndef _JOOL_USR_EAM_H
#define _JOOL_USR_EAM_H

#include "nat64/common/types.h"

int eam_display(bool csv_format);
int eam_count(void);
int eam_add(struct ipv6_prefix *prefix6, struct ipv4_prefix *prefix4);
int eam_remove(bool pref6_set, struct ipv6_prefix *prefix6, bool pref4_set,
		struct ipv4_prefix *prefix4);
int eam_flush();


#endif /* _JOOL_USR_EAM_H */
