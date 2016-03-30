#ifndef _JOOL_USR_EAM_H
#define _JOOL_USR_EAM_H

#include "nat64/common/types.h"

int eam_display(bool csv_format);
int eam_count(void);
int eam_add(struct ipv6_prefix *prefix6, struct ipv4_prefix *prefix4,
		bool force);
int eam_remove(struct ipv6_prefix *prefix6, struct ipv4_prefix *prefix4);
int eam_flush(void);

#endif /* _JOOL_USR_EAM_H */
