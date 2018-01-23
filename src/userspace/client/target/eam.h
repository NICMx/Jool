#ifndef _JOOL_USR_EAM_H
#define _JOOL_USR_EAM_H

#include "types.h"
#include "userspace-types.h"

int eam_display(display_flags flags);
int eam_add(struct ipv6_prefix *prefix6, struct ipv4_prefix *prefix4,
		bool force);
int eam_remove(struct ipv6_prefix *prefix6, struct ipv4_prefix *prefix4);
int eam_flush(void);

#endif /* _JOOL_USR_EAM_H */
