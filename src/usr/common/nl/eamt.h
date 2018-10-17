#ifndef _JOOL_USR_EAM_H
#define _JOOL_USR_EAM_H

#include "common/config.h"
#include "common/types.h"
#include "usr/common/types.h"

typedef int (*eamt_foreach_cb)(struct eamt_entry *entry, void *args);

int eamt_foreach(char *instance, eamt_foreach_cb cb, void *args);
int eamt_add(char *instance, struct ipv6_prefix *p6, struct ipv4_prefix *p4,
		bool force);
int eamt_rm(char *instance, struct ipv6_prefix *p6, struct ipv4_prefix *p4);
int eamt_flush(char *instance);

#endif /* _JOOL_USR_EAM_H */
