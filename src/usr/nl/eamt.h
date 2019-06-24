#ifndef _JOOL_USR_EAM_H
#define _JOOL_USR_EAM_H

#include "common/config.h"
#include "common/types.h"

typedef int (*eamt_foreach_cb)(struct eamt_entry *entry, void *args);

int eamt_foreach(char *iname, eamt_foreach_cb cb, void *args);
int eamt_add(char *iname, struct ipv6_prefix *p6, struct ipv4_prefix *p4,
		bool force);
int eamt_rm(char *iname, struct ipv6_prefix *p6, struct ipv4_prefix *p4);
int eamt_flush(char *iname);

int eamt_query_v6(char *iname, struct in6_addr *addr, struct in_addr *result);
int eamt_query_v4(char *iname, struct in_addr *addr, struct in6_addr *result);

#endif /* _JOOL_USR_EAM_H */
