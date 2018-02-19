#ifndef SRC_USERSPACE_CLIENT_NETLINK_EAMT_H_
#define SRC_USERSPACE_CLIENT_NETLINK_EAMT_H_

#include "nl-protocol.h"

typedef int (*eamt_foreach_cb)(struct eamt_entry *entry, void *args);

int eamt_foreach(char *instance, eamt_foreach_cb cb, void *args);
int eamt_add(char *instance, struct ipv6_prefix *p6, struct ipv4_prefix *p4,
		bool force);
int eamt_rm(char *instance, struct ipv6_prefix *p6, struct ipv4_prefix *p4);
int eamt_flush(char *instance);

#endif /* SRC_USERSPACE_CLIENT_NETLINK_EAMT_H_ */
