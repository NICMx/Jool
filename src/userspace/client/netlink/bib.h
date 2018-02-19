#ifndef SRC_USERSPACE_CLIENT_NETLINK_BIB_H_
#define SRC_USERSPACE_CLIENT_NETLINK_BIB_H_

#include "nl-protocol.h"

typedef int (*bib_foreach_cb)(struct bib_entry_usr *entry, void *args);

int bib_foreach(char *instance, l4_protocol proto,
		bib_foreach_cb cb, void *args);
int bib_add(char *instance,
		struct ipv6_transport_addr *a6,
		struct ipv4_transport_addr *a4,
		l4_protocol proto);
int bib_rm(char *instance,
		struct ipv6_transport_addr *a6,
		struct ipv4_transport_addr *a4,
		l4_protocol proto);

#endif /* SRC_USERSPACE_CLIENT_NETLINK_BIB_H_ */
