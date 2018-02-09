#ifndef SRC_USERSPACE_CLIENT_NETLINK_POOL4_H_
#define SRC_USERSPACE_CLIENT_NETLINK_POOL4_H_

#include "nl-protocol.h"

typedef int (*pool4_foreach_cb)(struct pool4_sample *sample, void *args);

int pool4_foreach(l4_protocol proto, pool4_foreach_cb cb, void *args);
int pool4_add(struct pool4_entry_usr *entry);
int pool4_rm(struct pool4_entry_usr *entry, bool quick);
int pool4_flush(bool quick);

#endif /* SRC_USERSPACE_CLIENT_NETLINK_POOL4_H_ */
