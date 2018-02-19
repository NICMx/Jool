#ifndef SRC_USERSPACE_CLIENT_NETLINK_SESSION_H_
#define SRC_USERSPACE_CLIENT_NETLINK_SESSION_H_

#include "nl-protocol.h"

typedef int (*session_foreach_cb)(struct session_entry_usr *entry, void *args);

int session_foreach(char *instance, l4_protocol proto,
		session_foreach_cb cb, void *args);

#endif /* SRC_USERSPACE_CLIENT_NETLINK_SESSION_H_ */
