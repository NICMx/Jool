#ifndef SRC_USERSPACE_CLIENT_NETLINK_INSTANCE_H_
#define SRC_USERSPACE_CLIENT_NETLINK_INSTANCE_H_

#include "types.h"

int instance_add(xlator_type type, char *name);
int instance_rm(char *name);

#endif /* SRC_USERSPACE_CLIENT_NETLINK_INSTANCE_H_ */
