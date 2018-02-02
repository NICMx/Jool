#ifndef SRC_USERSPACE_CLIENT_NETLINK_GLOBAL_H_
#define SRC_USERSPACE_CLIENT_NETLINK_GLOBAL_H_

#include "nl-protocol.h"

struct global_update_field {
	__u16 type;
	size_t size;
	void *data;
};

int global_query(struct full_config *result);
int global_update(unsigned int field_index, void *value);

#endif /* SRC_USERSPACE_CLIENT_NETLINK_GLOBAL_H_ */
