#ifndef INCLUDE_NAT64_MOD_COMMON_TIMESTAMP_H_
#define INCLUDE_NAT64_MOD_COMMON_TIMESTAMP_H_

#include "nat64/common/config.h"

typedef unsigned long timestamp;

#define TIMESTAMP_START(name) name = jiffies;
#define TIMESTAMP_CREATE(name) timestamp name = jiffies;

void TIMESTAMP_END(timestamp beginning, timestamp_type type, bool success);

struct timestamp_foreach_func {
	int (*cb)(struct timestamps_entry_usr *, void *);
	void *arg;
};

int timestamp_foreach(struct timestamp_foreach_func *func, void *args);

#endif /* INCLUDE_NAT64_MOD_COMMON_TIMESTAMP_H_ */
