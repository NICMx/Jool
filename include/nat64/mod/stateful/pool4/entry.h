#ifndef _JOOL_MOD_POOL4_ENTRY_H
#define _JOOL_MOD_POOL4_ENTRY_H

#include "nat64/common/types.h"

struct port_range {
	__u16 min;
	__u16 max;
};

struct pool4_sample {
	struct in_addr addr;
	struct port_range range;
};

struct pool4_ports {
	struct port_range range;
	/* Links this pool4_ports to its address's "ports" list. */
	struct list_head list_hook;
};

/**
 * An address within the pool, along with its ports.
 */
struct pool4_addr {
	struct in_addr addr;
	/**
	 * The port ranges from the addresses the user reserved for Jool to use.
	 * It links elements of type pool4_ports.
	 * TODO (performance) maybe we could break some iterations early if
	 * this was sorted.
	 */
	struct list_head ports;

	struct list_head list_hook;
};

struct pool4_ports *pool4_ports_create(const __u16 min, const __u16 max);

bool pool4_range_equals(const struct port_range *r1,
		const struct port_range *r2);
bool pool4_range_intersects(const struct port_range *r1,
		const struct port_range *r2);
unsigned int pool4_range_count(const struct port_range *range);

#endif /* _JOOL_MOD_POOL4_ENTRY_H */
