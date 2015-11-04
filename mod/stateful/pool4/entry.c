#include "nat64/mod/stateful/pool4/entry.h"
#include <linux/slab.h>

struct pool4_ports *pool4_ports_create(const __u16 min, const __u16 max)
{
	struct pool4_ports *ports;

	ports = kmalloc(sizeof(*ports), GFP_KERNEL);
	if (!ports)
		return NULL;

	ports->range.min = min;
	ports->range.max = max;
	return ports;
}
