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

bool pool4_range_equals(const struct port_range *r1,
		const struct port_range *r2)
{
	return (r1->min == r2->min) && (r1->max == r2->max);
}

bool pool4_range_intersects(const struct port_range *r1,
		const struct port_range *r2)
{
	return !(r1->max < r2->min || r2->max < r1->min);
}

unsigned int pool4_range_count(const struct port_range *range)
{
	return range->max - range->min + 1U;
}
