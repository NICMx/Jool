#include "nat64/mod/stateful/pool4/entry.h"
#include "nat64/mod/common/wkmalloc.h"

struct pool4_ports *pool4_ports_create(const __u16 min, const __u16 max)
{
	struct pool4_ports *ports;

	ports = wkmalloc(struct pool4_ports, GFP_KERNEL);
	if (!ports)
		return NULL;

	ports->range.min = min;
	ports->range.max = max;
	return ports;
}
