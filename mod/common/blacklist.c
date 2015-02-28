#include "nat64/mod/common/blacklist.h"

static struct ipv4_prefix list[] = {
		{ .address.s_addr = cpu_to_be32(0x00000000), .len = 8 }, /* 0.0.0.0/8 */
		{ .address.s_addr = cpu_to_be32(0x7f000000), .len = 8 }, /* 127.0.0.0/8 */
		{ .address.s_addr = cpu_to_be32(0xa9fe0000), .len = 16 }, /* 169.254.0.0/16 */
		{ .address.s_addr = cpu_to_be32(0xffffffff), .len = 32 }, /* 255.255.255.255 */
};

bool is_blacklisted(__be32 addr32)
{
	struct in_addr addr;
	int i;

	addr.s_addr = addr32;

	for (i = 0; i < ARRAY_SIZE(list); i++) {
		if (ipv4_prefix_contains(&list[i], &addr))
			return true;
	}

	return false;
}
