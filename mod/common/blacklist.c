#include "nat64/mod/common/blacklist.h"

static struct ipv4_prefix list4[] = {
		{ .address.s_addr = cpu_to_be32(0x00000000), .len = 8 }, /* 0.0.0.0/8 */
		{ .address.s_addr = cpu_to_be32(0x7f000000), .len = 8 }, /* 127.0.0.0/8 */
		{ .address.s_addr = cpu_to_be32(0xa9fe0000), .len = 16 }, /* 169.254.0.0/16 */
		{ .address.s_addr = cpu_to_be32(0xe0000000), .len = 4 }, /* 224.0.0.0/4 */
		{ .address.s_addr = cpu_to_be32(0xffffffff), .len = 32 }, /* 255.255.255.255 */
};

static struct ipv6_prefix list6[] = {
		{ /* ::/128 */
			.address.s6_addr32[0] = cpu_to_be32(0x00000000),
			.address.s6_addr32[1] = cpu_to_be32(0x00000000),
			.address.s6_addr32[2] = cpu_to_be32(0x00000000),
			.address.s6_addr32[3] = cpu_to_be32(0x00000000),
			.len = 128
		},
		{ /* ::1/128 */
			.address.s6_addr32[0] = cpu_to_be32(0x00000000),
			.address.s6_addr32[1] = cpu_to_be32(0x00000000),
			.address.s6_addr32[2] = cpu_to_be32(0x00000000),
			.address.s6_addr32[3] = cpu_to_be32(0x00000001),
			.len = 128
		},
		{ /* fe80::/10 */
			.address.s6_addr32[0] = cpu_to_be32(0xfe800000),
			.address.s6_addr32[1] = cpu_to_be32(0x00000000),
			.address.s6_addr32[2] = cpu_to_be32(0x00000000),
			.address.s6_addr32[3] = cpu_to_be32(0x00000000),
			.len = 10
		},
		{ /* ff00::/8 */
			.address.s6_addr32[0] = cpu_to_be32(0xff000000),
			.address.s6_addr32[1] = cpu_to_be32(0x00000000),
			.address.s6_addr32[2] = cpu_to_be32(0x00000000),
			.address.s6_addr32[3] = cpu_to_be32(0x00000000),
			.len = 10
		},
};

bool is_blacklisted4(const __be32 addr32)
{
	struct in_addr addr;
	int i;

	addr.s_addr = addr32;

	for (i = 0; i < ARRAY_SIZE(list4); i++) {
		if (prefix4_contains(&list4[i], &addr))
			return true;
	}

	return false;
}

bool is_blacklisted6(const struct in6_addr *addr)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(list6); i++) {
		if (prefix6_contains(&list6[i], addr))
			return true;
	}

	return false;
}
