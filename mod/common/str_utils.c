#include "nat64/common/str_utils.h"
#include <linux/inet.h>

int str_to_addr4(const char *str, struct in_addr *result)
{
	return in4_pton(str, -1, (u8 *) result, '\0', NULL) ? 0 : -EINVAL;
}

int str_to_addr6(const char *str, struct in6_addr *result)
{
	return in6_pton(str, -1, (u8 *) result, '\0', NULL) ? 0 : -EINVAL;
}

const char *l3proto_to_string(l3_protocol l3_proto)
{
	switch (l3_proto) {
	case L3PROTO_IPV6:
		return "IPv6";
	case L3PROTO_IPV4:
		return "IPv4";
	}

	return NULL;
}

const char *l4proto_to_string(l4_protocol l4_proto)
{
	switch (l4_proto) {
	case L4PROTO_TCP:
		return "TCP";
	case L4PROTO_UDP:
		return "UDP";
	case L4PROTO_ICMP:
		return "ICMP";
	case L4PROTO_OTHER:
		return "unknown";
	}

	return NULL;
}
