#include "nat64/comm/str_utils.h"

#include <linux/inet.h>


int str_to_addr4(const char *str, struct in_addr *result)
{
	return in4_pton(str, -1, (u8 *) result, '\0', NULL) ? 0 : -EINVAL;
}

int str_to_addr6(const char *str, struct in6_addr *result)
{
	return in6_pton(str, -1, (u8 *) result, '\0', NULL) ? 0 : -EINVAL;
}
