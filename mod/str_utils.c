#include "nat64/comm/str_utils.h"

#include <linux/inet.h>


enum error_code str_to_addr4(const char *str, struct in_addr *result)
{
	return in4_pton(str, -1, (u8 *) result, '\0', NULL) ? ERR_SUCCESS : ERR_PARSE_ADDR4;
}

enum error_code str_to_addr6(const char *str, struct in6_addr *result)
{
	return in6_pton(str, -1, (u8 *) result, '\0', NULL) ? ERR_SUCCESS : ERR_PARSE_ADDR6;
}
