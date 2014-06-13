#include "nat64/comm/str_utils.h"
#include <linux/inet.h>
#include "nat64/mod/types.h"


int str_to_addr6(const char *str, struct in6_addr *result)
{
	int error = in6_pton(str, -1, (u8 *) result, '\0', NULL) ? 0 : -EINVAL;

	if (error)
		log_err("Cannot parse '%s' as a valid IPv6 address", str);

	return error;
}

int str_to_addr4(const char *str, struct in_addr *result)
{
	int error = in4_pton(str, -1, (u8 *) result, '\0', NULL) ? 0 : -EINVAL;

	if (error)
		log_err("Cannot parse '%s' as a valid IPv4 address", str);

	return error;
}
