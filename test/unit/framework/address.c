#include "framework/address.h"

#include <linux/export.h>
#include <linux/inet.h>
#include <linux/string.h>

int str_to_addr4(const char *str, struct in_addr *result)
{
	return in4_pton(str, -1, (u8 *) result, '\0', NULL) ? 0 : -EINVAL;
}
EXPORT_SYMBOL_GPL(str_to_addr4);

int str_to_addr6(const char *str, struct in6_addr *result)
{
	return in6_pton(str, -1, (u8 *) result, '\0', NULL) ? 0 : -EINVAL;
}
EXPORT_SYMBOL_GPL(str_to_addr6);

int prefix6_parse(char *str, struct ipv6_prefix *result)
{
	const char *slash_pos;

	if (in6_pton(str, -1, (u8 *)&result->addr.s6_addr, '/', &slash_pos) != 1)
		goto fail;
	if (kstrtou8(slash_pos + 1, 0, &result->len) != 0)
		goto fail;

	return 0;

fail:
	pr_err("IPv6 prefix is malformed: %s.\n", str);
	return -EINVAL;
}
EXPORT_SYMBOL_GPL(prefix6_parse);

int prefix4_parse(char *str, struct ipv4_prefix *result)
{
	const char *slash_pos;

	if (strchr(str, '/') != NULL) {
		if (in4_pton(str, -1, (u8 *)&result->addr, '/', &slash_pos) != 1)
			goto fail;
		if (kstrtou8(slash_pos + 1, 0, &result->len) != 0)
			goto fail;
	} else {
		if (in4_pton(str, -1, (u8 *)&result->addr, '\0', NULL) != 1)
			goto fail;
		result->len = 32;
	}

	return 0;

fail:
	pr_err("IPv4 prefix or address is malformed: %s.\n", str);
	return -EINVAL;
}
EXPORT_SYMBOL_GPL(prefix4_parse);
