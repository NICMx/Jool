#include <linux/module.h>
#include <linux/printk.h>
#include <linux/inet.h>

#include "nat64/unit/unit_test.h"
#include "nat64/comm/types.h"
#include "nat64/comm/str_utils.h"
#include "rfc6052.c"


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ramiro Nava <ramiro.nava@gmail.mx>");
MODULE_DESCRIPTION("RFC 6052 module test.");

/*
 +-----------------------+------------+------------------------------+
 | Network-Specific      |    IPv4    | IPv4-embedded IPv6 address   |
 | Prefix                |   address  |                              |
 +-----------------------+------------+------------------------------+
 | 2001:db8::/32         | 192.0.2.33 | 2001:db8:c000:221::          |
 | 2001:db8:100::/40     | 192.0.2.33 | 2001:db8:1c0:2:21::          |
 | 2001:db8:122::/48     | 192.0.2.33 | 2001:db8:122:c000:2:2100::   |
 | 2001:db8:122:300::/56 | 192.0.2.33 | 2001:db8:122:3c0:0:221::     |
 | 2001:db8:122:344::/64 | 192.0.2.33 | 2001:db8:122:344:c0:2:2100:: |
 | 2001:db8:122:344::/96 | 192.0.2.33 | 2001:db8:122:344::192.0.2.33 |
 +-----------------------+------------+------------------------------+
 */

char ipv4_addr_str[INET_ADDRSTRLEN] = "192.0.2.33";
struct in_addr ipv4_addr;

char ipv6_addr_str[6][INET6_ADDRSTRLEN] = {
		"2001:db8:c000:221::",
		"2001:db8:1c0:2:21::",
		"2001:db8:122:c000:2:2100::",
		"2001:db8:122:3c0:0:221::",
		"2001:db8:122:344:c0:2:2100::",
		"2001:db8:122:344::192.0.2.33"
};
struct in6_addr ipv6_addr[6];

char prefixes_str[6][INET6_ADDRSTRLEN] = {
		"2001:db8::",
		"2001:db8:100::",
		"2001:db8:122::",
		"2001:db8:122:300::",
		"2001:db8:122:344::",
		"2001:db8:122:344::"
};
__u8 prefixes_mask[6] = { 32, 40, 48, 56, 64, 96 };
struct ipv6_prefix prefixes[6];

bool test_addr_6to4(struct in6_addr *src, struct ipv6_prefix *prefix, struct in_addr *expected)
{
	struct in_addr actual;
	bool success = true;

	success &= assert_true(addr_6to4(src, prefix, &actual), "Extract IPv4-result");
	success &= assert_equals_ipv4(expected, &actual, "Extract IPv4-out");

	return success;
}

bool test_addr_4to6(struct in_addr *src, struct ipv6_prefix *prefix, struct in6_addr *expected)
{
	struct in6_addr actual;
	bool success = true;

	success &= assert_true(addr_4to6(src, prefix, &actual), "Append IPv4-result");
	success &= assert_equals_ipv6(expected, &actual, "Append IPv4-out.");

	return success;
}

static bool init(void)
{
	int i;

	if (str_to_addr4(ipv4_addr_str, &ipv4_addr) != 0) {
		log_warning("Could not convert '%s' to a IPv4 address. Failing...", ipv4_addr_str);
		return false;
	}

	for (i = 0; i < 6; i++) {
		if (str_to_addr6(ipv6_addr_str[i], &ipv6_addr[i]) != 0) {
			log_warning("Could not convert '%s' to a IPv6 address. Failing...", ipv6_addr_str[i]);
			return false;
		}
	}

	for (i = 0; i < 6; i++) {
		if (str_to_addr6(prefixes_str[i], &prefixes[i].address) != 0) {
			log_warning("Could not convert '%s' to a IPv6 address. Failing...", prefixes_str[i]);
			return false;
		}
		prefixes[i].len = prefixes_mask[i];
	}

	return true;
}

int init_module(void)
{
	int i;
	START_TESTS("rfc6052.c");

	if (!init())
		return -EINVAL;

	/* test the extract function. */
	for (i = 0; i < 6; i++) {
		CALL_TEST(test_addr_6to4(&ipv6_addr[i], &prefixes[i], &ipv4_addr), "Extract-%pI6c",
				&ipv6_addr[i]);
	}

	/* Test the append function. */
	for (i = 0; i < 6; i++) {
		CALL_TEST(test_addr_4to6(&ipv4_addr, &prefixes[i], &ipv6_addr[i]), "Append-%pI6c",
				&ipv6_addr[i]);
	}

	END_TESTS;
}

void cleanup_module(void)
{
	/* No code. */
}
