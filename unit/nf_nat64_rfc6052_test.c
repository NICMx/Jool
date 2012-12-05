#include <linux/module.h>
#include <linux/printk.h>
#include <linux/inet.h>

#include "unit_test.h"
#include "nf_nat64_types.h"
#include "nf_nat64_rfc6052.h"

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

char arr_ipv6[6][INET6_ADDRSTRLEN] = {
		"2001:db8:c000:221::",
		"2001:db8:1c0:2:21::",
		"2001:db8:122:c000:2:2100::",
		"2001:db8:122:3c0:0:221::",
		"2001:db8:122:344:c0:2:2100::",
		"2001:db8:122:344::192.0.2.33"
};

char prefix[6][INET6_ADDRSTRLEN] = {
		"2001:db8::",
		"2001:db8:100::",
		"2001:db8:122::",
		"2001:db8:122:300::",
		"2001:db8:122:344::",
		"2001:db8:122:344::"
};

int pref[6] = { 32, 40, 48, 56, 64, 96 };

bool test_extract_ipv4(char* ipv6_as_string, int prefix)
{
	struct in_addr expected;
	struct in_addr actual;
	struct in6_addr ipv6;

	char expected_as_string[INET_ADDRSTRLEN] = "192.0.2.33";
	expected.s_addr = in_aton(expected_as_string);

	in6_aton(ipv6_as_string, &ipv6);
	actual = nat64_extract_ipv4(&ipv6, prefix);
	ASSERT_EQUALS_IPV4(expected, actual, "Extract IPv4.")

	return true;
}

bool test_append_ipv4(char* expect_str, char* ipv6_as_string, int prefix)
{
	struct in_addr append;
	struct in6_addr ipv6, ipv6_append, expected;
	int i;

	char expected_as_string[INET_ADDRSTRLEN] = "192.0.2.33";
	append.s_addr = in_aton(expected_as_string);

	in6_aton(expect_str, &expected);

	in6_aton(ipv6_as_string, &ipv6);
	ipv6_append = nat64_append_ipv4(&ipv6, &append, prefix);

	// TODO (test) usa las funciones de types...
	for (i = 0; i < 4; i++) {
		if (expected.s6_addr32[i] != ipv6_append.s6_addr32[i]) {
			pr_warning("Test failed: %s Expected: %pI6c. Actual: %pI6c.\n", "Append IPv4.\n", &expected,
					&ipv6_append);
			return false;
		}
	}

	return true;
}

int init_module(void)
{
	int i;
	START_TESTS("nf_nat64_rfc6052.c");

	// test the extract function.
	for (i = 0; i < 6; i++) {
		CALL_TEST(test_extract_ipv4(arr_ipv6[i], pref[i]), arr_ipv6[i]);
	}

	// Test the append function.
	for (i = 0; i < 6; i++) {
		CALL_TEST(test_append_ipv4(arr_ipv6[i], prefix[i], pref[i]), arr_ipv6[i]);
	}

	END_TESTS;
}

void cleanup_module(void)
{
	// No code.
}
