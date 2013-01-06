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

bool test_extract_ipv4(char* ipv6_as_string, int prefix_len)
{
	const char expected_as_string[INET_ADDRSTRLEN] = "192.0.2.33";
	struct in_addr expected;
	struct in_addr actual;
	struct in6_addr ipv6;

	if (!str_to_addr4(expected_as_string, &expected)) {
		log_warning("Can't parse expected IPv4 address '%s'. Failing test.", expected_as_string);
		return false;
	}
	if (!str_to_addr6(ipv6_as_string, &ipv6)) {
		log_warning("Can't parse IPv6 address being tested '%s'. Failing test.", ipv6_as_string);
		return false;
	}

	actual = nat64_extract_ipv4(&ipv6, prefix_len);
	return assert_equals_ipv4(&expected, &actual, "Extract IPv4.");
}

bool test_append_ipv4(char* expected_as_string, char* prefix_as_string, int prefix_len)
{
	char ipv4_as_string[INET_ADDRSTRLEN] = "192.0.2.33";
	struct in_addr ipv4;
	struct in6_addr prefix, actual, expected;

	if (!str_to_addr4(ipv4_as_string, &ipv4)) {
		log_warning("Can't parse IPv4 address '%s'. Failing test.", ipv4_as_string);
		return false;
	}
	if (!str_to_addr6(prefix_as_string, &prefix)) {
		log_warning("Can't parse prefix '%s'. Failing test.", prefix_as_string);
		return false;
	}
	if (!str_to_addr6(expected_as_string, &expected)) {
		log_warning("Can't parse expected address '%s'. Failing test.", expected_as_string);
		return false;
	}

	actual = nat64_append_ipv4(&prefix, &ipv4, prefix_len);
	return assert_equals_ipv6(&expected, &actual, "Append IPv4.");
}

int init_module(void)
{
	int i;
	START_TESTS("nf_nat64_rfc6052.c");

	// test the extract function.
	for (i = 0; i < 6; i++) {
		CALL_TEST(test_extract_ipv4(arr_ipv6[i], pref[i]), "Extract-%s", arr_ipv6[i]);
	}

	// Test the append function.
	for (i = 0; i < 6; i++) {
		CALL_TEST(test_append_ipv4(arr_ipv6[i], prefix[i], pref[i]), "Append-%s", arr_ipv6[i]);
	}

	END_TESTS;
}

void cleanup_module(void)
{
	// No code.
}
