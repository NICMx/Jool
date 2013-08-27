#include "nat64/unit/unit_test.h"
#include <linux/kernel.h>
#include "nat64/comm/str_utils.h"


#define UNIT_WARNING(test_name, expected, actual, specifier) \
		log_warning("Test '%s' failed. Expected: " specifier ". Actual: " specifier ".", \
				test_name, \
				expected, \
				actual);
#define UNIT_WARNING_NOT(test_name, expected, actual, specifier) \
		log_warning("Test '%s' failed. Expected: not " specifier ". Actual: " specifier ".", \
				test_name, \
				expected, \
				actual);


bool assert_true(bool condition, char *test_name)
{
	if (!condition) {
		log_warning("Test '%s' failed.", test_name);
		return false;
	}
	return true;
}

bool assert_equals_int(int expected, int actual, char *test_name)
{
	if (expected != actual) {
		UNIT_WARNING(test_name, expected, actual, "%d");
		return false;
	}
	return true;
}

bool assert_equals_u8(__u8 expected, __u8 actual, char *test_name)
{
	return assert_equals_u32(expected, actual, test_name);
}

bool assert_equals_u16(__u16 expected, __u16 actual, char *test_name)
{
	return assert_equals_u32(expected, actual, test_name);
}

bool assert_equals_u32(__u32 expected, __u32 actual, char *test_name)
{
	if (expected != actual) {
		UNIT_WARNING(test_name, expected, actual, "%u");
		return false;
	}
	return true;
}

bool assert_equals_ptr(void *expected, void *actual, char *test_name)
{
	if (expected != actual) {
		UNIT_WARNING(test_name, expected, actual, "%p");
		return false;
	}
	return true;
}

bool assert_equals_ipv4(struct in_addr *expected, struct in_addr *actual, char *test_name)
{
	if (!ipv4_addr_equals(expected, actual)) {
		UNIT_WARNING(test_name, expected, actual, "%pI4");
		return false;
	}
	return true;
}

bool assert_equals_ipv4_str(unsigned char *expected_str, struct in_addr *actual, char *test_name)
{
	struct in_addr expected;

	if (str_to_addr4(expected_str, &expected) != 0) {
		log_warning("Could not parse '%s' as a valid IPv4 address.", expected_str);
		return false;
	}

	return assert_equals_ipv4(&expected, actual, test_name);
}

bool assert_equals_ipv6(struct in6_addr *expected, struct in6_addr *actual, char *test_name)
{
	if (!ipv6_addr_equals(expected, actual)) {
		UNIT_WARNING(test_name, expected, actual, "%pI6c");
		return false;
	}
	return true;
}

bool assert_equals_ipv6_str(unsigned char *expected_str, struct in6_addr *actual, char *test_name)
{
	struct in6_addr expected;

	if (str_to_addr6(expected_str, &expected) != 0) {
		log_warning("Could not parse '%s' as a valid IPv6 address.", expected_str);
		return false;
	}

	return assert_equals_ipv6(&expected, actual, test_name);
}

bool assert_range(unsigned int expected_min, unsigned int expected_max, unsigned int actual,
		char *test_name)
{
	if (actual < expected_min || expected_max < actual) {
		UNIT_WARNING(test_name, (expected_min + expected_max) / 2, actual, "%d");
		return false;
	}

	return true;
}

bool assert_null(void *actual, char *test_name)
{
	return assert_equals_ptr(NULL, actual, test_name);
}

bool assert_false(bool condition, char *test_name)
{
	if (condition) {
		log_warning("Test '%s' failed.", test_name);
		return false;
	}
	return true;
}

bool assert_not_equals_int(int expected, int actual, char *test_name)
{
	if (expected == actual) {
		UNIT_WARNING_NOT(test_name, expected, actual, "%d");
		return false;
	}
	return true;
}

bool assert_not_equals_u16(__u16 expected, __u16 actual, char *test_name)
{
	if (expected == actual) {
		UNIT_WARNING_NOT(test_name, expected, actual, "%u");
		return false;
	}
	return true;
}

bool assert_not_equals_ptr(void *expected, void *actual, char *test_name)
{
	if (expected == actual) {
		UNIT_WARNING_NOT(test_name, expected, actual, "%p");
		return false;
	}
	return true;
}

bool assert_not_null(void *actual, char *test_name)
{
	return assert_not_equals_ptr(NULL, actual, test_name);
}
