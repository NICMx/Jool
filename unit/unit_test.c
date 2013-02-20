#include <linux/kernel.h>
#include "nat64/mod/unit_test.h"


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

bool assert_equals_ipv6(struct in6_addr *expected, struct in6_addr *actual, char *test_name)
{
	if (!ipv6_addr_equals(expected, actual)) {
		UNIT_WARNING(test_name, expected, actual, "%pI6c");
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
