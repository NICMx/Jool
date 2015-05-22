#include "nat64/unit/unit_test.h"

#include <linux/kernel.h>
#include <net/ipv6.h>
#include "nat64/common/str_utils.h"

bool __ASSERT_ADDR4(const struct in_addr *expected,
		const struct in_addr *actual,
		const char *test_name)
{
	if (expected == actual)
		return true;

	if (!expected || !actual || expected->s_addr != actual->s_addr) {
		log_err("Test '%s' failed. Expected:%pI4 Actual:%pI4",
				test_name, expected, actual);
		return false;
	}

	return true;
}

bool ASSERT_ADDR4(const char *expected_str, const struct in_addr *actual,
		const char *test_name)
{
	struct in_addr expected;

	if (!expected_str)
		return __ASSERT_ADDR4(NULL, actual, test_name);

	return str_to_addr4(expected_str, &expected)
			? false
			: __ASSERT_ADDR4(&expected, actual, test_name);
}

bool __ASSERT_ADDR6(const struct in6_addr *expected,
		const struct in6_addr *actual,
		const char *test_name)
{
	if (expected == actual)
		return true;

	if (!expected || !actual || ipv6_addr_cmp(expected, actual)) {
		log_err("Test '%s' failed. Expected:%pI6c Actual:%pI6c",
				test_name, expected, actual);
		return false;
	}

	return true;
}

bool ASSERT_ADDR6(const char *expected_str, const struct in6_addr *actual,
		const char *test_name)
{
	struct in6_addr expected;

	if (!expected_str)
		return __ASSERT_ADDR6(NULL, actual, test_name);

	return str_to_addr6(expected_str, &expected)
			? false
			: __ASSERT_ADDR6(&expected, actual, test_name);
}

#define BIB_KEY "BIB [%pI4#%u, %pI6c#%u]"
#define BIB_PRINT(bib) &bib->ipv4.l3, bib->ipv4.l4, &bib->ipv6.l3, bib->ipv6.l4

bool ASSERT_BIB(struct bib_entry* expected, struct bib_entry* actual,
		char *test_name)
{
	if (expected == actual)
		return true;

	if (!expected) {
		log_err("Test '%s' failed: Expected:NULL Actual:" BIB_KEY,
				test_name, BIB_PRINT(actual));
		return false;
	}
	if (!actual) {
		log_err("Test '%s' failed: Expected:" BIB_KEY " Actual:NULL",
				test_name, BIB_PRINT(expected));
		return false;
	}

	if (!ipv4_transport_addr_equals(&expected->ipv4, &actual->ipv4)
			|| !ipv6_transport_addr_equals(&expected->ipv6, &actual->ipv6)) {
		log_err("Test '%s' failed: Expected:" BIB_KEY
				" Actual:" BIB_KEY, test_name,
				BIB_PRINT(expected), BIB_PRINT(actual));
		return false;
	}

	return true;
}

#undef BIB_PRINT
#undef BIB_KEY
