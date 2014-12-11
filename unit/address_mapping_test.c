/*
 * address_mapping_test.c
 *
 *  Created on: Dic 2, 2014
 *      Author: dhernandez
 */

#include <linux/module.h> /* Needed by all modules */
#include <linux/kernel.h> /* Needed for KERN_INFO */
#include <linux/init.h> /* Needed for the macros */

MODULE_LICENSE("GPL");
MODULE_AUTHOR("dhernandez");
MODULE_DESCRIPTION("Unit tests for the Address Mapping module");
MODULE_ALIAS("nat64_test_address_mapping");

#include "nat64/comm/str_utils.h"
#include "nat64/unit/types.h"
#include "nat64/unit/unit_test.h"
#include "../mod/address_mapping.c"

static const char* IPV4_ADDRS[] = { "10.0.0.0", "10.0.0.12", "10.0.0.8", "10.0.0.16", "10.0.0.254",
									"10.0.0.254", "10.0.1.0", "10.0.1.0", "10.0.0.0" };
static const __u8 IPV4_PREFIXES[] = { 30, 30, 28, 28, 32, 32, 24, 24, 30 };
static const char* IPV6_ADDRS[] = { "2001:db8::0", "2001:db8::4", "2001:db8::8", "2001:db8::11",
									"2001:db8::1", "2001:db8::111", "2001:db8::100", "2001:db8::200"
									, "2001:db8::0"};
static const __u8 IPV6_PREFIXES[] = { 126, 126, 124, 124, 128, 128, 120, 120, 128 };

static const int error_codes[] = { 0, 0, -EEXIST, 0, -EEXIST, 0, -EEXIST, 0, -EINVAL};

static struct ipv4_prefix pref4[ARRAY_SIZE(IPV4_ADDRS)];
static struct ipv6_prefix pref6[ARRAY_SIZE(IPV6_ADDRS)];

static bool init(void)
{
	int error;


	int i;

	for (i = 0; i < ARRAY_SIZE(IPV4_ADDRS); i++) {
		if (is_error(str_to_addr4(IPV4_ADDRS[i], &pref4[i].address)))
			goto fail;
		pref4[i].len = IPV4_PREFIXES[i];
	}

	for (i = 0; i < ARRAY_SIZE(IPV6_ADDRS); i++) {
		if (is_error(str_to_addr6(IPV6_ADDRS[i], &pref6[i].address)))
			goto fail;
		pref6[i].len = IPV6_PREFIXES[i];
	}

	error = address_mapping_init();
	if (error)
		goto fail;

	return true;

fail:
	return false;
}

static void end(void)
{
	address_mapping_destroy();
}

static bool insert_prefixes(void)
{
	int i;
	int error;
	bool result = true;
	for (i = 0; i < ARRAY_SIZE(IPV4_ADDRS); i++) {
		log_debug("Inserting prefixes #%d", i+1);
		error = address_mapping_insert_entry(&pref6[i], &pref4[i]);
		result &= assert_equals_int(error_codes[i], error, "inserting prefix");
	}

	return result;
}

static bool translate_6to4(struct in6_addr *addr6, struct in_addr *expected,
		struct in_addr *result)
{
	if (is_error(address_mapping_get_ipv4_by_ipv6(addr6, result)))
		return false;

	return assert_equals_ipv4(expected, result, "translate_6to4");
}

static bool translate_4to6(struct in_addr *addr, struct in6_addr *expected,
		struct in6_addr *result)
{
	if (is_error(address_mapping_get_ipv6_by_ipv4(addr, result)))
		return false;

	return assert_equals_ipv6(expected, result, "translate_4to6");
}

static bool translate_address(void)
{
	int i;
	bool result = true;

	char* ADDRS_4[] = { "10.0.0.2", "10.0.0.14", "10.0.0.27", "10.0.0.254", "10.0.1.15" };
	char* ADDRS_6[] = { "2001:db8::2", "2001:db8::6", "2001:db8::1B", "2001:db8::111",
									"2001:db8::20F" };
	struct in_addr expected_addr4[ARRAY_SIZE(ADDRS_4)], result_addr4[ARRAY_SIZE(ADDRS_4)];
	struct in6_addr expected_addr6[ARRAY_SIZE(ADDRS_6)], result_addr6[ARRAY_SIZE(ADDRS_6)];

	for (i = 0; i < ARRAY_SIZE(ADDRS_6); i++) {
		if (is_error(str_to_addr6(ADDRS_6[i], &expected_addr6[i])))
			return false;
	}

	for (i = 0; i < ARRAY_SIZE(ADDRS_4); i++) {
		if (is_error(str_to_addr4(ADDRS_4[i], &expected_addr4[i])))
			return false;
	}

	for (i = 0; i < ARRAY_SIZE(ADDRS_4); i++) {
		result &= translate_4to6(&expected_addr4[i], &expected_addr6[i], &result_addr6[i]);
	}

	for (i = 0; i < ARRAY_SIZE(ADDRS_6); i++) {
		result &= translate_6to4(&expected_addr6[i], &expected_addr4[i], &result_addr4[i]);
	}


	return result;
}

static bool general_test(void)
{
	bool result = true;

	result &= insert_prefixes();

	result &= translate_address();

	return result;
}


static int address_mapping_test_init(void)
{
	START_TESTS("Address Mapping test");

//	INIT_CALL_END(init(), simple_substraction(), end(), "test_log_time substraction 1");

	INIT_CALL_END(init(), general_test(), end(), "Test inserting address");

	END_TESTS;
}

static void address_mapping_test_exit(void)
{
	/* No code. */
}

module_init(address_mapping_test_init);
module_exit(address_mapping_test_exit);
