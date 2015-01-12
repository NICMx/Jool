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
#include "../mod/stateless/eam.c"

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

	error = eamt_init();
	if (error)
		goto fail;

	return true;

fail:
	return false;
}

static void end(void)
{
	eamt_destroy();
}

static bool insert_prefixes(void)
{
	int i;
	int error;
	bool result = true;
	for (i = 0; i < ARRAY_SIZE(IPV4_ADDRS); i++) {
		log_debug("Inserting prefixes #%d", i+1);
		error = eamt_add(&pref6[i], &pref4[i]);
		result &= assert_equals_int(error_codes[i], error, "inserting prefix");
	}

	return result;
}

static bool translate_6to4(struct in6_addr *addr6, struct in_addr *expected,
		struct in_addr *result)
{
	if (is_error(eamt_get_ipv4_by_ipv6(addr6, result)))
		return false;

	return assert_equals_ipv4(expected, result, "translate_6to4");
}

static bool translate_4to6(struct in_addr *addr, struct in6_addr *expected,
		struct in6_addr *result)
{
	if (is_error(eamt_get_ipv6_by_ipv4(addr, result)))
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

static bool add_entry(char *addr4, __u8 len4, char *addr6, __u8 len6)
{
	struct ipv4_prefix prefix4;
	struct ipv6_prefix prefix6;

	if (str_to_addr4(addr4, &prefix4.address))
		return false;
	prefix4.len = len4;

	if (str_to_addr6(addr6, &prefix6.address))
		return false;
	prefix6.len = len6;

	if (eamt_add(&prefix6, &prefix4)) {
		log_err("The call to eamt_add() failed.");
		return false;
	}

	return true;
}

static bool test(char *addr4_str, char *addr6_str)
{
	struct in_addr addr4, result4;
	struct in6_addr addr6, result6;
	int error1, error2;
	bool success = true;

	log_debug("Testing %s <-> %s...", addr4_str, addr6_str);

	if (str_to_addr4(addr4_str, &addr4))
		return false;
	if (str_to_addr6(addr6_str, &addr6))
		return false;

	error1 = eamt_get_ipv6_by_ipv4(&addr4, &result6);
	error2 = eamt_get_ipv4_by_ipv6(&addr6, &result4);
	if (error1 || error2) {
		log_err("The call to eamt_get_ipv6_by_ipv4() spew errcode %d.", error1);
		log_err("The call to eamt_get_ipv4_by_ipv6() spew errcode %d.", error2);
		return false;
	}

	success &= assert_equals_ipv6(&addr6, &result6, "IPv4 to IPv6 result");
	success &= assert_equals_ipv4(&addr4, &result4, "IPv6 to IPv4 result");
	return success;
}

static bool anderson_test(void)
{
	bool success = true;

	success &= add_entry("192.0.2.1", 32, "2001:db8:aaaa::", 128);
	success &= add_entry("192.0.2.2", 32, "2001:db8:bbbb::b", 128);
	success &= add_entry("192.0.2.16", 28, "2001:db8:cccc::", 124);
	success &= add_entry("192.0.2.128", 26, "2001:db8:dddd::", 64);
	success &= add_entry("192.0.2.192", 31, "64:ff9b::", 127);
	if (!success)
		return false;

	success &= test("192.0.2.1", "2001:db8:aaaa::");
	success &= test("192.0.2.2", "2001:db8:bbbb::b");
	success &= test("192.0.2.16", "2001:db8:cccc::");
	success &= test("192.0.2.24", "2001:db8:cccc::8");
	success &= test("192.0.2.31", "2001:db8:cccc::f");
	success &= test("192.0.2.128", "2001:db8:dddd::");
	success &= test("192.0.2.152", "2001:db8:dddd:0:6000::");
	success &= test("192.0.2.183", "2001:db8:dddd:0:dc00::");
	success &= test("192.0.2.191", "2001:db8:dddd:0:fc00::");
	success &= test("192.0.2.193", "64:ff9b::1");

	return success;
}

static bool remove_entry(char *addr4, __u8 len4, char *addr6, __u8 len6, int expected_error)
{
	struct ipv4_prefix prefix4;
	struct ipv6_prefix prefix6;

	if (!addr4 && !addr6) {
		log_err("Test syntax error, addr4 and addr6 are NULL");
	}

	if (addr4) {
		if (is_error(str_to_addr4(addr4, &prefix4.address)))
			return false;
		prefix4.len = len4;
	}

	if (addr6) {
		if (is_error(str_to_addr6(addr6, &prefix6.address)))
			return false;
		prefix6.len = len6;
	}

	return assert_equals_int(expected_error, eamt_remove(addr6 ? &prefix6 : NULL,
			addr4 ? &prefix4 : NULL), "removing EAM entry");
}

static bool remove_test(void)
{
	bool success = true;

	success &= add_entry("10.0.0.0", 24, "1::", 120);
	success &= remove_entry("10.0.0.0", 24, "1::", 120, 0);

	success &= add_entry("20.0.0.0", 25, "2::", 121);
	success &= remove_entry("30.0.0.1", 25, NULL, 0, -ESRCH);
	success &= remove_entry("20.0.0.130", 25, NULL, 0, -ESRCH);
	success &= remove_entry("20.0.0.120", 25, NULL, 0, 0);

	success &= add_entry("30.0.0.0", 24, "3::", 120);
	success &= remove_entry(NULL, 0, "3::1:0", 120, -ESRCH);
	success &= remove_entry(NULL, 0, "3::0", 120, 0);

	success &= add_entry("10.0.0.0", 24, "1::", 120);
	success &= remove_entry("10.0.1.0", 24, "1::", 120, -EINVAL);
	success &= remove_entry("10.0.0.0", 24, "1::", 120, 0);

	success &= assert_equals_u64(0, eam_table.count, "Table count");
	if (!success)
		return false;

	success &= insert_prefixes();
	if (!success)
		return false;

	eamt_flush();
	success &= assert_equals_u64(0, eam_table.count, "Table count 2");

	return success;
}

static int address_mapping_test_init(void)
{
	START_TESTS("Address Mapping test");

	INIT_CALL_END(init(), general_test(), end(), "Test inserting address");
	INIT_CALL_END(init(), anderson_test(), end(), "Tests from T. Anderson's 3rd draft.");
	INIT_CALL_END(init(), remove_test(), end(), "Test removing address.");

	END_TESTS;
}

static void address_mapping_test_exit(void)
{
	/* No code. */
}

module_init(address_mapping_test_init);
module_exit(address_mapping_test_exit);
