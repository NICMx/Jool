#include <linux/module.h>

#include "nf_nat64_config.h"
#include "nf_nat64_ipv4_pool.h"
#include "unit_test.h"


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ramiro Nava");
MODULE_DESCRIPTION("POOL module test");


#define ASSERT_TRANSPORT_ADDR(expected_ip, expected_port, actual, test_name) \
		ASSERT_EQUALS_IPV4(expected_ips[expected_ip], actual->address, test_name ", address"); \
		ASSERT_EQUALS(expected_port, actual->port, test_name ", port")

const char* expected_ips_as_str[] = { "192.168.2.1", "192.168.2.2", "192.168.2.3" };
struct in_addr expected_ips[3];

static bool test_gets(void)
{
	int addr_ctr, port_ctr;
	struct transport_addr_struct *result;

	for (addr_ctr = 0; addr_ctr < 3; addr_ctr++) {
		for (port_ctr = 0; port_ctr < 2; port_ctr++) {
			result = get_udp_transport_addr();
			ASSERT_TRANSPORT_ADDR(addr_ctr, port_ctr, result, "Request addr");
		}
	}

	result = get_udp_transport_addr();
	ASSERT_NULL(result, "Request addr, pool ran out 1.");
	result = get_udp_transport_addr();
	ASSERT_NULL(result, "Request addr, pool ran out 2.");

	return true;
}

static bool test_returns(void)
{
	struct transport_addr_struct *result[6];

	log_debug("First get.");
	result[0] = get_udp_transport_addr();
	ASSERT_TRANSPORT_ADDR(0, 0, result[0], "First get");

	log_debug("Second get.");
	result[1] = get_udp_transport_addr();
	ASSERT_TRANSPORT_ADDR(0, 1, result[1], "Second get");

	log_debug("Third get.");
	result[2] = get_udp_transport_addr();
	ASSERT_TRANSPORT_ADDR(1, 0, result[2], "Third get");

	log_debug("Returning second one.");
	return_udp_transport_addr(result[1]);

	log_debug("Second get (again).");
	result[1] = get_udp_transport_addr();
	ASSERT_TRANSPORT_ADDR(0, 1, result[1], "Second get (again)");

	log_debug("Fourth get.");
	result[3] = get_udp_transport_addr();
	ASSERT_TRANSPORT_ADDR(1, 1, result[3], "Fourth get");

	log_debug("Fifth get.");
	result[4] = get_udp_transport_addr();
	ASSERT_TRANSPORT_ADDR(2, 0, result[4], "Fifth get");

	log_debug("Returning second, fourth and fifth ones.");
	return_udp_transport_addr(result[1]);
	return_udp_transport_addr(result[3]);
	return_udp_transport_addr(result[4]);

	log_debug("Second get (again again).");
	result[1] = get_udp_transport_addr();
	ASSERT_TRANSPORT_ADDR(0, 1, result[1], "Second get (again again)");

	log_debug("Fourth get (again).");
	result[3] = get_udp_transport_addr();
	ASSERT_TRANSPORT_ADDR(1, 1, result[3], "Fourth get (again)");

	log_debug("Returning second one (again again again).");
	return_udp_transport_addr(result[1]);

	log_debug("Second get (again again again).");
	result[1] = get_udp_transport_addr();
	ASSERT_TRANSPORT_ADDR(2, 0, result[1], "Second get (again again again)");

	log_debug("Fifth get (again).");
	result[4] = get_udp_transport_addr();
	ASSERT_TRANSPORT_ADDR(0, 1, result[4], "Fifth get (again)");

	return true;
}

static bool test_allocates(void)
{
	struct ipv4_tuple_address tuple_addr[4];
	struct transport_addr_struct transport_addr[4];

	const char *ip_not_in_pool_as_str = "192.168.2.7";
	struct in_addr ip_not_in_pool;
	struct transport_addr_struct *get_result[6];

	int counter;

	// Init test addresses.
	if (!str_to_addr4(ip_not_in_pool_as_str, &ip_not_in_pool)) {
		log_warning("Cannot parse test address '%s'. Failing...", ip_not_in_pool_as_str);
		return false;
	}

	tuple_addr[0].address = expected_ips[0];
	tuple_addr[0].pi.port = cpu_to_be16(0);
	tuple_addr[1].address = expected_ips[0];
	tuple_addr[1].pi.port = cpu_to_be16(1);
	tuple_addr[2].address = expected_ips[1];
	tuple_addr[2].pi.port = cpu_to_be16(0);
	tuple_addr[3].address = ip_not_in_pool;
	tuple_addr[3].pi.port = cpu_to_be16(0);

	for (counter = 0; counter < 4; counter++) {
		transport_addr[counter].address = tuple_addr[counter].address;
		transport_addr[counter].port = tuple_addr[counter].pi.port;
	}

	// Test allocate alone, also in combination with returns.
	for (counter = 0; counter < 2; counter++) {
		ASSERT_EQUALS(true, allocate_given_ipv4_transport_address(IPPROTO_UDP, &tuple_addr[1]),
				"Alloc 1.");
		ASSERT_EQUALS(true, allocate_given_ipv4_transport_address(IPPROTO_UDP, &tuple_addr[0]),
				"Alloc 2.");
		ASSERT_EQUALS(true, allocate_given_ipv4_transport_address(IPPROTO_UDP, &tuple_addr[2]),
				"Alloc 3.");
		ASSERT_EQUALS(false, allocate_given_ipv4_transport_address(IPPROTO_UDP, &tuple_addr[3]),
				"Alloc something not in pool.");

		ASSERT_EQUALS(false, allocate_given_ipv4_transport_address(IPPROTO_UDP, &tuple_addr[1]),
				"Alloc 1 again.");
		ASSERT_EQUALS(false, allocate_given_ipv4_transport_address(IPPROTO_UDP, &tuple_addr[0]),
				"Alloc 2 again.");
		ASSERT_EQUALS(false, allocate_given_ipv4_transport_address(IPPROTO_UDP, &tuple_addr[2]),
				"Alloc 3 again.");
		ASSERT_EQUALS(false, allocate_given_ipv4_transport_address(IPPROTO_UDP, &tuple_addr[3]),
				"Alloc something not in pool again.");

		return_udp_transport_addr(&transport_addr[0]);
		return_udp_transport_addr(&transport_addr[1]);
		return_udp_transport_addr(&transport_addr[2]);
	}

	// Test allocate after gets.
	get_result[0] = get_udp_transport_addr();
	ASSERT_TRANSPORT_ADDR(0, 0, get_result[0], "Get after returning alloc 1.");
	get_result[1] = get_udp_transport_addr();
	ASSERT_TRANSPORT_ADDR(0, 1, get_result[1], "Get after returning alloc 2.");

	ASSERT_EQUALS(false, allocate_given_ipv4_transport_address(IPPROTO_UDP, &tuple_addr[0]),
			"Alloc something already get'd 1.");
	ASSERT_EQUALS(false, allocate_given_ipv4_transport_address(IPPROTO_UDP, &tuple_addr[1]),
			"Alloc something already get'd 2.");
	ASSERT_EQUALS(true, allocate_given_ipv4_transport_address(IPPROTO_UDP, &tuple_addr[2]),
			"Alloc something not get'd.");
	ASSERT_EQUALS(false, allocate_given_ipv4_transport_address(IPPROTO_UDP, &tuple_addr[2]),
			"Alloc something already alloc'd.");

	return_udp_transport_addr(&transport_addr[0]);
	return_udp_transport_addr(&transport_addr[1]);
	return_udp_transport_addr(&transport_addr[2]);

	// Test gets after allocate.
	ASSERT_EQUALS(true, allocate_given_ipv4_transport_address(IPPROTO_UDP, &tuple_addr[1]),
			"Allocate to test gets.");
	get_result[0] = get_udp_transport_addr();
	ASSERT_TRANSPORT_ADDR(0, 0, get_result[0], "Get after alloc, unaffected.");
	get_result[2] = get_udp_transport_addr();
	ASSERT_TRANSPORT_ADDR(1, 0, get_result[2], "Get after alloc, should skip.");

	return_udp_transport_addr(&transport_addr[0]);
	return_udp_transport_addr(&transport_addr[1]);
	return_udp_transport_addr(&transport_addr[2]);

	return true;
}

static bool test_function_get_new_port(void)
{
	return true;
}

static bool init(void)
{
	int addr_ctr;

	if (!nat64_config_init()) {
		log_warning("Could not load the default config. Failing...");
		return false;
	}
	init_pools(&cs);

	for (addr_ctr = 0; addr_ctr < 3; addr_ctr++)
		if (!str_to_addr4(expected_ips_as_str[addr_ctr], &expected_ips[addr_ctr])) {
			log_warning("Cannot parse test address '%s'. Failing.", expected_ips_as_str[addr_ctr]);
			return false;
		}

	return true;
}

static void destroy(void)
{
//	destroy_pools();
}

int init_module(void){
	START_TESTS("Pool");

//	INIT_CALL_END(init(), test_gets(), destroy(), "Get functions.");
	INIT_CALL_END(init(), test_returns(), destroy(), "Return functions.");
//	INIT_CALL_END(init(), test_allocates(), destroy(), "Allocate functions.");
//	INIT_CALL_END(init(), test_function_get_new_port(), destroy(), "Allocate functions.");

	END_TESTS;
}
void cleanup_module(void)
{
	// Sin código.
}
