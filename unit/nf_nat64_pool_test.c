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
	ASSERT_TRANSPORT_ADDR(0, 1, result[1], "Second get (again again again)");

	log_debug("Fifth get (again).");
	result[4] = get_udp_transport_addr();
	ASSERT_TRANSPORT_ADDR(2, 0, result[4], "Fifth get (again)");

	return true;
}

static bool test_allocates(void)
{
	struct ipv4_tuple_address addr;
	const char *ip_not_in_pool_as_str = "192.168.2.7";
	struct in_addr ip_in_pool = expected_ips[0], ip_not_in_pool;
	struct transport_addr_struct *get_result[6];

	if (!str_to_addr4(ip_not_in_pool_as_str, &ip_not_in_pool)) {
		log_warning("Cannot parse test address '%s'. Failing...", ip_not_in_pool_as_str);
		return false;
	}

	addr.address = ip_in_pool;
	addr.pi.port = cpu_to_be16(1);
	ASSERT_EQUALS(true, allocate_given_ipv4_transport_address(IPPROTO_UDP, &addr),
			"Pool is full, requesting address in pool.");

	addr.address = ip_not_in_pool;
	ASSERT_EQUALS(false, allocate_given_ipv4_transport_address(IPPROTO_UDP, &addr),
			"Requesting address not in pool.");

	get_result[0] = get_udp_transport_addr();
	ASSERT_TRANSPORT_ADDR(0, 0, get_result[0], "Get after allocate; unaffected.");
	get_result[2] = get_udp_transport_addr();
	ASSERT_TRANSPORT_ADDR(1, 0, get_result[2], "Get after allocate; skip the allocated one.");

	return true;
}

static bool init(void)
{
	int addr_ctr;

	if (!nat64_load_default_config()) {
		log_warning("Could not load the default config. Failing...");
		return false;
	}
	if (!init_pools()) {
		log_warning("Could not init the pools. Failing...");
		return false;
	}

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
//	INIT_CALL_END(init(), test_returns(), destroy(), "Return functions.");
	INIT_CALL_END(init(), test_allocates(), destroy(), "Allocate functions.");

	END_TESTS;
}
void cleanup_module(void)
{
	// Sin código.
}
