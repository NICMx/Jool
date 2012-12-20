#include <linux/module.h>
#include <linux/inet.h>
#include <net/netfilter/nf_conntrack_tuple.h>

#include "unit_test.h"
#include "nf_nat64_outgoing.c"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ramiro Nava <ramiro.nava@gmail.mx>");
MODULE_DESCRIPTION("Outgoing module test");

bool add_bib(char *ip4_addr, __u16 ip4_port, char *ip6_addr, __u16 ip6_port, u_int8_t l4protocol)
{
	// Generate the BIB.
	struct bib_entry *bib = kmalloc(sizeof(struct bib_entry), GFP_ATOMIC);
	if (!bib) {
		log_warning("Unable to allocate a dummy BIB.");
		goto failure;
	}

	bib->ipv4.address.s_addr = in_aton(ip4_addr);
	bib->ipv4.pi.port = cpu_to_be16(ip4_port);
	in6_pton(ip6_addr, -1, (u8 *) &bib->ipv6.address, '\\', NULL);
	bib->ipv6.pi.port = cpu_to_be16(ip6_port);
	INIT_LIST_HEAD(&bib->session_entries);

	//	log_debug("BIB [%pI4#%d, %pI6c#%d]",
	//			&bib->ipv4.address, be16_to_cpu(bib->ipv4.pi.port),
	//			&bib->ipv6.address, be16_to_cpu(bib->ipv6.pi.port));

	// Add it to the table.
	if (!nat64_add_bib_entry(bib, l4protocol)) {
		log_warning("Can't add the dummy BIB to the table.");
		goto failure;
	}

	return true;

failure:
	kfree(bib);
	return false;
}

/**
 * Prepares the environment for the tests.
 *
 * @return whether the initialization was successful or not. An error message has been printed to
 *		the kernel ring buffer.
 */
bool init(void)
{
	u_int8_t protocols[] = { IPPROTO_UDP, IPPROTO_TCP, IPPROTO_ICMP };
	int i;

	nat64_bib_init();

	for (i = 0; i < ARRAY_SIZE(protocols); i++) {
		if (!add_bib("203.0.113.1", 2000, "2001:db8::1", 1500, protocols[i]))
			return false;
		if (!add_bib("192.168.0.2", 80, "64:ff9b::c0a8:0002", 80, protocols[i]))
			return false;
	}

	return true;
}

/**
 * Frees from memory the stuff we created during init().
 */
void cleanup(void)
{
	nat64_bib_destroy();
}

bool test_tuple5_function(void)
{
	struct nf_conntrack_tuple outgoing_tuple, incoming_tuple, expected, esperado, expected6;
	enum translation_mode mode;
	bool test = false;
	//Generar incoming tuple con datos
	char src_ipv6[INET6_ADDRSTRLEN] = "2001:db8::1";
	char dst_ipv6[INET6_ADDRSTRLEN] = "64:ff9b::c0a8:0002";
	char src_ipv4[INET_ADDRSTRLEN] = "192.168.0.2";
	char dst_ipv4[INET_ADDRSTRLEN] = "203.0.113.1";

	in6_pton(src_ipv6, -1, (u8 *) &(incoming_tuple.ipv6_src_addr), '\\', NULL);
	in6_pton(dst_ipv6, -1, (u8 *) &(incoming_tuple.ipv6_dst_addr), '\\', NULL);

	incoming_tuple.src_port = cpu_to_be16(1500);
	incoming_tuple.dst_port = cpu_to_be16(80);

	log_warning("Incoming ip src: %pI6c. puerto: %d  \n",
			&incoming_tuple.ipv6_src_addr, incoming_tuple.src_port);
	log_warning("Incoming ip dst: %pI6c. puerto: %d  \n",
			&incoming_tuple.ipv6_dst_addr, incoming_tuple.dst_port);

	incoming_tuple.L3_PROTOCOL = 10;
	incoming_tuple.L4_PROTOCOL = IPPROTO_UDP;

	mode = IPV6_TO_IPV4;

	test = nat64_compute_outgoing_tuple_tuple5(&outgoing_tuple, &incoming_tuple, mode);

	in4_pton(src_ipv4, -1, (u8 *) &(expected.ipv4_src_addr), '\\', NULL);
	in4_pton(dst_ipv4, -1, (u8 *) &(esperado.ipv4_dst_addr), '\\', NULL);
	ASSERT_EQUALS_IPV4(esperado.ipv4_dst_addr, outgoing_tuple.ipv4_src_addr, "6-->4");
	ASSERT_EQUALS_IPV4(expected.ipv4_src_addr, outgoing_tuple.ipv4_dst_addr, "6-->4");

	if (test) {

		in4_pton(src_ipv4, -1, (u8 *) &(incoming_tuple.ipv4_src_addr), '\\', NULL);
		in4_pton(dst_ipv4, -1, (u8 *) &(incoming_tuple.ipv4_dst_addr), '\\', NULL);
		log_warning("Incoming ip src: %pI4. puerto: %d  \n",
				&incoming_tuple.ipv4_src_addr, incoming_tuple.src_port);
		log_warning("Incoming ip src: %pI4. puerto: %d  \n",
				&incoming_tuple.ipv4_dst_addr, incoming_tuple.dst_port);

		mode = IPV4_TO_IPV6;
		test = nat64_compute_outgoing_tuple_tuple5(&outgoing_tuple, &incoming_tuple, mode);

		in6_pton(src_ipv6, -1, (u8 *) &(expected.ipv6_src_addr), '\\', NULL);
		in6_pton(dst_ipv6, -1, (u8 *) &(expected6.ipv6_dst_addr), '\\', NULL);
		ASSERT_EQUALS_IPV6(expected.ipv6_src_addr, outgoing_tuple.ipv6_src_addr, "4-->6");
		ASSERT_EQUALS_IPV6(expected6.ipv6_dst_addr, outgoing_tuple.ipv6_dst_addr, "4-->6");

	}

	return test;
}

bool test_tuple3_function(void)
{
	struct nf_conntrack_tuple outgoing_tuple, incoming_tuple, expected, expected6, esperado;
	enum translation_mode mode;
	bool test = false;
	//Generar incoming tuple con datos
	char src_ipv6[INET6_ADDRSTRLEN] = "2001:db8::1";
	char dst_ipv6[INET6_ADDRSTRLEN] = "64:ff9b::c0a8:0002";
	char src_ipv4[INET_ADDRSTRLEN] = "192.168.0.2";
	char dst_ipv4[INET_ADDRSTRLEN] = "203.0.113.1";

	in6_pton(src_ipv6, -1, (u8 *) &(incoming_tuple.ipv6_src_addr), '\\', NULL);
	in6_pton(dst_ipv6, -1, (u8 *) &(incoming_tuple.ipv6_dst_addr), '\\', NULL);

	incoming_tuple.icmp_id = cpu_to_be16(1500);
	// incoming_tuple.dst_id = cpu_to_be16(80);

	incoming_tuple.L3_PROTOCOL = 10;
	incoming_tuple.L4_PROTOCOL = IPPROTO_ICMPV6;

	mode = IPV6_TO_IPV4;

	test = nat64_compute_outgoing_tuple_tuple3(&outgoing_tuple, &incoming_tuple, mode);

	/*assert*/
	in4_pton(src_ipv4, -1, (u8 *) &(expected.ipv4_src_addr), '\\', NULL);
	in4_pton(dst_ipv4, -1, (u8 *) &(esperado.ipv4_dst_addr), '\\', NULL);
	ASSERT_EQUALS_IPV4(esperado.ipv4_dst_addr, outgoing_tuple.ipv4_src_addr, "6-->4");
	ASSERT_EQUALS_IPV4(expected.ipv4_src_addr, outgoing_tuple.ipv4_dst_addr, "6-->4");

	/**/
	if (test) {

		in4_pton(src_ipv4, -1, (u8 *) &(incoming_tuple.ipv4_src_addr), '\0', NULL);
		in4_pton(dst_ipv4, -1, (u8 *) &(incoming_tuple.ipv4_dst_addr), '\0', NULL);
		log_warning("Incoming ip src: %pI4. puerto: %d  \n",
				&incoming_tuple.ipv4_src_addr, incoming_tuple.src_port);
		log_warning("Incoming ip src: %pI4. puerto: %d  \n",
				&incoming_tuple.ipv4_dst_addr, incoming_tuple.dst_port);
		incoming_tuple.L4_PROTOCOL = IPPROTO_ICMP;
		mode = IPV4_TO_IPV6;
		test = nat64_compute_outgoing_tuple_tuple3(&outgoing_tuple, &incoming_tuple, mode);

		in6_pton(src_ipv6, -1, (u8 *) &(expected.ipv6_src_addr), '\\', NULL);
		in6_pton(dst_ipv6, -1, (u8 *) &(expected6.ipv6_dst_addr), '\\', NULL);
		ASSERT_EQUALS_IPV6(expected.ipv6_src_addr, outgoing_tuple.ipv6_src_addr, "4-->6");
		ASSERT_EQUALS_IPV6(expected6.ipv6_dst_addr, outgoing_tuple.ipv6_dst_addr, "4-->6");
	}

	return test;
}

int init_module(void)
{
	START_TESTS("Outgoing");

	if (!init())
		return -EINVAL;

	CALL_TEST(test_tuple5_function(), "Tuple 5 function");
	CALL_TEST(test_tuple3_function(), "Tuple 3 function");

	cleanup();

	END_TESTS;
}

void cleanup_module(void)
{
	// No code.
}
