#include <linux/module.h>
#include <linux/inet.h>
#include <net/ipv6.h>
#include <net/netfilter/nf_conntrack_tuple.h>

#include "unit_test.h"
#include "nf_nat64_outgoing.c"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ramiro Nava <ramiro.nava@gmail.mx>");
MODULE_AUTHOR("Alberto Leiva <aleiva@nic.mx>");
MODULE_DESCRIPTION("Outgoing module test");


char remote_ipv6_str[INET6_ADDRSTRLEN] = "2001:db8::1";
char local_ipv6_str[INET6_ADDRSTRLEN] = "64:ff9b::c0a8:0002";
char local_ipv4_str[INET_ADDRSTRLEN] = "203.0.113.1";
char remote_ipv4_str[INET_ADDRSTRLEN] = "192.168.0.2";

struct in6_addr remote_ipv6, local_ipv6;
struct in_addr local_ipv4, remote_ipv4;


static bool add_bib(struct in_addr *ip4_addr, __u16 ip4_port, struct in6_addr *ip6_addr,
		__u16 ip6_port, u_int8_t l4protocol)
{
	// Generate the BIB.
	struct bib_entry *bib = kmalloc(sizeof(struct bib_entry), GFP_ATOMIC);
	if (!bib) {
		log_warning("Unable to allocate a dummy BIB.");
		goto failure;
	}

	bib->ipv4.address = *ip4_addr;
	bib->ipv4.pi.port = cpu_to_be16(ip4_port);
	bib->ipv6.address = *ip6_addr;
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
static bool init(void)
{
	u_int8_t protocols[] = { IPPROTO_UDP, IPPROTO_TCP, IPPROTO_ICMP };
	int i;

	// Init test addresses
	if (!str_to_addr6(remote_ipv6_str, &remote_ipv6)) {
		log_warning("Can't parse address '%s'. Failing test...", remote_ipv6_str);
		return false;
	}
	if (!str_to_addr6(local_ipv6_str, &local_ipv6)) {
		log_warning("Can't parse address '%s'. Failing test...", local_ipv6_str);
		return false;
	}
	if (!str_to_addr4(local_ipv4_str, &local_ipv4)) {
		log_warning("Can't parse address '%s'. Failing test...", local_ipv4_str);
		return false;
	}
	if (!str_to_addr4(remote_ipv4_str, &remote_ipv4)) {
		log_warning("Can't parse address '%s'. Failing test...", remote_ipv4_str);
		return false;
	}

	// Init the BIB module
	nat64_bib_init();

	for (i = 0; i < ARRAY_SIZE(protocols); i++)
		if (!add_bib(&local_ipv4, 80, &remote_ipv6, 1500, protocols[i]))
			return false;

	return true;
}

/**
 * Frees from memory the stuff we created during init().
 */
static void cleanup(void)
{
	nat64_bib_destroy();
}

static bool test_6to4(
		bool (*function)(struct nf_conntrack_tuple *, struct nf_conntrack_tuple *,
				enum translation_mode),
		u_int8_t in_l3_protocol, u_int8_t out_l3_protocol)
{
	struct nf_conntrack_tuple incoming, outgoing;
	bool success = true;

	incoming.ipv6_src_addr = remote_ipv6;
	incoming.ipv6_dst_addr = local_ipv6;
	incoming.src_port = cpu_to_be16(1500); // Lookup will use this.
	incoming.dst_port = cpu_to_be16(123); // Whatever
	incoming.L3_PROTOCOL = NFPROTO_IPV6;
	incoming.L4_PROTOCOL = in_l3_protocol;

	success &= assert_true(function(&outgoing, &incoming, IPV6_TO_IPV4), "Function call");
	success &= assert_equals_ipv4(&local_ipv4, &outgoing.ipv4_src_addr, "Source address");
	success &= assert_equals_ipv4(&remote_ipv4, &outgoing.ipv4_dst_addr, "Destination address");
	success &= assert_equals_u16(NFPROTO_IPV4, outgoing.L3_PROTOCOL, "Layer-3 protocol");
	success &= assert_equals_u8(out_l3_protocol, outgoing.L4_PROTOCOL, "Layer-4 protocol");
	// TODO (test) need to test ports?

	return success;
}

static bool test_4to6(
		bool (*function)(struct nf_conntrack_tuple *, struct nf_conntrack_tuple *,
				enum translation_mode),
		u_int8_t in_l3_protocol, u_int8_t out_l3_protocol)
{
	struct nf_conntrack_tuple incoming, outgoing;
	bool success = true;

	incoming.ipv4_src_addr = remote_ipv4;
	incoming.ipv4_dst_addr = local_ipv4;
	incoming.src_port = cpu_to_be16(123); // Whatever
	incoming.dst_port = cpu_to_be16(80); // Lookup will use this.
	incoming.L3_PROTOCOL = NFPROTO_IPV4;
	incoming.L4_PROTOCOL = in_l3_protocol;

	success &= assert_true(function(&outgoing, &incoming, IPV4_TO_IPV6), "Function call");
	success &= assert_equals_ipv6(&local_ipv6, &outgoing.ipv6_src_addr, "Source address");
	success &= assert_equals_ipv6(&remote_ipv6, &outgoing.ipv6_dst_addr, "Destination address");
	success &= assert_equals_u16(NFPROTO_IPV6, outgoing.L3_PROTOCOL, "Layer-3 protocol");
	success &= assert_equals_u8(out_l3_protocol, outgoing.L4_PROTOCOL, "Layer-4 protocol");
	// TODO (test) need to test ports?

	return success;
}

int init_module(void)
{
	START_TESTS("Outgoing");

	if (!init())
		return -EINVAL;

	// I don't want to throw this into loops because it gets kind of messy.
	CALL_TEST(test_6to4(nat64_compute_outgoing_tuple_tuple5, IPPROTO_UDP, IPPROTO_UDP),
			"Tuple-5, 6 to 4, UDP");
	CALL_TEST(test_4to6(nat64_compute_outgoing_tuple_tuple5, IPPROTO_UDP, IPPROTO_UDP),
			"Tuple-5, 4 to 6, UDP");
	CALL_TEST(test_6to4(nat64_compute_outgoing_tuple_tuple5, IPPROTO_TCP, IPPROTO_TCP),
			"Tuple-5, 6 to 4, TCP");
	CALL_TEST(test_4to6(nat64_compute_outgoing_tuple_tuple5, IPPROTO_TCP, IPPROTO_TCP),
			"Tuple-5, 4 to 6, TCP");
	CALL_TEST(test_6to4(nat64_compute_outgoing_tuple_tuple5, NEXTHDR_ICMP, IPPROTO_ICMP),
			"Tuple-5, 6 to 4, ICMP");
	CALL_TEST(test_4to6(nat64_compute_outgoing_tuple_tuple5, IPPROTO_ICMP, NEXTHDR_ICMP),
			"Tuple-5, 4 to 6, ICMP");

	CALL_TEST(test_6to4(nat64_compute_outgoing_tuple_tuple3, NEXTHDR_ICMP, IPPROTO_ICMP),
			"Tuple-3, 6 to 4, ICMP");
	CALL_TEST(test_4to6(nat64_compute_outgoing_tuple_tuple3, IPPROTO_ICMP, NEXTHDR_ICMP),
			"Tuple-3, 4 to 6, ICMP");

	cleanup();

	END_TESTS;
}

void cleanup_module(void)
{
	// No code.
}
