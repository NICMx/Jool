#include <linux/module.h>
#include <linux/inet.h>

#include "nat64/unit/unit_test.h"
#include "nat64/comm/str_utils.h"
#include "compute_outgoing_tuple.c"


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ramiro Nava <ramiro.nava@gmail.mx>");
MODULE_AUTHOR("Alberto Leiva <aleiva@nic.mx>");
MODULE_DESCRIPTION("Outgoing module test");


static char remote_ipv6_str[INET6_ADDRSTRLEN] = "2001:db8::1";
static char local_ipv6_str[INET6_ADDRSTRLEN] = "64:ff9b::c0a8:0002";
static char local_ipv4_str[INET_ADDRSTRLEN] = "203.0.113.1";
static char remote_ipv4_str[INET_ADDRSTRLEN] = "192.168.0.2";

static struct in6_addr remote_ipv6, local_ipv6;
static struct in_addr local_ipv4, remote_ipv4;


static bool add_bib(struct in_addr *ip4_addr, __u16 ip4_port, struct in6_addr *ip6_addr,
		__u16 ip6_port, l4_protocol l4_proto)
{
	/* Generate the BIB. */
	struct bib_entry *bib = kmalloc(sizeof(struct bib_entry), GFP_ATOMIC);
	if (!bib) {
		log_warning("Unable to allocate a dummy BIB.");
		goto failure;
	}

	bib->ipv4.address = *ip4_addr;
	bib->ipv4.l4_id = ip4_port;
	bib->ipv6.address = *ip6_addr;
	bib->ipv6.l4_id = ip6_port;
	INIT_LIST_HEAD(&bib->sessions);

	/*
	log_debug("BIB [%pI4#%u, %pI6c#%u]",
			&bib->ipv4.address, bib->ipv4.l4_id,
			&bib->ipv6.address, bib->ipv6.l4_id);
	*/

	/* Add it to the table. */
	if (bib_add(bib, l4_proto) != 0) {
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
	l4_protocol l4_protos[] = { L4PROTO_UDP, L4PROTO_TCP, L4PROTO_ICMP };
	int i;
	struct ipv6_prefix prefix;

	/* Init test addresses */
	if (str_to_addr6(remote_ipv6_str, &remote_ipv6) != 0) {
		log_warning("Can't parse address '%s'. Failing test...", remote_ipv6_str);
		return false;
	}
	if (str_to_addr6(local_ipv6_str, &local_ipv6) != 0) {
		log_warning("Can't parse address '%s'. Failing test...", local_ipv6_str);
		return false;
	}
	if (str_to_addr4(local_ipv4_str, &local_ipv4) != 0) {
		log_warning("Can't parse address '%s'. Failing test...", local_ipv4_str);
		return false;
	}
	if (str_to_addr4(remote_ipv4_str, &remote_ipv4) != 0) {
		log_warning("Can't parse address '%s'. Failing test...", remote_ipv4_str);
		return false;
	}

	/* Init the IPv6 pool module */
	if (pool6_init(NULL, 0) != 0) /* we'll use the defaults. */
		return false;
	if (str_to_addr6("64:ff9b::", &prefix.address) != 0) {
		log_warning("Cannot parse the IPv6 prefix. Failing...");
		return false;
	}
	prefix.len = 96;

	/* Init the BIB module */
	if (bib_init() != 0)
		return false;

	for (i = 0; i < ARRAY_SIZE(l4_protos); i++)
		if (!add_bib(&local_ipv4, 80, &remote_ipv6, 1500, l4_protos[i]))
			return false;

	return true;
}

/**
 * Frees from memory the stuff we created during init().
 */
static void cleanup(void)
{
	bib_destroy();
	pool6_destroy();
}

static bool test_6to4(l4_protocol l4_proto)
{
	struct tuple incoming, outgoing;
	bool success = true;

	incoming.src.addr.ipv6 = remote_ipv6;
	incoming.dst.addr.ipv6 = local_ipv6;
	incoming.src.l4_id = 1500; /* Lookup will use this. */
	incoming.dst.l4_id = 123; /* Whatever */
	incoming.l3_proto = L3PROTO_IPV6;
	incoming.l4_proto = l4_proto;

	if (l4_proto != L4PROTO_ICMP) {
		success &= assert_true(tuple5(&incoming, &outgoing), "Function call");
		success &= assert_equals_u16(80, outgoing.src.l4_id, "Source port");
		success &= assert_equals_u16(123, outgoing.dst.l4_id, "Destination port");
	} else {
		success &= assert_true(tuple3(&incoming, &outgoing), "Function call");
		success &= assert_equals_u16(80, outgoing.icmp_id, "ICMP ID");
	}
	success &= assert_equals_ipv4(&local_ipv4, &outgoing.src.addr.ipv4, "Source address");
	success &= assert_equals_ipv4(&remote_ipv4, &outgoing.dst.addr.ipv4, "Destination address");
	success &= assert_equals_u16(L3PROTO_IPV4, outgoing.l3_proto, "Layer-3 protocol");
	success &= assert_equals_u8(l4_proto, outgoing.l4_proto, "Layer-4 protocol");

	return success;
}

static bool test_4to6(l4_protocol l4_proto)
{
	struct tuple incoming, outgoing;
	bool success = true;

	incoming.src.addr.ipv4 = remote_ipv4;
	incoming.dst.addr.ipv4 = local_ipv4;
	incoming.src.l4_id = 123; /* Whatever */
	incoming.dst.l4_id = 80; /* Lookup will use this. */
	incoming.l3_proto = L3PROTO_IPV4;
	incoming.l4_proto = l4_proto;

	if (l4_proto != L4PROTO_ICMP) {
		success &= assert_true(tuple5(&incoming, &outgoing), "Function call");
		success &= assert_equals_u16(123, outgoing.src.l4_id, "Source port");
		success &= assert_equals_u16(1500, outgoing.dst.l4_id, "Destination port");
	} else {
		success &= assert_true(tuple3(&incoming, &outgoing), "Function call");
		success &= assert_equals_u16(1500, outgoing.icmp_id, "ICMP ID");
	}
	success &= assert_equals_ipv6(&local_ipv6, &outgoing.src.addr.ipv6, "Source address");
	success &= assert_equals_ipv6(&remote_ipv6, &outgoing.dst.addr.ipv6, "Destination address");
	success &= assert_equals_u16(L3PROTO_IPV6, outgoing.l3_proto, "Layer-3 protocol");
	success &= assert_equals_u8(l4_proto, outgoing.l4_proto, "Layer-4 protocol");

	return success;
}

int init_module(void)
{
	START_TESTS("Outgoing");

	if (!init())
		return -EINVAL;

	CALL_TEST(test_6to4(L4PROTO_UDP), "Tuple-5, 6 to 4, UDP");
	CALL_TEST(test_4to6(L4PROTO_UDP), "Tuple-5, 4 to 6, UDP");
	CALL_TEST(test_6to4(L4PROTO_TCP), "Tuple-5, 6 to 4, TCP");
	CALL_TEST(test_4to6(L4PROTO_TCP), "Tuple-5, 4 to 6, TCP");
	CALL_TEST(test_6to4(L4PROTO_ICMP), "Tuple-3, 6 to 4, ICMP");
	CALL_TEST(test_4to6(L4PROTO_ICMP), "Tuple-3, 4 to 6, ICMP");

	cleanup();

	END_TESTS;
}

void cleanup_module(void)
{
	/* No code. */
}
