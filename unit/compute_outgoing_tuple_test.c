#include <linux/module.h>
#include <linux/inet.h>

#include "nat64/unit/unit_test.h"
#include "nat64/comm/str_utils.h"
#include "nat64/mod/bib_db.h"
#include "nat64/mod/compute_outgoing_tuple.h"


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
	struct bib_entry *bib;
	struct ipv6_transport_addr addr6;
	struct ipv4_transport_addr addr4;

	/* Generate the BIB. */
	addr4.l3 = *ip4_addr;
	addr4.l4 = ip4_port;
	addr6.l3 = *ip6_addr;
	addr6.l4 = ip6_port;

	bib = bib_create(&addr4, &addr6, false, l4_proto);
	if (!bib) {
		log_err("Can't allocate a BIB entry!");
		return false;
	}

	/*
	log_debug("BIB [%pI4#%u, %pI6c#%u]",
			&bib->ipv4.address, bib->ipv4.l4_id,
			&bib->ipv6.address, bib->ipv6.l4_id);
	*/

	/* Add it to the table. */
	if (is_error(bibdb_add(bib))) {
		log_err("Can't add the dummy BIB to the table.");
		bib_kfree(bib);
		return false;
	}

	return true;
}

/**
 * Prepares the environment for the tests.
 *
 * @return whether the initialization was successful or not.
 */
static bool init(void)
{
	l4_protocol l4_protos[] = { L4PROTO_UDP, L4PROTO_TCP, L4PROTO_ICMP };
	int i;
	struct ipv6_prefix prefix;

	/* Init test addresses */
	if (str_to_addr6(remote_ipv6_str, &remote_ipv6) != 0)
		return false;
	if (str_to_addr6(local_ipv6_str, &local_ipv6) != 0)
		return false;
	if (str_to_addr4(local_ipv4_str, &local_ipv4) != 0)
		return false;
	if (str_to_addr4(remote_ipv4_str, &remote_ipv4) != 0)
		return false;

	/* Init the IPv6 pool module */
	if (str_to_addr6("64:ff9b::", &prefix.address) != 0) {
		log_err("Cannot parse the IPv6 prefix. Failing...");
		return false;
	}
	prefix.len = 96;

	/* Init the BIB module */
	if (is_error(bibdb_init()))
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
	bibdb_destroy();
}

static bool test_6to4(l4_protocol l4_proto)
{
	struct tuple incoming, outgoing;
	bool success = true;
	int field = 0;

	incoming.src.addr6.l3 = remote_ipv6;
	incoming.dst.addr6.l3 = local_ipv6;
	incoming.src.addr6.l4 = 1500; /* Lookup will use this. */
	incoming.dst.addr6.l4 = 123; /* Whatever */
	incoming.l3_proto = L3PROTO_IPV6;
	incoming.l4_proto = l4_proto;

	success &= assert_equals_int(VER_CONTINUE, compute_out_tuple(&incoming, &outgoing, &field), "Function call");
	success &= assert_equals_u16(80, outgoing.src.addr4.l4, "Source port");

	if (l4_proto != L4PROTO_ICMP)
		success &= assert_equals_u16(123, outgoing.dst.addr4.l4, "Destination port");
	else
		success &= assert_equals_u16(80, outgoing.dst.addr4.l4, "ICMP ID");
	success &= assert_equals_ipv4(&local_ipv4, &outgoing.src.addr4.l3, "Source address");
	success &= assert_equals_ipv4(&remote_ipv4, &outgoing.dst.addr4.l3, "Destination address");
	success &= assert_equals_u16(L3PROTO_IPV4, outgoing.l3_proto, "Layer-3 protocol");
	success &= assert_equals_u8(l4_proto, outgoing.l4_proto, "Layer-4 protocol");

	return success;
}

static bool test_4to6(l4_protocol l4_proto)
{
	struct tuple incoming, outgoing;
	bool success = true;
	int field = 0;

	incoming.src.addr4.l3 = remote_ipv4;
	incoming.dst.addr4.l3 = local_ipv4;
	incoming.src.addr4.l4 = 123; /* Whatever */
	incoming.dst.addr4.l4 = 80; /* Lookup will use this. */
	incoming.l3_proto = L3PROTO_IPV4;
	incoming.l4_proto = l4_proto;

	success &= assert_equals_int(VER_CONTINUE, compute_out_tuple(&incoming, &outgoing, &field), "Function call");
	success &= assert_equals_u16(1500, outgoing.dst.addr6.l4, "Destination port");
	if (l4_proto != L4PROTO_ICMP)
		success &= assert_equals_u16(123, outgoing.src.addr6.l4, "Source port");
	success &= assert_equals_ipv6(&local_ipv6, &outgoing.src.addr6.l3, "Source address");
	success &= assert_equals_ipv6(&remote_ipv6, &outgoing.dst.addr6.l3, "Destination address");
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
