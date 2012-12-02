#include <linux/module.h>
#include <linux/printk.h>

#include "unit_test.h"
#include "nf_nat64_ipv6_hdr_iterator.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Alberto Leiva Popper <aleiva@nic.mx>");
MODULE_DESCRIPTION("Header iterator test.");

static bool test_no_subheaders(void)
{
	// Init.
	struct ipv6hdr *ip6_header;
	unsigned char *payload;

	ip6_header = kmalloc(sizeof(struct ipv6hdr) + 4, GFP_ATOMIC);
	if (!ip6_header) {
		pr_warning("Unable to allocate a test header.\n");
		return false;
	}
	ip6_header->nexthdr = NEXTHDR_UDP;

	payload = (unsigned char *) (ip6_header + 1);

	// Test next function.
	{
		struct hdr_iterator iterator = HDR_ITERATOR_INIT(ip6_header);
		ASSERT_EQUALS_PTR(ip6_header, iterator.data, "First header, data");
		ASSERT_EQUALS(-1, iterator.hdr_type, "First header, hdr type");

		hdr_iterator_next(&iterator);
		ASSERT_EQUALS_PTR(payload, iterator.data, "Payload 1st, data");
		ASSERT_EQUALS(NEXTHDR_UDP, iterator.hdr_type, "Payload 1st, hdr type");

		hdr_iterator_next(&iterator);
		ASSERT_EQUALS_PTR(payload, iterator.data, "Payload 2nd, data");
		ASSERT_EQUALS(NEXTHDR_UDP, iterator.hdr_type, "Payload 2nd, hdr type");

		hdr_iterator_next(&iterator);
		hdr_iterator_next(&iterator);
		hdr_iterator_next(&iterator);
		ASSERT_EQUALS_PTR(payload, iterator.data, "Payload 3rd, data");
		ASSERT_EQUALS(NEXTHDR_UDP, iterator.hdr_type, "Payload 3rd, hdr type");
	}

	// Test last function.
	{
		struct hdr_iterator iterator = HDR_ITERATOR_INIT(ip6_header);
		hdr_iterator_last(&iterator);
		ASSERT_EQUALS_PTR(payload, iterator.data, "Last function, data");
		ASSERT_EQUALS(NEXTHDR_UDP, iterator.hdr_type, "Last function, hdr type");
	}

	// Test get extension header function.
	{
		void *frag_hdr_computed = get_extension_header(ip6_header, NEXTHDR_FRAGMENT);
		void *hop_by_hop_hdr_computed = get_extension_header(ip6_header, NEXTHDR_HOP);
		void *udp_hdr_computed = get_extension_header(ip6_header, NEXTHDR_UDP);

		ASSERT_EQUALS_PTR(NULL, frag_hdr_computed, "Get function, frag hdr");
		ASSERT_EQUALS_PTR(NULL, hop_by_hop_hdr_computed, "Get function, hop-by-hop hdr");
		// Cause the UDP header is not an extension header.
		ASSERT_EQUALS_PTR(NULL, udp_hdr_computed, "Get function, payload");
	}

	return true;
}

static bool test_subheaders(void)
{
	// Init.
	const __u16 HOP_BY_HOP_HDR_LEN = 32;
	const __u16 ROUTING_HDR_LEN = 40;

	struct ipv6hdr *ip6_header;
	struct frag_hdr *fragment_hdr;
	struct ipv6_opt_hdr *hop_by_hop_hdr;
	struct ipv6_opt_hdr *routing_hdr;
	unsigned char *payload;

	ip6_header = kmalloc(sizeof(struct ipv6hdr)
				+ sizeof(struct frag_hdr)
				+ HOP_BY_HOP_HDR_LEN
				+ ROUTING_HDR_LEN
				+ 4, // (payload.)
				GFP_ATOMIC);
	if (!ip6_header) {
		pr_warning("Unable to allocate a test header.\n");
		return false;
	}
	ip6_header->nexthdr = NEXTHDR_FRAGMENT;

	fragment_hdr = (struct frag_hdr *) (ip6_header + 1);
	fragment_hdr->nexthdr = NEXTHDR_HOP;

	hop_by_hop_hdr = (struct ipv6_opt_hdr *) (fragment_hdr + 1);
	hop_by_hop_hdr->nexthdr = NEXTHDR_ROUTING;
	hop_by_hop_hdr->hdrlen = (HOP_BY_HOP_HDR_LEN / 8) - 1;

	routing_hdr = ((void *) hop_by_hop_hdr) + HOP_BY_HOP_HDR_LEN;
	routing_hdr->nexthdr = NEXTHDR_UDP;
	routing_hdr->hdrlen = (ROUTING_HDR_LEN / 8) - 1;

	payload = ((void *) routing_hdr) + ROUTING_HDR_LEN;

	// Test next function.
	{
		struct hdr_iterator next_iterator = HDR_ITERATOR_INIT(ip6_header);
		ASSERT_EQUALS_PTR(ip6_header, next_iterator.data, "First (main) header, data");
		ASSERT_EQUALS(-1, next_iterator.hdr_type, "First (main) header, hdr type");

		hdr_iterator_next(&next_iterator);
		ASSERT_EQUALS_PTR(fragment_hdr, next_iterator.data, "Second (frag) header, data");
		ASSERT_EQUALS(NEXTHDR_FRAGMENT, next_iterator.hdr_type, "Second (frag) header, hdr type");

		hdr_iterator_next(&next_iterator);
		ASSERT_EQUALS_PTR(hop_by_hop_hdr, next_iterator.data, "Third (hop-by-hop) header, data");
		ASSERT_EQUALS(NEXTHDR_HOP, next_iterator.hdr_type, "Third (hop-by-hop) header, hdr type");

		hdr_iterator_next(&next_iterator);
		ASSERT_EQUALS_PTR(routing_hdr, next_iterator.data, "Fourth (Routing) header, data");
		ASSERT_EQUALS(NEXTHDR_ROUTING, next_iterator.hdr_type, "Fourth (Routing) header, hdr type");

		hdr_iterator_next(&next_iterator);
		ASSERT_EQUALS_PTR(payload, next_iterator.data, "Payload 1st, data");
		ASSERT_EQUALS(NEXTHDR_UDP, next_iterator.hdr_type, "Payload 1st, hdr type");

		hdr_iterator_next(&next_iterator);
		ASSERT_EQUALS_PTR(payload, next_iterator.data, "Payload 2nd, data");
		ASSERT_EQUALS(NEXTHDR_UDP, next_iterator.hdr_type, "Payload 2nd, hdr type");
	}

	// Test last function.
	{
		struct hdr_iterator last_iterator = HDR_ITERATOR_INIT(ip6_header);
		hdr_iterator_init(&last_iterator, ip6_header);
		hdr_iterator_last(&last_iterator);
		ASSERT_EQUALS_PTR(payload, last_iterator.data, "Last function, data");
		ASSERT_EQUALS(NEXTHDR_UDP, last_iterator.hdr_type, "Last function, hdr type");
	}

	// Test get extension header function.
	{
		void *frag_hdr_computed = get_extension_header(ip6_header, NEXTHDR_FRAGMENT);
		void *hop_by_hop_hdr_computed = get_extension_header(ip6_header, NEXTHDR_HOP);
		void *udp_hdr_computed = get_extension_header(ip6_header, NEXTHDR_UDP);

		ASSERT_EQUALS_PTR(fragment_hdr, frag_hdr_computed, "Get function, frag hdr");
		ASSERT_EQUALS_PTR(hop_by_hop_hdr, hop_by_hop_hdr_computed, "Get function, hop-by-hop hdr");
		// Cause the UDP header is not an extension header.
		ASSERT_EQUALS_PTR(NULL, udp_hdr_computed, "Get function, payload");
	}

	return true;
}

int init_module(void)
{
	START_TESTS("IPv6 header iterator");

	CALL_TEST(test_no_subheaders(), "No subheaders");
	CALL_TEST(test_subheaders(), "Subheaders");

	END_TESTS;
}

void cleanup_module(void)
{
	// No code.
}
