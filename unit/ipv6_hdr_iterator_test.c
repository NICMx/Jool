#include <linux/module.h>
#include <linux/printk.h>
#include <net/ipv6.h>

#include "nat64/mod/unit_test.h"
#include "nat64/comm/types.h"
#include "ipv6_hdr_iterator.c"


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Alberto Leiva Popper <aleiva@nic.mx>");
MODULE_DESCRIPTION("Header iterator test.");


const __u8 FRAG_HDR_LEN = sizeof(struct frag_hdr);
const __u8 ROUTING_HDR_LEN = 40;
const __u8 OPT_HDR_LEN = 32; // Needs to be a multiple of 8.

struct ipv6hdr *kmalloc_packet(__u16 payload_len, __u8 nexthdr)
{
	struct ipv6hdr *result = kmalloc(sizeof(struct ipv6hdr) + payload_len, GFP_ATOMIC);
	if (!result) {
		log_warning("Unable to allocate a test header.");
		return NULL;
	}

	result->nexthdr = nexthdr;
	result->payload_len = cpu_to_be16(payload_len);
	return result;
}

struct frag_hdr *add_frag_hdr(void *previous_hdr, __u16 previous_hdr_len, __u8 nexthdr)
{
	struct frag_hdr *hdr = previous_hdr + previous_hdr_len;
	hdr->nexthdr = nexthdr;
	return hdr;
}

struct ipv6_opt_hdr *add_routing_hdr(void *previous_hdr, __u16 previous_hdr_len, __u8 nexthdr)
{
	struct ipv6_opt_hdr *hdr = previous_hdr + previous_hdr_len;
	hdr->nexthdr = NEXTHDR_UDP;
	hdr->hdrlen = (ROUTING_HDR_LEN / 8) - 1;
	return hdr;
}

/**
 * Sometimes this function is also used to obtain ESP headers. I'm aware they don't work like this;
 * for the purposes of the tests that doesn't matter.
 */
struct ipv6_opt_hdr *add_opt_hdr(void *previous_hdr, __u16 previous_hdr_len, __u8 nexthdr)
{
	struct ipv6_opt_hdr *hdr = previous_hdr + previous_hdr_len;
	hdr->nexthdr = nexthdr;
	hdr->hdrlen = (OPT_HDR_LEN / 8) - 1;
	return hdr;
}

unsigned char *add_payload(void *previous_hdr, __u16 previous_hdr_len)
{
	return previous_hdr + previous_hdr_len;
}


static bool test_next_function_no_subheaders(void)
{
	bool success = true;
	struct hdr_iterator iterator;

	// Init
	struct ipv6hdr *ip6_header;
	unsigned char *payload;

	ip6_header = kmalloc_packet(4, NEXTHDR_UDP);
	if (!ip6_header)
		return false;
	payload = add_payload(ip6_header, sizeof(struct ipv6hdr));

	// Test
	hdr_iterator_init(&iterator, ip6_header);
	success &= assert_equals_ptr(payload, iterator.data, "Payload 1, data");
	success &= assert_equals_u8(NEXTHDR_UDP, iterator.hdr_type, "Payload 1, type");
	if (!success)
		goto end;

	success &= assert_equals_int(HDR_ITERATOR_END, hdr_iterator_next(&iterator), "Result 1");
	success &= assert_equals_ptr(payload, iterator.data, "Payload 2, data");
	success &= assert_equals_u8(NEXTHDR_UDP, iterator.hdr_type, "Payload 2, type");
	if (!success)
		goto end;

	success &= assert_equals_int(HDR_ITERATOR_END, hdr_iterator_next(&iterator), "Result 2");
	success &= assert_equals_int(HDR_ITERATOR_END, hdr_iterator_next(&iterator), "Result 3");
	success &= assert_equals_int(HDR_ITERATOR_END, hdr_iterator_next(&iterator), "Result 4");
	success &= assert_equals_ptr(payload, iterator.data, "Payload 3, data");
	success &= assert_equals_u8(NEXTHDR_UDP, iterator.hdr_type, "Payload 3, type");
	// Fall through.

end:
	kfree(ip6_header);
	return success;
}

static bool test_next_function_subheaders(void)
{
	bool success = true;
	struct hdr_iterator iterator;

	// Init
	struct ipv6hdr *ip6_header;
	struct frag_hdr *fragment_hdr;
	struct ipv6_opt_hdr *hop_by_hop_hdr;
	struct ipv6_opt_hdr *routing_hdr;
	unsigned char *payload;

	ip6_header = kmalloc_packet(FRAG_HDR_LEN + OPT_HDR_LEN + ROUTING_HDR_LEN + 4, NEXTHDR_FRAGMENT);
	if (!ip6_header)
		return false;
	fragment_hdr = add_frag_hdr(ip6_header, sizeof(struct ipv6hdr), NEXTHDR_HOP);
	hop_by_hop_hdr = add_opt_hdr(fragment_hdr, FRAG_HDR_LEN, NEXTHDR_ROUTING);
	routing_hdr = add_routing_hdr(hop_by_hop_hdr, OPT_HDR_LEN, NEXTHDR_UDP);
	payload = add_payload(routing_hdr, ROUTING_HDR_LEN);

	// Test
	hdr_iterator_init(&iterator, ip6_header);
	success &= assert_equals_ptr(fragment_hdr, iterator.data, "Frag hdr, data");
	success &= assert_equals_u8(NEXTHDR_FRAGMENT, iterator.hdr_type, "Frag hdr, type");
	if (!success)
		goto end;

	success &= assert_equals_int(HDR_ITERATOR_SUCCESS, hdr_iterator_next(&iterator), "Next 1");
	success &= assert_equals_ptr(hop_by_hop_hdr, iterator.data, "Hop-by-hop hdr, data");
	success &= assert_equals_u8(NEXTHDR_HOP, iterator.hdr_type, "Hop-by-hop hdr, type");
	if (!success)
		goto end;

	success &= assert_equals_int(HDR_ITERATOR_SUCCESS, hdr_iterator_next(&iterator), "Next 2");
	success &= assert_equals_ptr(routing_hdr, iterator.data, "Routing hdr, data");
	success &= assert_equals_u8(NEXTHDR_ROUTING, iterator.hdr_type, "Routing hdr, type");
	if (!success)
		goto end;

	success &= assert_equals_int(HDR_ITERATOR_SUCCESS, hdr_iterator_next(&iterator), "Next 3");
	success &= assert_equals_ptr(payload, iterator.data, "Payload 1, data");
	success &= assert_equals_u8(NEXTHDR_UDP, iterator.hdr_type, "Payload 1, type");
	if (!success)
		goto end;

	success &= assert_equals_int(HDR_ITERATOR_END, hdr_iterator_next(&iterator), "Next 4");
	success &= assert_equals_ptr(payload, iterator.data, "Payload 2, data");
	success &= assert_equals_u8(NEXTHDR_UDP, iterator.hdr_type, "Payload 2, type");
	// Fall through.

end:
	kfree(ip6_header);
	return success;
}

static bool test_next_function_unsupported(void)
{
	bool success = true;
	struct hdr_iterator iterator;

	// Init
	struct ipv6hdr *ip6_header;
	struct frag_hdr *fragment_hdr;
	struct ipv6_opt_hdr *esp_hdr;
	struct ipv6_opt_hdr *routing_hdr;
	unsigned char *payload;

	ip6_header = kmalloc_packet(FRAG_HDR_LEN + OPT_HDR_LEN + ROUTING_HDR_LEN + 4, NEXTHDR_FRAGMENT);
	if (!ip6_header)
		return false;
	fragment_hdr = add_frag_hdr(ip6_header, sizeof(struct ipv6hdr), NEXTHDR_ESP);
	esp_hdr = add_opt_hdr(fragment_hdr, FRAG_HDR_LEN, FRAG_HDR_LEN);
	routing_hdr = add_routing_hdr(esp_hdr, OPT_HDR_LEN, NEXTHDR_UDP);
	payload = add_payload(routing_hdr, ROUTING_HDR_LEN);

	// Test
	hdr_iterator_init(&iterator, ip6_header);
	success &= assert_equals_ptr(fragment_hdr, iterator.data, "Frag hdr, pointer");
	success &= assert_equals_u8(NEXTHDR_FRAGMENT, iterator.hdr_type, "Frag hdr, type");
	if (!success)
		goto end;

	success &= assert_equals_int(HDR_ITERATOR_SUCCESS, hdr_iterator_next(&iterator), "Next 1");
	success &= assert_equals_ptr(esp_hdr, iterator.data, "ESP hdr, pointer");
	success &= assert_equals_u8(NEXTHDR_ESP, iterator.hdr_type, "ESP hdr, type");
	if (!success)
		goto end;

	success &= assert_equals_int(HDR_ITERATOR_UNSUPPORTED, hdr_iterator_next(&iterator), "Next 2");
	success &= assert_equals_ptr(esp_hdr, iterator.data, "Still ESP header, pointer");
	success &= assert_equals_u8(NEXTHDR_ESP, iterator.hdr_type, "Still ESP header, type");
	// Fall through.

end:
	kfree(ip6_header);
	return success;
}

static bool test_next_function_overflow(void)
{
	bool success = true;
	struct hdr_iterator iterator;

	// Init
	struct ipv6hdr *ip6_header;
	struct frag_hdr *fragment_hdr;
	struct ipv6_opt_hdr *hop_by_hop_hdr;

	ip6_header = kmalloc_packet(FRAG_HDR_LEN + OPT_HDR_LEN, NEXTHDR_FRAGMENT);
	if (!ip6_header)
		return false;
	fragment_hdr = add_frag_hdr(ip6_header, sizeof(struct ipv6hdr), NEXTHDR_HOP);
	hop_by_hop_hdr = add_opt_hdr(fragment_hdr, FRAG_HDR_LEN, NEXTHDR_ROUTING);

	// Test
	hdr_iterator_init(&iterator, ip6_header);
	success &= assert_equals_ptr(fragment_hdr, iterator.data, "Frag hdr, data");
	success &= assert_equals_u8(NEXTHDR_FRAGMENT, iterator.hdr_type, "Frag hdr, type");
	if (!success)
		goto end;

	success &= assert_equals_int(HDR_ITERATOR_SUCCESS, hdr_iterator_next(&iterator), "Next 1");
	success &= assert_equals_ptr(hop_by_hop_hdr, iterator.data, "Hop-by-hop hdr, data");
	success &= assert_equals_u8(NEXTHDR_HOP, iterator.hdr_type, "Hop-by-hop hdr, type");
	if (!success)
		goto end;

	success &= assert_equals_int(HDR_ITERATOR_OVERFLOW, hdr_iterator_next(&iterator), "Next 2");
	// Fall through.

end:
	kfree(ip6_header);
	return success;
}

static bool test_last_function_no_subheaders(void)
{
	bool success = true;
	struct hdr_iterator iterator;

	// Init
	struct ipv6hdr *ip6_header;
	unsigned char *payload;

	ip6_header = kmalloc_packet(4, NEXTHDR_UDP);
	if (!ip6_header)
		return false;
	payload = add_payload(ip6_header, sizeof(struct ipv6hdr));

	// Test
	hdr_iterator_init(&iterator, ip6_header);
	success &= assert_equals_int(HDR_ITERATOR_END, hdr_iterator_last(&iterator), "Result");
	success &= assert_equals_ptr(payload, iterator.data, "Last function, data");
	success &= assert_equals_u8(NEXTHDR_UDP, iterator.hdr_type, "Last function, type");

	// End
	kfree(ip6_header);
	return success;
}

static bool test_last_function_subheaders(void)
{
	bool success = true;
	struct hdr_iterator iterator;

	// Init
	struct ipv6hdr *ip6_header;
	struct frag_hdr *fragment_hdr;
	struct ipv6_opt_hdr *hop_by_hop_hdr;
	struct ipv6_opt_hdr *routing_hdr;
	unsigned char *payload;

	ip6_header = kmalloc_packet(FRAG_HDR_LEN + OPT_HDR_LEN + ROUTING_HDR_LEN + 4, NEXTHDR_FRAGMENT);
	if (!ip6_header)
		return false;
	fragment_hdr = add_frag_hdr(ip6_header, sizeof(struct ipv6hdr), NEXTHDR_HOP);
	hop_by_hop_hdr = add_opt_hdr(fragment_hdr, FRAG_HDR_LEN, NEXTHDR_ROUTING);
	routing_hdr = add_routing_hdr(hop_by_hop_hdr, OPT_HDR_LEN, NEXTHDR_UDP);
	payload = add_payload(routing_hdr, ROUTING_HDR_LEN);

	// Test
	hdr_iterator_init(&iterator, ip6_header);
	success &= assert_equals_int(HDR_ITERATOR_END, hdr_iterator_last(&iterator), "Result");
	success &= assert_equals_ptr(payload, iterator.data, "Last function, data");
	success &= assert_equals_u8(NEXTHDR_UDP, iterator.hdr_type, "Last function, type");

	// End
	kfree(ip6_header);
	return success;
}

static bool test_last_function_unsupported(void)
{
	bool success = true;
	struct hdr_iterator iterator;

	// Init
	struct ipv6hdr *ip6_header;
	struct frag_hdr *fragment_hdr;
	struct ipv6_opt_hdr *esp_hdr;
	struct ipv6_opt_hdr *routing_hdr;
	unsigned char *payload;

	ip6_header = kmalloc_packet(FRAG_HDR_LEN + OPT_HDR_LEN + ROUTING_HDR_LEN + 4, NEXTHDR_FRAGMENT);
	if (!ip6_header)
		return false;
	fragment_hdr = add_frag_hdr(ip6_header, sizeof(struct ipv6hdr), NEXTHDR_ESP);
	esp_hdr = add_opt_hdr(fragment_hdr, FRAG_HDR_LEN, FRAG_HDR_LEN);
	routing_hdr = add_routing_hdr(esp_hdr, OPT_HDR_LEN, NEXTHDR_UDP);
	payload = add_payload(routing_hdr, ROUTING_HDR_LEN);

	// Test
	hdr_iterator_init(&iterator, ip6_header);
	success &= assert_equals_int(HDR_ITERATOR_UNSUPPORTED, hdr_iterator_last(&iterator), "Result");
	success &= assert_equals_ptr(esp_hdr, iterator.data, "Last function, data");
	success &= assert_equals_u8(NEXTHDR_ESP, iterator.hdr_type, "Last function, type");

	// End
	kfree(ip6_header);
	return success;
}

static bool test_last_function_overflow(void)
{
	bool success = true;
	struct hdr_iterator iterator;

	// Init
	struct ipv6hdr *ip6_header;
	struct frag_hdr *fragment_hdr;
	struct ipv6_opt_hdr *hop_by_hop_hdr;

	ip6_header = kmalloc_packet(FRAG_HDR_LEN + OPT_HDR_LEN, NEXTHDR_FRAGMENT);
	if (!ip6_header)
		return false;
	fragment_hdr = add_frag_hdr(ip6_header, sizeof(struct ipv6hdr), NEXTHDR_HOP);
	hop_by_hop_hdr = add_opt_hdr(fragment_hdr, NEXTHDR_FRAGMENT, NEXTHDR_ROUTING);

	// Test
	hdr_iterator_init(&iterator, ip6_header);
	success &= assert_equals_int(HDR_ITERATOR_OVERFLOW, hdr_iterator_last(&iterator), "Result");

	// End
	kfree(ip6_header);
	return success;
}

static bool test_get_ext_function_no_subheaders(void)
{
	bool success = true;

	// Init
	struct ipv6hdr *ip6_header;
	unsigned char *payload;

	ip6_header = kmalloc_packet(4, NEXTHDR_UDP);
	if (!ip6_header)
		return false;
	payload = add_payload(ip6_header, sizeof(struct ipv6hdr));

	// Test
	success &= assert_equals_ptr(NULL, get_extension_header(ip6_header, NEXTHDR_FRAGMENT),
			"Frag hdr");
	success &= assert_equals_ptr(NULL, get_extension_header(ip6_header, NEXTHDR_HOP),
			"Hop-by-hop hdr");
	success &= assert_equals_ptr(NULL, get_extension_header(ip6_header, NEXTHDR_ESP),
			"ESP hdr");
	success &= assert_equals_ptr(NULL, get_extension_header(ip6_header, NEXTHDR_UDP),
			"Payload"); // The UDP header is not an extension header.

	// End
	kfree(ip6_header);
	return success;
}

static bool test_get_ext_function_subheaders(void)
{
	bool success = true;

	// Init
	struct ipv6hdr *ip6_header;
	struct frag_hdr *fragment_hdr;
	struct ipv6_opt_hdr *hop_by_hop_hdr;
	struct ipv6_opt_hdr *routing_hdr;
	unsigned char *payload;

	ip6_header = kmalloc_packet(FRAG_HDR_LEN + OPT_HDR_LEN + ROUTING_HDR_LEN + 4, NEXTHDR_FRAGMENT);
	if (!ip6_header)
		return false;
	fragment_hdr = add_frag_hdr(ip6_header, sizeof(struct ipv6hdr), NEXTHDR_HOP);
	hop_by_hop_hdr = add_opt_hdr(fragment_hdr, FRAG_HDR_LEN, NEXTHDR_ROUTING);
	routing_hdr = add_opt_hdr(hop_by_hop_hdr, OPT_HDR_LEN, NEXTHDR_UDP);
	payload = add_payload(routing_hdr, ROUTING_HDR_LEN);

	// Test
	success &= assert_equals_ptr(fragment_hdr, get_extension_header(ip6_header, NEXTHDR_FRAGMENT),
			"Frag hdr");
	success &= assert_equals_ptr(hop_by_hop_hdr, get_extension_header(ip6_header, NEXTHDR_HOP),
			"Hop-by-hop hdr");
	success &= assert_equals_ptr(NULL, get_extension_header(ip6_header, NEXTHDR_ESP),
			"ESP header");
	success &= assert_equals_ptr(NULL, get_extension_header(ip6_header, NEXTHDR_UDP),
			"Payload"); // The UDP header is not an extension header.

	// End
	kfree(ip6_header);
	return success;
}

static bool test_get_ext_function_unsupported(void)
{
	bool success = true;

	// Init.
	struct ipv6hdr *ip6_header;
	struct frag_hdr *fragment_hdr;
	struct ipv6_opt_hdr *esp_hdr, *routing_hdr;
	unsigned char *payload;

	ip6_header = kmalloc_packet(FRAG_HDR_LEN + OPT_HDR_LEN + ROUTING_HDR_LEN + 4, NEXTHDR_FRAGMENT);
	if (!ip6_header)
		return false;
	fragment_hdr = add_frag_hdr(ip6_header, sizeof(struct ipv6hdr), NEXTHDR_ESP);
	esp_hdr = add_opt_hdr(fragment_hdr, FRAG_HDR_LEN, FRAG_HDR_LEN);
	routing_hdr = add_routing_hdr(esp_hdr, OPT_HDR_LEN, NEXTHDR_UDP);
	payload = add_payload(routing_hdr, ROUTING_HDR_LEN);

	// Test
	success &= assert_equals_ptr(fragment_hdr, get_extension_header(ip6_header, NEXTHDR_FRAGMENT),
			"Frag hdr");
	success &= assert_equals_ptr(esp_hdr, get_extension_header(ip6_header, NEXTHDR_ESP),
			"ESP header");
	success &= assert_equals_ptr(NULL, get_extension_header(ip6_header, NEXTHDR_ROUTING),
			"Routing header"); // The ESP header is in the way.
	success &= assert_equals_ptr(NULL, get_extension_header(ip6_header, NEXTHDR_UDP),
			"Payload"); // Same, but that isn't an extension header anyway.

	// End
	kfree(ip6_header);
	return success;
}

static bool test_get_ext_function_overflow(void)
{
	bool success = true;

	// Init
	struct ipv6hdr *ip6_header;
	struct frag_hdr *fragment_hdr;
	struct ipv6_opt_hdr *hop_by_hop_hdr;

	ip6_header = kmalloc_packet(FRAG_HDR_LEN + OPT_HDR_LEN, NEXTHDR_FRAGMENT);
	if (!ip6_header)
		return false;
	fragment_hdr = add_frag_hdr(ip6_header, sizeof(struct ipv6hdr), NEXTHDR_HOP);
	hop_by_hop_hdr = add_opt_hdr(fragment_hdr, FRAG_HDR_LEN, NEXTHDR_ROUTING);

	// Test
	success &= assert_equals_ptr(fragment_hdr, get_extension_header(ip6_header, NEXTHDR_FRAGMENT),
			"Frag hdr");
	success &= assert_equals_ptr(hop_by_hop_hdr, get_extension_header(ip6_header, NEXTHDR_HOP),
			"Hop-by-hop hdr");
	success &= assert_equals_ptr(NULL, get_extension_header(ip6_header, NEXTHDR_UDP),
			"Payload"); // The UDP header is not an extension header.

	// End
	kfree(ip6_header);
	return success;
}

int init_module(void)
{
	START_TESTS("IPv6 header iterator");

	CALL_TEST(test_next_function_no_subheaders(), "next function, no subheaders");
	CALL_TEST(test_next_function_subheaders(), "next function, subheaders");
	CALL_TEST(test_next_function_unsupported(), "next function, unsupported headers");
	CALL_TEST(test_next_function_overflow(), "next function, corrupted packet");

	CALL_TEST(test_last_function_no_subheaders(), "last function, no subheaders");
	CALL_TEST(test_last_function_subheaders(), "last function, subheaders");
	CALL_TEST(test_last_function_unsupported(), "last function, unsupported headers");
	CALL_TEST(test_last_function_overflow(), "last function, corrupted packet");

	CALL_TEST(test_get_ext_function_no_subheaders(), "get ext function, no subheaders");
	CALL_TEST(test_get_ext_function_subheaders(), "get ext function, subheaders");
	CALL_TEST(test_get_ext_function_unsupported(), "get ext function, unsupported headers");
	CALL_TEST(test_get_ext_function_overflow(), "get ext function, corrupted packet");

	END_TESTS;
}

void cleanup_module(void)
{
	// No code.
}
