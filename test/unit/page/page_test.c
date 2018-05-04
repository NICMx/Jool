#include <linux/module.h>

#include "nat64/unit/unit_test.h"
#include "nat64/unit/skb_generator.h"
#include "nat64/unit/types.h"

#include "nat64/common/str_utils.h"
#include "nat64/mod/common/core.h"
#include "nat64/mod/common/pool6.h"
#include "nat64/mod/common/xlator.h"

MODULE_LICENSE(JOOL_LICENSE);
MODULE_AUTHOR("Alberto Leiva");
MODULE_DESCRIPTION("Pages test");

struct tuple tuple6;
struct net_device *dev;
u8 buffer[PAGE_SIZE];
extern struct sk_buff *skb_out;

static int init(void)
{
	struct xlator jool;
	struct ipv6_prefix prefix6;
	int error;

	error = xlator_add(&jool);
	if (error)
		return error;

	error = str_to_addr6("2001:db8::", &prefix6.address);
	if (error)
		return error;
	prefix6.len = 96;
	error = pool6_add(jool.pool6, &prefix6);
	if (error)
		return error;

	/* Test's global variables */
	error = init_tuple6(&tuple6,
			"2001:db8::192.0.2.1", 5000,
			"2001:db8::203.0.113.2", 6000,
			L4PROTO_TCP);
	if (error)
		return error;
	/*
	 * Yes, this is sort of a hack. I just need a valid device in the
	 * current namespace.
	 */
	dev = init_net.loopback_dev;

	xlator_put(&jool);
	return 0;
}

static void clean(void)
{
	xlator_rm();
}

static void print_some_bytes(void *buffer, unsigned int size)
{
	u8 *better = buffer;
	unsigned int i;

	if (size < 6) {
		for (i = 0; i < size; i++)
			pr_cont("%x ", better[i]);
		pr_cont("\n");
		return;
	}

	pr_cont("%x %x %x ... %x %x %x\n",
			better[0], better[1], better[2],
			better[size - 3], better[size - 2], better[size - 1]);
}

static void print_skb(struct sk_buff *skb, char *prefix)
{
	struct skb_shared_info *shinfo = skb_shinfo(skb);
	unsigned int i;

	pr_info("======= SKB %s =======\n", prefix);
	pr_info("len: %u\n", skb->len);
	pr_info("headlen: %u\n", skb_headlen(skb));
	pr_info("data_len: %u\n", skb->data_len);
	pr_info("nr_frags: %u\n", shinfo->nr_frags);

	pr_info("    head: ");
	print_some_bytes(skb->data, skb_headlen(skb));

	for (i = 0; i < shinfo->nr_frags; i++) {
		skb_frag_t *frag;
		u8 *vaddr;
		unsigned int frag_size;

		frag = &shinfo->frags[i];
		frag_size = skb_frag_size(frag);

		vaddr = kmap_atomic(skb_frag_page(frag));
		memcpy(buffer, vaddr, frag_size);
		kunmap_atomic(vaddr);

		pr_info("    frag %u (%u): ", i, frag_size);
		print_some_bytes(buffer, frag_size);
	}

	pr_info("===================\n");
}

static bool validate_skb(struct sk_buff *in, struct sk_buff *out)
{
#define BUFFER_SIZE 16
	u8 buffer_in[BUFFER_SIZE];
	u8 buffer_out[BUFFER_SIZE];
	bool success = true;

	success &= ASSERT_INT(in->len - 20, out->len, "out->len");
	success &= ASSERT_INT(0, skb_copy_bits(in, in->len - BUFFER_SIZE,
			buffer_in, BUFFER_SIZE), "in buffer extraction");
	success &= ASSERT_INT(0, skb_copy_bits(out, out->len - BUFFER_SIZE,
			buffer_out, BUFFER_SIZE), "out buffer extraction");
	success &= ASSERT_INT(0, memcmp(buffer_in, buffer_out, BUFFER_SIZE),
			"last bytes comparison");

	return success;
}

static int add_v6_hdr(struct sk_buff *skb, unsigned int *offset, u16 plen)
{
	struct ipv6hdr hdr;
	int error;

	error = init_ipv6_hdr(&hdr, plen, NEXTHDR_TCP, &tuple6, 1, 0, 0, 64);
	if (error)
		return error;

	error = skb_store_bits(skb, *offset, &hdr, sizeof(hdr));
	if (error) {
		log_err("skb_store_bits() error: %d", error);
		return error;
	}

	*offset += sizeof(hdr);
	return 0;
}

static int add_tcp_hdr(struct sk_buff *skb, unsigned int *offset, u16 dlen)
{
	struct tcphdr hdr;
	int error;

	error = init_tcp_hdr(&hdr, ETH_P_IPV6, dlen, &tuple6);
	if (error)
		return error;

	error = skb_store_bits(skb, *offset, &hdr, sizeof(hdr));
	if (error) {
		log_err("skb_store_bits() error: %d", error);
		return error;
	}

	*offset += sizeof(hdr);
	return 0;
}

static int add_icmp6_hdr(struct sk_buff *skb, unsigned int *offset)
{
	struct icmp6hdr hdr;
	int error;

	hdr.icmp6_type = ICMPV6_PKT_TOOBIG;
	hdr.icmp6_code = 0;
	hdr.icmp6_cksum = 0;
	hdr.icmp6_mtu = cpu_to_be32(1500);

	error = skb_store_bits(skb, *offset, &hdr, sizeof(hdr));
	if (error) {
		log_err("skb_store_bits() error: %d", error);
		return error;
	}

	*offset += sizeof(hdr);
	return 0;
}

static int init_skb(struct sk_buff *skb, unsigned int active_len)
{
	__u8 buffer[256];
	unsigned int offset = 0;
	unsigned int len;

	unsigned int i;
	int error;

	skb_reset_network_header(skb);
	skb_set_transport_header(skb, 40);

	error = add_v6_hdr(skb, &offset, active_len - sizeof(struct ipv6hdr));
	if (error)
		return error;
	error = add_icmp6_hdr(skb, &offset);
	if (error)
		return error;
	error = add_v6_hdr(skb, &offset, 30);
	if (error)
		return error;
	error = add_tcp_hdr(skb, &offset, 30);
	if (error)
		return error;

	for (i = 0; i < 256; i++)
		buffer[i] = i;

	while (offset < active_len) {
		/* log_info("offset: %u", offset); */

		len = min_t(unsigned int, 256U, active_len - offset);
		/* log_info("	(want to write %u bytes)", len); */

		error = skb_store_bits(skb, offset, buffer, len);
		if (error) {
			log_err("skb_store_bits() error: %d", error);
			return error;
		}

		offset += len;
	}

	return 0;
}

struct sk_buff *create_paged_skb(unsigned int head_len, unsigned int data_len)
{
	struct sk_buff *skb;
	unsigned int reserved_len = LL_MAX_HEADER;
	int error = 0;

	/*
	 * It's weird; @error pretty much always returns -ENOBUFS.
	 * This seems to be by design.
	 *
	 * Also, I can't for the life of me understand wtf the third argument
	 * is supposed to be used for. All I know is that it seems to create
	 * pages larger than PAGE_SIZE, which I'd expect to be illegal.
	 */
	skb = alloc_skb_with_frags(reserved_len + head_len, data_len, 0, &error,
			GFP_KERNEL);
	if (!skb)
		return NULL;

	/* One wonders why this is not part of alloc_skb_with_frags(), FFS */
	skb_reserve(skb, reserved_len);
	skb_put(skb, head_len);
	skb->data_len = data_len;
	skb->len += data_len;

	if (init_skb(skb, head_len + data_len)) {
		kfree_skb(skb);
		skb = NULL;
	}

	return skb;
}

static bool basic_single_test(unsigned int head_len, unsigned int data_len)
{
	struct sk_buff *skb_in;
	unsigned int verdict;
	bool success = true;

	if (head_len + data_len < 108) /* IPv6 + ICMP + IPv6 + TCP */
		return true; /* "Sure thing, kiddo." */

	skb_in = create_paged_skb(head_len, data_len);
	if (!skb_in)
		return false;

	verdict = core_6to4(skb_in, dev);
	if (verdict != NF_STOLEN)
		kfree_skb(skb_in);

	success &= ASSERT_INT(NF_STOLEN, verdict, "full xlat");

	if (skb_out == NULL) {
		log_err("skb_out is null.");
		return false;
	}

	/*
	 * Note: This sucks, but I can't just skb_get() the original skb_in,
	 * because Jool refuses to translate shared packets.
	 */
	skb_in = create_paged_skb(head_len, data_len);
	if (!skb_in) {
		log_err("Failed to recreate skb_in.");
		kfree_skb(skb_out);
		return false;
	}

	print_skb(skb_in, "in");
	print_skb(skb_out, "out");
	success &= validate_skb(skb_in, skb_out);

	kfree_skb(skb_in);
	kfree_skb(skb_out);

	return success;
}

static bool basic(void)
{
	unsigned int data_lens[] = {
			0, 1, 2, 3, 4, 6, 7, 8, 9,

			PAGE_SIZE - 9,
			PAGE_SIZE - 8,
			PAGE_SIZE - 7,
			PAGE_SIZE - 6,
			PAGE_SIZE - 5,
			PAGE_SIZE - 4,
			PAGE_SIZE - 3,
			PAGE_SIZE - 2,
			PAGE_SIZE - 1,
			PAGE_SIZE,
			PAGE_SIZE + 1,
			PAGE_SIZE + 2,
			PAGE_SIZE + 3,
			PAGE_SIZE + 4,
			PAGE_SIZE + 5,
			PAGE_SIZE + 6,
			PAGE_SIZE + 7,
			PAGE_SIZE + 8,
			PAGE_SIZE + 9,

			2 * PAGE_SIZE - 9,
			2 * PAGE_SIZE - 8,
			2 * PAGE_SIZE - 7,
			2 * PAGE_SIZE - 6,
			2 * PAGE_SIZE - 5,
			2 * PAGE_SIZE - 4,
			2 * PAGE_SIZE - 3,
			2 * PAGE_SIZE - 2,
			2 * PAGE_SIZE - 1,
			2 * PAGE_SIZE,
			2 * PAGE_SIZE + 1,
			2 * PAGE_SIZE + 2,
			2 * PAGE_SIZE + 3,
			2 * PAGE_SIZE + 4,
			2 * PAGE_SIZE + 5,
			2 * PAGE_SIZE + 6,
			2 * PAGE_SIZE + 7,
			2 * PAGE_SIZE + 8,
			2 * PAGE_SIZE + 9,
	};

	unsigned int h, d; /* head counter, data[_len] counter */
	bool success = true;

	for (h = 40; h < 110; h += 20)
		for (d = 0; d < ARRAY_SIZE(data_lens); d++)
			success &= basic_single_test(h, data_lens[d]);

	return success;
}

int init_module(void)
{
	struct test_group test = {
		.name = "Pages",
		.setup_fn = xlator_setup,
		.teardown_fn = xlator_teardown,
		.init_fn = init,
		.clean_fn = clean,
	};

	if (test_group_begin(&test))
		return -EINVAL;

	test_group_test(&test, basic, "Basic test");

	return test_group_end(&test);
}

void cleanup_module(void)
{
	/* No code. */
}
