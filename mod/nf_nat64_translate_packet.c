#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/icmpv6.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/icmp.h>
#include <net/tcp.h>

#include "nf_nat64_types.h"
#include "nf_nat64_constants.h"
#include "nf_nat64_config.h"
#include "nf_nat64_translate_packet.h"
#include "nf_nat64_ipv6_hdr_iterator.h"
#include "external_stuff.h"

#include "nf_nat64_translate_packet_4to6.c"
#include "nf_nat64_translate_packet_6to4.c"

/**
 * Joins out.l3_hdr, out.l4_hdr and out.payload into a single packet, placing the result in
 * out.packet.
 */
static bool create_skb(struct packet_out *out)
{
	struct sk_buff *new_skb;

	new_skb = alloc_skb(config.packet_head_room // user's reserved.
			+ LL_MAX_HEADER // kernel's reserved + layer 2.
			+ out->l3_hdr_len // layer 3.
			+ out->l4_hdr_len // layer 4.
			+ out->payload_len // packet data.
			+ config.packet_tail_room, // user's reserved+.
			GFP_ATOMIC);
	if (!new_skb) {
		pr_warning("New packet allocation failed.\n");
		return false;
	}
	out->packet = new_skb;

	skb_reserve(new_skb, config.packet_head_room + LL_MAX_HEADER);
	skb_put(new_skb, out->l3_hdr_len + out->l4_hdr_len + out->payload_len);

	// skb_reset_mac_header(new_skb);
	skb_reset_network_header(new_skb);
	skb_set_transport_header(new_skb, out->l3_hdr_len);

	memcpy(skb_network_header(new_skb), out->l3_hdr, out->l3_hdr_len);
	memcpy(skb_transport_header(new_skb), out->l4_hdr, out->l4_hdr_len);
	memcpy(skb_transport_header(new_skb) + out->l4_hdr_len, out->payload, out->payload_len);

	return true;
}

/**
 * layer-4 header and payload translation that assumes that neither has to be changed.
 * As such, it just copies the pointers to the original data to the pointers to the new data,
 * instead of populating new data.
 */
static bool copy_l4_hdr_and_payload(struct packet_in *in, struct packet_out *out)
{
	out->l4_hdr_type = in->l4_hdr_type;
	out->l4_hdr_len = in->l4_hdr_len;
	out->l4_hdr = skb_transport_header(in->packet);
	out->payload = in->payload;
	out->payload_len = in->payload_len;

	return true;
}

bool translate_inner_packet(struct packet_in *in_outer, struct packet_out *out_outer,
		bool (*l3_function)(struct packet_in *, struct packet_out *))
{
	// While naming variables in this function,
	// "in" means either (inner or outer) incoming packet (the one we're translating).
	// "out" means either (inner or outer) outgoing packet (the NAT64's translation).
	// "src" are the pointers to where the data is originally allocated.
	// "dst" are the pointers to where the data will be once returned.
	// (And just to be paranoid: "l3's payload" means l4 header + real payload.)

	/** Data from the original packet's inner packet. */
	struct {
		struct {
			void *src;
			unsigned int len;
		} hdr;
		struct {
			unsigned char *src;
			unsigned int len;
		} payload;
	} in_inner;

	/** Data from the new packet's inner packet. */
	struct {
		struct {
			void *src;
			unsigned char *dst;
			unsigned int len;
		} hdr;
		struct {
			unsigned char *src;
			unsigned char *dst;
			unsigned int len;
		} payload;
	} out_inner;

	struct packet_in inner_packet_in;
	struct packet_out inner_packet_out = INIT_PACKET_OUT;

	pr_debug("Translating the inner packet...\n");

	if (in_outer->payload_len < in_outer->l3_hdr_basic_len) {
		pr_warning("translate_inner_packet - Packet is too small to contain a packet.\n");
		goto failure;
	}

	// Get references to the original data.
	in_inner.hdr.src = in_outer->payload;
	in_inner.hdr.len = in_outer->compute_l3_hdr_len(in_inner.hdr.src);
	in_inner.payload.src = in_inner.hdr.src + in_inner.hdr.len;
	in_inner.payload.len = in_outer->payload_len - in_inner.hdr.len;

	// Create the layer 3 headers.
	inner_packet_in.packet = NULL;
	inner_packet_in.tuple = in_outer->tuple;
	inner_packet_in.l3_hdr = in_inner.hdr.src;
	if (!l3_function(&inner_packet_in, &inner_packet_out)) {
		pr_warning("translate_inner_packet - Header translation failed.\n");
		goto failure;
	}

	// Get references to the new data.
	out_inner.hdr.src = inner_packet_out.l3_hdr;
	out_inner.hdr.len = inner_packet_out.l3_hdr_len;
	out_inner.payload.src = in_inner.payload.src;
	// If this exceeds the MTU, we'll cut it later; we don't know the full packet's length ATM.
	out_inner.payload.len = in_inner.payload.len;

	// Put it all together.
	out_outer->payload_len = out_inner.hdr.len + out_inner.payload.len;
	out_outer->payload = kmalloc(out_outer->payload_len, GFP_ATOMIC);
	if (!out_outer->payload) {
		pr_warning("translate_inner_packet - New payload allocation failed.\n");
		goto failure;
	}
	out_outer->payload_needs_kfreeing = true;

	out_inner.hdr.dst = out_outer->payload;
	out_inner.payload.dst = out_inner.hdr.dst + out_inner.hdr.len;

	memcpy(out_inner.hdr.dst, out_inner.hdr.src, out_inner.hdr.len);
	memcpy(out_inner.payload.dst, out_inner.payload.src, out_inner.payload.len);

	kfree(inner_packet_out.l3_hdr);
	return true;

failure:
	pr_warning("translate_inner_packet - Will leave the inner content as is.\n");
	out_outer->payload = in_outer->payload;
	out_outer->payload_len = in_outer->payload_len;
	out_outer->payload_needs_kfreeing = false;

	kfree(inner_packet_out.l3_hdr);
	return true;
}

/**
 * Assumes that "l3_hdr" points to a iphdr, and returns its size, options included.
 */
static __u16 compute_ipv4_hdr_len(void *l3_hdr)
{
	return 4 * ((struct iphdr *) l3_hdr)->ihl;
}

/**
 * Assumes that "l3_hdr" points to a ipv6hdr, and returns its size, extension headers included.
 */
static __u16 compute_ipv6_hdr_len(void *l3_hdr)
{
	struct hdr_iterator iterator = HDR_ITERATOR_INIT((struct ipv6hdr *) l3_hdr);
	hdr_iterator_last(&iterator);
	return iterator.data - l3_hdr;
}

/**
 * Initializes both "pipeline" and "in" using the data from "tuple", "skb", and the assumption that
 * we're translating from 4 to 6.
 * "pipeline" defines the sequence of functions that will be executed later and "in" is basically a
 * summary of "skb".
 */
static bool init_pipeline_ipv4(struct pipeline *pipeline, struct packet_in *in,
		struct nf_conntrack_tuple *tuple, struct sk_buff *skb)
{
	struct iphdr *ip4_hdr = ip_hdr(skb);

	pipeline->l3_hdr_function = create_ipv6_hdr;
	pipeline->create_skb_function = create_skb;
	pipeline->l3_post_function = post_ipv6;

	in->packet = skb;
	in->tuple = tuple;

	in->l3_hdr = ip4_hdr;
	in->l3_hdr_type = IPPROTO_IP;
	in->l3_hdr_len = skb_transport_header(skb) - skb_network_header(skb);
	in->l3_hdr_basic_len = sizeof(*ip4_hdr);
	in->compute_l3_hdr_len = compute_ipv4_hdr_len;

	in->l4_hdr_type = ip4_hdr->protocol;
	switch (in->l4_hdr_type) {
	case IPPROTO_TCP:
		in->l4_hdr_len = tcp_hdrlen(skb);
		pipeline->l4_hdr_and_payload_function = copy_l4_hdr_and_payload;
		pipeline->l4_post_function = post_tcp_ipv6;
		break;
	case IPPROTO_UDP:
		in->l4_hdr_len = sizeof(struct udphdr);
		pipeline->l4_hdr_and_payload_function = copy_l4_hdr_and_payload;
		pipeline->l4_post_function = post_udp_ipv6;
		break;
	case IPPROTO_ICMP:
		in->l4_hdr_len = sizeof(struct icmphdr);
		pipeline->l4_hdr_and_payload_function = create_icmp6_hdr_and_payload;
		pipeline->l4_post_function = post_icmp6;
		break;
	default:
		pr_warning("init_pipeline_ipv4: Unsupported l4 protocol (%d). Cannot translate.\n",
				in->l4_hdr_type);
		return false;
	}

	in->payload = skb_transport_header(skb) + in->l4_hdr_len;
	in->payload_len = be16_to_cpu(ip4_hdr->tot_len) - in->l3_hdr_len - in->l4_hdr_len;

	return true;
}

/**
 * Initializes both "pipeline" and "in" using the data from "tuple", "skb", and the assumption that
 * we're translating from 6 to 4.
 * "pipeline" defines the sequence of functions that will be executed later and "in" is basically a
 * summary of "skb".
 */
static bool init_pipeline_ipv6(struct pipeline *pipeline, struct packet_in *in,
		struct nf_conntrack_tuple *tuple, struct sk_buff *skb)
{
	struct ipv6hdr *ip6_hdr = ipv6_hdr(skb);
	struct hdr_iterator iterator = HDR_ITERATOR_INIT(ip6_hdr);

	pipeline->l3_hdr_function = create_ipv4_hdr;
	pipeline->create_skb_function = create_skb;
	pipeline->l3_post_function = post_ipv4;

	in->packet = skb;
	in->tuple = tuple;

	in->l3_hdr = ip6_hdr;
	in->l3_hdr_type = IPPROTO_IPV6;
	in->l3_hdr_len = skb_transport_header(skb) - skb_network_header(skb);
	in->l3_hdr_basic_len = sizeof(*ip6_hdr);
	in->compute_l3_hdr_len = compute_ipv6_hdr_len;

	hdr_iterator_last(&iterator);
	if (iterator.hdr_type == NEXTHDR_AUTH || iterator.hdr_type == NEXTHDR_ESP) {
		// RFC 6146 section 5.1.
		pr_warning("Incoming IPv6 packet has an Auth header or an ESP header. Cannot translate; "
				"will drop the packet.\n");
		return false;
	}

	in->l4_hdr_type = iterator.hdr_type;
	switch (in->l4_hdr_type) {
	case NEXTHDR_TCP:
		in->l4_hdr_len = tcp_hdrlen(skb);
		pipeline->l4_post_function = post_tcp_ipv4;
		pipeline->l4_hdr_and_payload_function = copy_l4_hdr_and_payload;
		break;
	case NEXTHDR_UDP:
		in->l4_hdr_len = sizeof(struct udphdr);
		pipeline->l4_hdr_and_payload_function = copy_l4_hdr_and_payload;
		pipeline->l4_post_function = post_udp_ipv4;
		break;
	case NEXTHDR_ICMP:
		in->l4_hdr_len = sizeof(struct icmp6hdr);
		pipeline->l4_hdr_and_payload_function = create_icmp4_hdr_and_payload;
		pipeline->l4_post_function = post_icmp4;
		break;
	default:
		pr_warning("init_pipeline_ipv6: Unsupported l4 protocol (%d). Cannot translate.\n",
				in->l4_hdr_type);
		return false;
	}

	in->payload = iterator.data + in->l4_hdr_len;
	in->payload_len = be16_to_cpu(ip6_hdr->payload_len) //
			- (in->l3_hdr_len - sizeof(*ip6_hdr)) //
			- in->l4_hdr_len;

	return true;
}

/**
 * Freeds everything from "out" that might need to be released. Doesn't free "out".
 */
void kfree_packet_out(struct packet_out *out)
{
	kfree(out->l3_hdr);

	if (out->l4_hdr_type == IPPROTO_ICMP || out->l4_hdr_type == NEXTHDR_ICMP)
		kfree(out->l4_hdr);

	if (out->payload_needs_kfreeing)
		kfree(out->payload);

	kfree_skb(out->packet);
}

bool nat64_translating_the_packet(struct nf_conntrack_tuple *tuple, struct sk_buff *skb_in,
		struct sk_buff **skb_out)
{
	struct packet_in in;
	struct packet_out out = INIT_PACKET_OUT;
	struct pipeline pipeline;

	pr_debug("Step 4: Translating the Packet\n");

	// TODO (info) alguien me la va a rayar por esto. Piénsalo más tiempo.
	switch (ip_hdr(skb_in)->version) {
	case 4: // 4 to 6.
		if (!init_pipeline_ipv4(&pipeline, &in, tuple, skb_in))
			goto failure;
		break;
	case 6: // 6 to 4.
		if (!init_pipeline_ipv6(&pipeline, &in, tuple, skb_in))
			goto failure;
		break;
	default:
		pr_crit("nat64_translating_the_packet: Programming error; unknown l3 protocol: %d\n",
				ip_hdr(skb_in)->version);
		return false;
	}

	if (!pipeline.l3_hdr_function(&in, &out))
		goto failure;
	if (!pipeline.l4_hdr_and_payload_function(&in, &out))
		goto failure;
	if (!pipeline.create_skb_function(&out))
		goto failure;
	if (!pipeline.l3_post_function(&out))
		goto failure;
	if (!pipeline.l4_post_function(&out))
		goto failure;

	*skb_out = out.packet;
	out.packet = NULL;
	kfree_packet_out(&out);

	pr_debug("Done step 4.\n");
	return true;

failure:
	kfree_packet_out(&out);
	return false;
}
