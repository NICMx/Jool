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


struct translate_config config;

#include "nf_nat64_translate_packet_4to6.c"
#include "nf_nat64_translate_packet_6to4.c"

bool translate_packet_init(void)
{
	__u16 default_plateaus[] = TRAN_DEF_MTU_PLATEAUS;

	config.packet_head_room = TRAN_DEF_USR_HEAD_ROOM;
	config.packet_tail_room = TRAN_DEF_USR_TAIL_ROOM;
	config.override_ipv6_traffic_class = TRAN_DEF_OVERRIDE_IPV6_TRAFFIC_CLASS;
	config.override_ipv4_traffic_class = TRAN_DEF_OVERRIDE_IPV4_TRAFFIC_CLASS;
	config.ipv4_traffic_class = TRAN_DEF_TRAFFIC_CLASS;
	config.df_always_set = TRAN_DEF_DF_ALWAYS_SET;
	config.generate_ipv4_id = TRAN_DEF_GENERATE_IPV4_ID;
	config.improve_mtu_failure_rate = TRAN_DEF_IMPROVE_MTU_FAILURE_RATE;
	config.ipv6_nexthop_mtu = TRAN_DEF_IPV6_NEXTHOP_MTU;
	config.ipv4_nexthop_mtu = TRAN_DEF_IPV4_NEXTHOP_MTU;

	config.mtu_plateau_count = ARRAY_SIZE(default_plateaus);
	config.mtu_plateaus = kmalloc(sizeof(default_plateaus), GFP_ATOMIC);
	if (!config.mtu_plateaus) {
		log_warning("Could not allocate memory to store the MTU plateaus.");
		return false;
	}
	memcpy(config.mtu_plateaus, &default_plateaus, sizeof(default_plateaus));

	return true;
}

void translate_packet_destroy(void)
{
	kfree(config.mtu_plateaus);
}

bool translate_clone_config(struct translate_config *clone)
{
	__u16 plateaus_len = config.mtu_plateau_count * sizeof(*config.mtu_plateaus);

	memcpy(clone, &config, sizeof(*clone));

	clone->mtu_plateaus = kmalloc(plateaus_len, GFP_ATOMIC);
	if (!clone->mtu_plateaus)
		return false;
	memcpy(clone->mtu_plateaus, &config.mtu_plateaus, plateaus_len);

	return true;
}

enum response_code translate_packet_config(__u32 operation, struct translate_config *new_config)
{
	if (operation & PHR_MASK)
		config.packet_head_room = new_config->packet_head_room;
	if (operation & PTR_MASK)
		config.packet_tail_room = new_config->packet_tail_room;
	if (operation & IPV6_NEXTHOP_MASK)
		config.ipv6_nexthop_mtu = new_config->ipv6_nexthop_mtu;
	if (operation & IPV4_NEXTHOP_MASK)
		config.ipv4_nexthop_mtu = new_config->ipv4_nexthop_mtu;
	if (operation & IPV4_TRAFFIC_MASK)
		config.ipv4_traffic_class = new_config->ipv4_traffic_class;
	if (operation & OIPV6_MASK)
		config.override_ipv6_traffic_class = new_config->override_ipv6_traffic_class;
	if (operation & OIPV4_MASK)
		config.override_ipv4_traffic_class = new_config->override_ipv4_traffic_class;
	if (operation & DF_ALWAYS_MASK)
		config.df_always_set = new_config->df_always_set;
	if (operation & GEN_IPV4_MASK)
		config.generate_ipv4_id = new_config->generate_ipv4_id;
	if (operation & IMP_MTU_FAIL_MASK)
		config.improve_mtu_failure_rate = new_config->improve_mtu_failure_rate;
	if (operation & MTU_PLATEAUS_MASK) {
		__u16 *old_mtus = config.mtu_plateaus;
		__u16 new_mtus_len = new_config->mtu_plateau_count * sizeof(*new_config->mtu_plateaus);

		config.mtu_plateaus = kmalloc(new_mtus_len, GFP_ATOMIC);
		if (!config.mtu_plateaus) {
			config.mtu_plateaus = old_mtus;
			return RESPONSE_ALLOC_FAILED;
		}

		kfree(old_mtus);
		config.mtu_plateau_count = new_config->mtu_plateau_count;
		memcpy(config.mtu_plateaus, new_config->mtu_plateaus, new_mtus_len);
	}

	return RESPONSE_SUCCESS;
}

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
		log_warning("  New packet allocation failed.");
		return false;
	}
	out->packet = new_skb;

	skb_reserve(new_skb, config.packet_head_room + LL_MAX_HEADER);
	skb_put(new_skb, out->l3_hdr_len + out->l4_hdr_len + out->payload_len);

	skb_reset_mac_header(new_skb);
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

	log_debug("  Translating the inner packet...");

	if (in_outer->payload_len < in_outer->l3_hdr_basic_len) {
		log_warning("  Packet is too small to contain a packet.");
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
		log_warning("  Header translation failed.");
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
		log_warning("  New payload allocation failed.");
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
	log_warning("  Will leave the inner content as is.");
	out_outer->payload = in_outer->payload;
	out_outer->payload_len = in_outer->payload_len;
	out_outer->payload_needs_kfreeing = false;

	kfree(inner_packet_out.l3_hdr);
	return true;
}

/**
 * Freeds everything from "out" that might need to be released. Doesn't free "out".
 */
static void kfree_packet_out(struct packet_out *out)
{
	kfree(out->l3_hdr);

	if (out->l4_hdr_type == IPPROTO_ICMP || out->l4_hdr_type == NEXTHDR_ICMP)
		kfree(out->l4_hdr);

	if (out->payload_needs_kfreeing)
		kfree(out->payload);

	kfree_skb(out->packet);
}

/**
 * @param l3_hdr_function The function that will translate the layer-3 header.
 *		Its purpose if to set the variables from "out" which are prefixed by "l3_", based on the
 *		packet described by "in".
 * @param l4_hdr_and_payload_function The function that will translate the layer-4 header and the
 *		payload. Layer 4 and payload are combined in a single function due to their strong
 *		interdependence.
 *		Its purpose is to set the variables from "out" which are prefixed by "l4_" or "payload",
 *		based on the packet described by "in".
 * @param l3_post_function Post-processing involving the layer 3 header.
 *		Currently, this function fixes the header's lengths and checksum, which cannot be done in
 *		the functions above given that they generally require the packet to be assembled and ready.
 *		Not all lengths and checksums have that requirement, but just to be consistent do it always
 *		here, please.
 *		Note, out.l3_hdr, out.l4_hdr and out.payload point to garbage given that the packet has
 *		already been assembled. When you want to access the headers, use out.packet.
 * @param l4_post_function Post-processing involving the layer 4 header. See l3_post_function.
 */
static bool translate_packet(struct nf_conntrack_tuple *tuple,
		struct sk_buff *skb_in, struct sk_buff **skb_out,
		bool (*init_packet_in_function)(struct nf_conntrack_tuple *, struct sk_buff *,
				struct packet_in *in),
		bool (*l3_hdr_function)(struct packet_in *in, struct packet_out *out),
		bool (*l4_hdr_and_payload_function)(struct packet_in *in, struct packet_out *out),
		bool (*l3_post_function)(struct packet_out *out),
		bool (*l4_post_function)(struct packet_out *out))
{
	struct packet_in in;
	struct packet_out out = INIT_PACKET_OUT;

	if (!init_packet_in_function(tuple, skb_in, &in))
		goto failure;
	if (!l3_hdr_function(&in, &out))
		goto failure;
	if (!l4_hdr_and_payload_function(&in, &out))
		goto failure;
	if (!create_skb(&out))
		goto failure;
	if (!l3_post_function(&out))
		goto failure;
	if (!l4_post_function(&out))
		goto failure;

	*skb_out = out.packet;
	out.packet = NULL;
	kfree_packet_out(&out);

	log_debug("Done step 4.");
	return true;

failure:
	kfree_packet_out(&out);
	return false;
}

bool nat64_translating_the_packet_4to6(struct nf_conntrack_tuple *tuple,
		struct sk_buff *skb_in, struct sk_buff **skb_out)
{
	bool (*l4_hdr_and_payload_function)(struct packet_in *, struct packet_out *);
	bool (*l4_post_function)(struct packet_out *);

	log_debug("Step 4: Translating the Packet");

	switch (ip_hdr(skb_in)->protocol) {
	case IPPROTO_TCP:
		l4_hdr_and_payload_function = copy_l4_hdr_and_payload;
		l4_post_function = post_tcp_ipv6;
		break;
	case IPPROTO_UDP:
		l4_hdr_and_payload_function = copy_l4_hdr_and_payload;
		l4_post_function = post_udp_ipv6;
		break;
	case IPPROTO_ICMP:
		l4_hdr_and_payload_function = create_icmp6_hdr_and_payload;
		l4_post_function = post_icmp6;
		break;
	default:
		log_warning("  Unsupported l4 protocol (%d). Cannot translate.", ip_hdr(skb_in)->protocol);
		return false;
	}

	return translate_packet(tuple, skb_in, skb_out,
			init_packet_in_4to6,
			create_ipv6_hdr, l4_hdr_and_payload_function,
			post_ipv6, l4_post_function);
}

bool nat64_translating_the_packet_6to4(struct nf_conntrack_tuple *tuple,
		struct sk_buff *skb_in, struct sk_buff **skb_out)
{
	bool (*l4_hdr_and_payload_function)(struct packet_in *, struct packet_out *);
	bool (*l4_post_function)(struct packet_out *);
	struct hdr_iterator iterator = HDR_ITERATOR_INIT(ipv6_hdr(skb_in));

	log_debug("Step 4: Translating the Packet");

	hdr_iterator_last(&iterator);
	if (iterator.hdr_type == NEXTHDR_AUTH || iterator.hdr_type == NEXTHDR_ESP) {
		// RFC 6146 section 5.1.
		log_warning("  Incoming IPv6 packet has an Auth header or an ESP header. Cannot translate; "
				"will drop the packet.");
		return false;
	}

	switch (iterator.hdr_type) {
	case NEXTHDR_TCP:
		l4_hdr_and_payload_function = copy_l4_hdr_and_payload;
		l4_post_function = post_tcp_ipv4;
		break;
	case NEXTHDR_UDP:
		l4_hdr_and_payload_function = copy_l4_hdr_and_payload;
		l4_post_function = post_udp_ipv4;
		break;
	case NEXTHDR_ICMP:
		l4_hdr_and_payload_function = create_icmp4_hdr_and_payload;
		l4_post_function = post_icmp4;
		break;
	default:
		log_warning("  Unsupported l4 protocol (%d). Cannot translate.", iterator.hdr_type);
		return false;
	}

	return translate_packet(tuple, skb_in, skb_out,
			init_packet_in_6to4,
			create_ipv4_hdr, l4_hdr_and_payload_function,
			post_ipv4, l4_post_function);
}
