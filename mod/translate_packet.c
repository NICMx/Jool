#include "nat64/mod/translate_packet.h"
#include "nat64/comm/types.h"
#include "nat64/comm/constants.h"
#include "nat64/mod/config.h"
#include "nat64/mod/ipv6_hdr_iterator.h"

#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/sort.h>
#include <linux/icmpv6.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/icmp.h>
#include <net/tcp.h>


static struct translate_config config;
static DEFINE_SPINLOCK(config_lock);

#include "translate_packet_4to6.c"
#include "translate_packet_6to4.c"

int translate_packet_init(void)
{
	__u16 default_plateaus[] = TRAN_DEF_MTU_PLATEAUS;

	spin_lock_bh(&config_lock);

	config.skb_head_room = TRAN_DEF_SKB_HEAD_ROOM;
	config.skb_tail_room = TRAN_DEF_SKB_TAIL_ROOM;
	config.reset_traffic_class = TRAN_DEF_RESET_TRAFFIC_CLASS;
	config.reset_tos = TRAN_DEF_RESET_TOS;
	config.new_tos = TRAN_DEF_NEW_TOS;
	config.df_always_on = TRAN_DEF_DF_ALWAYS_ON;
	config.build_ipv4_id = TRAN_DEF_BUILD_IPV4_ID;
	config.lower_mtu_fail = TRAN_DEF_LOWER_MTU_FAIL;
	config.mtu_plateau_count = ARRAY_SIZE(default_plateaus);
	config.mtu_plateaus = kmalloc(sizeof(default_plateaus), GFP_ATOMIC);
	if (!config.mtu_plateaus) {
		log_err(ERR_ALLOC_FAILED, "Could not allocate memory to store the MTU plateaus.");
		spin_unlock_bh(&config_lock);
		return -ENOMEM;
	}
	memcpy(config.mtu_plateaus, &default_plateaus, sizeof(default_plateaus));

	spin_unlock_bh(&config_lock);
	return 0;
}

void translate_packet_destroy(void)
{
	spin_lock_bh(&config_lock);
	// Note that config is static (and hence its members are initialized to zero at startup),
	// so calling destroy() before init() is not harmful.
	kfree(config.mtu_plateaus);
	spin_unlock_bh(&config_lock);
}

int clone_translate_config(struct translate_config *clone)
{
	__u16 plateaus_len;

	spin_lock_bh(&config_lock);

	memcpy(clone, &config, sizeof(config));
	plateaus_len = config.mtu_plateau_count * sizeof(*config.mtu_plateaus);
	clone->mtu_plateaus = kmalloc(plateaus_len, GFP_ATOMIC);
	if (!clone->mtu_plateaus) {
		spin_unlock_bh(&config_lock);
		log_err(ERR_ALLOC_FAILED, "Could not allocate a clone of the config's plateaus list.");
		return -ENOMEM;
	}
	memcpy(clone->mtu_plateaus, config.mtu_plateaus, plateaus_len);

	spin_unlock_bh(&config_lock);
	return 0;
}

static int be16_compare(const void *a, const void *b)
{
	return *(__u16 *)b  - *(__u16 *)a;
}

static void be16_swap(void *a, void *b, int size)
{
	__u16 t = *(__u16 *)a;
	*(__u16 *)a = *(__u16 *)b;
	*(__u16 *)b = t;
}

int set_translate_config(__u32 operation, struct translate_config *new_config)
{
	// Validate.
	if (operation & MTU_PLATEAUS_MASK) {
		int i, j;

		if (new_config->mtu_plateau_count == 0) {
			log_err(ERR_MTU_LIST_EMPTY, "The MTU list received from userspace is empty.");
			return -EINVAL;
		}

		// Sort descending.
		sort(new_config->mtu_plateaus, new_config->mtu_plateau_count,
				sizeof(*new_config->mtu_plateaus), be16_compare, be16_swap);

		// Remove zeroes and duplicates.
		for (i = 0, j = 1; j < new_config->mtu_plateau_count; j++) {
			if (new_config->mtu_plateaus[j] == 0)
				break;
			if (new_config->mtu_plateaus[i] != new_config->mtu_plateaus[j]) {
				i++;
				new_config->mtu_plateaus[i] = new_config->mtu_plateaus[j];
			}
		}

		if (new_config->mtu_plateaus[0] == 0) {
			log_err(ERR_MTU_LIST_ZEROES, "The MTU list contains nothing but zeroes.");
			return -EINVAL;
		}

		new_config->mtu_plateau_count = i + 1;
	}

	// Update.
	spin_lock_bh(&config_lock);

	if (operation & SKB_HEAD_ROOM_MASK)
		config.skb_head_room = new_config->skb_head_room;
	if (operation & SKB_TAIL_ROOM_MASK)
		config.skb_tail_room = new_config->skb_tail_room;
	if (operation & RESET_TCLASS_MASK)
		config.reset_traffic_class = new_config->reset_traffic_class;
	if (operation & RESET_TOS_MASK)
		config.reset_tos = new_config->reset_tos;
	if (operation & NEW_TOS_MASK)
		config.new_tos = new_config->new_tos;
	if (operation & DF_ALWAYS_ON_MASK)
		config.df_always_on = new_config->df_always_on;
	if (operation & BUILD_IPV4_ID_MASK)
		config.build_ipv4_id = new_config->build_ipv4_id;
	if (operation & LOWER_MTU_FAIL_MASK)
		config.lower_mtu_fail = new_config->lower_mtu_fail;
	if (operation & MTU_PLATEAUS_MASK) {
		__u16 *old_mtus = config.mtu_plateaus;
		__u16 new_mtus_len = new_config->mtu_plateau_count * sizeof(*new_config->mtu_plateaus);

		config.mtu_plateaus = kmalloc(new_mtus_len, GFP_ATOMIC);
		if (!config.mtu_plateaus) {
			config.mtu_plateaus = old_mtus; // Should we revert the other fields?
			spin_unlock_bh(&config_lock);
			log_err(ERR_ALLOC_FAILED, "Could not allocate the kernel's MTU plateaus list.");
			return -ENOMEM;
		}

		kfree(old_mtus);
		config.mtu_plateau_count = new_config->mtu_plateau_count;
		memcpy(config.mtu_plateaus, new_config->mtu_plateaus, new_mtus_len);
	}

	spin_unlock_bh(&config_lock);
	return 0;
}

/**
 * Joins out.l3_hdr, out.l4_hdr and out.payload into a single packet, placing the result in
 * out.packet.
 */
static bool create_skb(struct packet_out *out)
{
	struct sk_buff *new_skb;
	__u16 head_room, tail_room;

	spin_lock_bh(&config_lock);
	head_room = config.skb_head_room;
	tail_room = config.skb_tail_room;
	spin_unlock_bh(&config_lock);

	new_skb = alloc_skb(head_room // user's reserved.
			+ LL_MAX_HEADER // kernel's reserved + layer 2.
			+ out->l3_hdr_len // layer 3.
			+ out->l4_hdr_len // layer 4.
			+ out->payload_len // packet data.
			+ tail_room, // user's reserved+.
			GFP_ATOMIC);
	if (!new_skb) {
		log_err(ERR_ALLOC_FAILED, "New packet allocation failed.");
		return false;
	}
	out->packet = new_skb;

	skb_reserve(new_skb, head_room + LL_MAX_HEADER);
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

	log_debug("Translating the inner packet...");

	if (in_outer->payload_len < in_outer->l3_hdr_basic_len) {
		log_warning("Packet is too small to contain a packet.");
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
		log_err(ERR_INNER_PACKET, "Translation of the inner packet's layer 3 header failed.");
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
		log_err(ERR_ALLOC_FAILED, "Translation of the inner packet's payload header failed.");
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
	kfree(inner_packet_out.l3_hdr);
	return false;
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
static bool translate_packet(struct tuple *tuple, struct sk_buff *skb_in, struct sk_buff **skb_out,
		bool (*init_packet_in_function)(struct tuple *, struct sk_buff *, struct packet_in *in),
		bool (*l3_hdr_function)(struct packet_in *in, struct packet_out *out),
		bool (*l4_hdr_and_payload_function)(struct packet_in *in, struct packet_out *out),
		bool (*l3_post_function)(struct packet_out *out),
		bool (*l4_post_function)(struct packet_in *in, struct packet_out *out))
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
	if (!l4_post_function(&in, &out))
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

bool translating_the_packet_4to6(struct tuple *tuple, struct sk_buff *skb_in,
		struct sk_buff **skb_out)
{
	bool (*l4_hdr_and_payload_function)(struct packet_in *, struct packet_out *);
	bool (*l4_post_function)(struct packet_in *, struct packet_out *);

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
		log_err(ERR_L4PROTO, "Unsupported transport protocol: %u.", ip_hdr(skb_in)->protocol);
		return false;
	}

	return translate_packet(tuple, skb_in, skb_out,
			init_packet_in_4to6,
			create_ipv6_hdr, l4_hdr_and_payload_function,
			post_ipv6, l4_post_function);
}

bool translating_the_packet_6to4(struct tuple *tuple, struct sk_buff *skb_in,
		struct sk_buff **skb_out)
{
	bool (*l4_hdr_and_payload_function)(struct packet_in *, struct packet_out *);
	bool (*l4_post_function)(struct packet_in *, struct packet_out *);
	struct hdr_iterator iterator = HDR_ITERATOR_INIT(ipv6_hdr(skb_in));

	log_debug("Step 4: Translating the Packet");

	hdr_iterator_last(&iterator);
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
		log_err(ERR_L4PROTO, "Unsupported transport protocol: %u.", iterator.hdr_type);
		return false;
	}

	return translate_packet(tuple, skb_in, skb_out,
			init_packet_in_6to4,
			create_ipv4_hdr, l4_hdr_and_payload_function,
			post_ipv4, l4_post_function);
}
