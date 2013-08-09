#include "nat64/mod/translate_packet.h"
#include "nat64/comm/types.h"
#include "nat64/comm/constants.h"
#include "nat64/mod/random.h"
#include "nat64/mod/config.h"
#include "nat64/mod/ipv6_hdr_iterator.h"

#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/list.h>
#include <linux/sort.h>
#include <linux/icmpv6.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/icmp.h>
#include <net/tcp.h>


struct translation_steps {
	/**
	 * The function that will translate the layer-3 header.
	 * Its purpose if to set the variables from "out" which are prefixed by "l3_", based on the
 	 * packet described by "in".
	 */
	enum verdict (*l3_hdr_function)(struct tuple *tuple, struct fragment *in, struct fragment *out);
	/**
	 * The function that will translate the layer-4 header and the
	 * payload. Layer 4 and payload are combined in a single function due to their strong
	 * interdependence.
	 * Its purpose is to set the variables from "out" which are prefixed by "l4_" or "payload",
	 * based on the packet described by "in".
	 */
	enum verdict (*l4_hdr_and_payload_function)(struct tuple *, struct fragment *in, struct fragment *out);
	/**
	 * Post-processing involving the layer 3 header.
	 * Currently, this function fixes the header's lengths and checksum, which cannot be done in
	 * the functions above given that they generally require the packet to be assembled and ready.
	 * Not all lengths and checksums have that requirement, but just to be consistent do it always
	 * here, please.
	 * Note, out.l3_hdr, out.l4_hdr and out.payload point to garbage given that the packet has
	 * already been assembled. When you want to access the headers, use out.packet.
	 */
	enum verdict (*l3_post_function)(struct fragment *out);
	/** Post-processing involving the layer 4 header. See l3_post_function. */
	enum verdict (*l4_post_function)(struct tuple *tuple, struct fragment *in, struct fragment *out);
};

struct translation_steps steps[L3_PROTO_COUNT][L4_PROTO_COUNT];

static struct translate_config config;
static DEFINE_SPINLOCK(config_lock);


#include "translate_packet_4to6.c"
#include "translate_packet_6to4.c"

//int clone_translate_config(struct translate_config *clone)
//{
//	__u16 plateaus_len;
//
//	spin_lock_bh(&config_lock);
//
//	memcpy(clone, &config, sizeof(config));
//	plateaus_len = config.mtu_plateau_count * sizeof(*config.mtu_plateaus);
//	clone->mtu_plateaus = kmalloc(plateaus_len, GFP_ATOMIC);
//	if (!clone->mtu_plateaus) {
//		spin_unlock_bh(&config_lock);
//		log_err(ERR_ALLOC_FAILED, "Could not allocate a clone of the config's plateaus list.");
//		return -ENOMEM;
//	}
//	memcpy(clone->mtu_plateaus, config.mtu_plateaus, plateaus_len);
//
//	spin_unlock_bh(&config_lock);
//	return 0;
//}
//
//static int be16_compare(const void *a, const void *b)
//{
//	return *(__u16 *)b - *(__u16 *)a;
//}
//
//static void be16_swap(void *a, void *b, int size)
//{
//	__u16 t = *(__u16 *)a;
//	*(__u16 *)a = *(__u16 *)b;
//	*(__u16 *)b = t;
//}
//
//int set_translate_config(__u32 operation, struct translate_config *new_config)
//{
//	/* Validate. */
//	if (operation & MTU_PLATEAUS_MASK) {
//		int i, j;
//
//		if (new_config->mtu_plateau_count == 0) {
//			log_err(ERR_MTU_LIST_EMPTY, "The MTU list received from userspace is empty.");
//			return -EINVAL;
//		}
//
//		/* Sort descending. */
//		sort(new_config->mtu_plateaus, new_config->mtu_plateau_count,
//				sizeof(*new_config->mtu_plateaus), be16_compare, be16_swap);
//
//		/* Remove zeroes and duplicates. */
//		for (i = 0, j = 1; j < new_config->mtu_plateau_count; j++) {
//			if (new_config->mtu_plateaus[j] == 0)
//				break;
//			if (new_config->mtu_plateaus[i] != new_config->mtu_plateaus[j]) {
//				i++;
//				new_config->mtu_plateaus[i] = new_config->mtu_plateaus[j];
//			}
//		}
//
//		if (new_config->mtu_plateaus[0] == 0) {
//			log_err(ERR_MTU_LIST_ZEROES, "The MTU list contains nothing but zeroes.");
//			return -EINVAL;
//		}
//
//		new_config->mtu_plateau_count = i + 1;
//	}
//
//	/* Update. */
//	spin_lock_bh(&config_lock);
//
//	if (operation & SKB_HEAD_ROOM_MASK)
//		config.skb_head_room = new_config->skb_head_room;
//	if (operation & SKB_TAIL_ROOM_MASK)
//		config.skb_tail_room = new_config->skb_tail_room;
//	if (operation & RESET_TCLASS_MASK)
//		config.reset_traffic_class = new_config->reset_traffic_class;
//	if (operation & RESET_TOS_MASK)
//		config.reset_tos = new_config->reset_tos;
//	if (operation & NEW_TOS_MASK)
//		config.new_tos = new_config->new_tos;
//	if (operation & DF_ALWAYS_ON_MASK)
//		config.df_always_on = new_config->df_always_on;
//	if (operation & BUILD_IPV4_ID_MASK)
//		config.build_ipv4_id = new_config->build_ipv4_id;
//	if (operation & LOWER_MTU_FAIL_MASK)
//		config.lower_mtu_fail = new_config->lower_mtu_fail;
//	if (operation & MTU_PLATEAUS_MASK) {
//		__u16 *old_mtus = config.mtu_plateaus;
//		__u16 new_mtus_len = new_config->mtu_plateau_count * sizeof(*new_config->mtu_plateaus);
//
//		config.mtu_plateaus = kmalloc(new_mtus_len, GFP_ATOMIC);
//		if (!config.mtu_plateaus) {
//			config.mtu_plateaus = old_mtus; /* Should we revert the other fields? */
//			spin_unlock_bh(&config_lock);
//			log_err(ERR_ALLOC_FAILED, "Could not allocate the kernel's MTU plateaus list.");
//			return -ENOMEM;
//		}
//
//		kfree(old_mtus);
//		config.mtu_plateau_count = new_config->mtu_plateau_count;
//		memcpy(config.mtu_plateaus, new_config->mtu_plateaus, new_mtus_len);
//	}
//
//	spin_unlock_bh(&config_lock);
//	return 0;
//}

static enum verdict empty(struct tuple *tuple, struct fragment *in, struct fragment *out)
{
	return VER_CONTINUE;
}

static enum verdict copy_payload(struct tuple *tuple, struct fragment *in, struct fragment *out)
{
	out->l4_hdr.proto = L4PROTO_NONE;
	out->l4_hdr.len = 0;
	out->l4_hdr.ptr = NULL;
	out->l4_hdr.ptr_belongs_to_skb = true;
	out->payload = in->payload;

	return VER_CONTINUE;
}

/**
 * layer-4 header and payload translation that assumes that neither has to be changed.
 * As such, it just copies the pointers to the original data to the pointers to the new data,
 * instead of populating new data.
 */
static enum verdict copy_l4_hdr_and_payload(struct tuple *tuple, struct fragment *in, struct fragment *out)
{
	out->l4_hdr = in->l4_hdr;
	out->payload = in->payload;

	return VER_CONTINUE;
}

enum verdict translate_inner_packet(struct fragment *in_outer, struct fragment *out_outer,
		enum verdict (*l3_function)(struct tuple *, struct fragment *, struct fragment *))
{
	return VER_CONTINUE; // TODO
}
//	/*
//	 * While naming variables in this function,
//	 * "in" means either (inner or outer) incoming packet (the one we're translating).
//	 * "out" means either (inner or outer) outgoing packet (the NAT64's translation).
//	 * "src" are the pointers to where the data is originally allocated.
//	 * "dst" are the pointers to where the data will be once returned.
//	 * (And just to be paranoid: "l3's payload" means l4 header + real payload.)
//	 */
//
//	/** Data from the original packet's inner packet. */
//	struct {
//		struct {
//			void *src;
//			unsigned int len;
//		} hdr;
//		struct {
//			unsigned char *src;
//			unsigned int len;
//		} payload;
//	} in_inner;
//
//	/** Data from the new packet's inner packet. */
//	struct {
//		struct {
//			void *src;
//			unsigned char *dst;
//			unsigned int len;
//		} hdr;
//		struct {
//			unsigned char *src;
//			unsigned char *dst;
//			unsigned int len;
//		} payload;
//	} out_inner;
//
//	struct packet_in inner_packet_in;
//	struct packet_out inner_packet_out = INIT_PACKET_OUT;
//
//	log_debug("Translating the inner packet...");
//
//
//	/* Get references to the original data. */
//	in_inner.hdr.src = in_outer->payload;
//	if (!validate_inner_packet(in_outer->l3_hdr_type, in_outer->payload, in_outer->payload_len,
//			&in_inner.hdr.len))
//		goto failure;
//	in_inner.payload.src = in_inner.hdr.src + in_inner.hdr.len;
//	in_inner.payload.len = in_outer->payload_len - in_inner.hdr.len;
//
//	/* Create the layer 3 headers. */
//	inner_packet_in.packet = NULL;
//	inner_packet_in.tuple = in_outer->tuple;
//	inner_packet_in.l3_hdr = in_inner.hdr.src;
//	if (!l3_function(&inner_packet_in, &inner_packet_out)) {
//		log_err(ERR_INNER_PACKET, "Translation of the inner packet's layer 3 header failed.");
//		goto failure;
//	}
//
//	/* Get references to the new data. */
//	out_inner.hdr.src = inner_packet_out.l3_hdr;
//	out_inner.hdr.len = inner_packet_out.l3_hdr_len;
//	out_inner.payload.src = in_inner.payload.src;
//	/* If this exceeds the MTU, we'll cut it later; we don't know the full packet's length ATM. */
//	out_inner.payload.len = in_inner.payload.len;
//
//	/* Put it all together. */
//	out_outer->payload_len = out_inner.hdr.len + out_inner.payload.len;
//	out_outer->payload = kmalloc(out_outer->payload_len, GFP_ATOMIC);
//	if (!out_outer->payload) {
//		log_err(ERR_ALLOC_FAILED, "Translation of the inner packet's payload header failed.");
//		goto failure;
//	}
//	out_outer->payload_needs_kfreeing = true;
//
//	out_inner.hdr.dst = out_outer->payload;
//	out_inner.payload.dst = out_inner.hdr.dst + out_inner.hdr.len;
//
//	memcpy(out_inner.hdr.dst, out_inner.hdr.src, out_inner.hdr.len);
//	memcpy(out_inner.payload.dst, out_inner.payload.src, out_inner.payload.len);
//
//	kfree(inner_packet_out.l3_hdr);
//	return true;
//
//failure:
//	kfree(inner_packet_out.l3_hdr);
//	return false;
//}

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
	config.min_ipv6_mtu = TRAN_DEF_MIN_IPV6_MTU;
	memcpy(config.mtu_plateaus, &default_plateaus, sizeof(default_plateaus));

	spin_unlock_bh(&config_lock);

	steps[L3PROTO_IPV6][L4PROTO_NONE].l3_hdr_function = create_ipv4_hdr;
	steps[L3PROTO_IPV6][L4PROTO_NONE].l4_hdr_and_payload_function = copy_payload;
	steps[L3PROTO_IPV6][L4PROTO_NONE].l3_post_function = post_ipv4;
	steps[L3PROTO_IPV6][L4PROTO_NONE].l4_post_function = empty;

	steps[L3PROTO_IPV6][L4PROTO_TCP].l3_hdr_function = create_ipv4_hdr;
	steps[L3PROTO_IPV6][L4PROTO_TCP].l4_hdr_and_payload_function = copy_l4_hdr_and_payload;
	steps[L3PROTO_IPV6][L4PROTO_TCP].l3_post_function = post_ipv4;
	steps[L3PROTO_IPV6][L4PROTO_TCP].l4_post_function = post_tcp_ipv4;

	steps[L3PROTO_IPV6][L4PROTO_UDP].l3_hdr_function = create_ipv4_hdr;
	steps[L3PROTO_IPV6][L4PROTO_UDP].l4_hdr_and_payload_function = copy_l4_hdr_and_payload;
	steps[L3PROTO_IPV6][L4PROTO_UDP].l3_post_function = post_ipv4;
	steps[L3PROTO_IPV6][L4PROTO_UDP].l4_post_function = post_udp_ipv4;

	steps[L3PROTO_IPV6][L4PROTO_ICMP].l3_hdr_function = create_ipv4_hdr;
	steps[L3PROTO_IPV6][L4PROTO_ICMP].l4_hdr_and_payload_function = create_icmp4_hdr_and_payload;
	steps[L3PROTO_IPV6][L4PROTO_ICMP].l3_post_function = post_ipv4;
	steps[L3PROTO_IPV6][L4PROTO_ICMP].l4_post_function = post_icmp4;

	steps[L3PROTO_IPV4][L4PROTO_NONE].l3_hdr_function = create_ipv6_hdr;
	steps[L3PROTO_IPV4][L4PROTO_NONE].l4_hdr_and_payload_function = copy_payload;
	steps[L3PROTO_IPV4][L4PROTO_NONE].l3_post_function = post_ipv6;
	steps[L3PROTO_IPV4][L4PROTO_NONE].l4_post_function = empty;

	steps[L3PROTO_IPV4][L4PROTO_TCP].l3_hdr_function = create_ipv6_hdr;
	steps[L3PROTO_IPV4][L4PROTO_TCP].l4_hdr_and_payload_function = copy_l4_hdr_and_payload;
	steps[L3PROTO_IPV4][L4PROTO_TCP].l3_post_function = post_ipv6;
	steps[L3PROTO_IPV4][L4PROTO_TCP].l4_post_function = post_tcp_ipv6;

	steps[L3PROTO_IPV4][L4PROTO_UDP].l3_hdr_function = create_ipv6_hdr;
	steps[L3PROTO_IPV4][L4PROTO_UDP].l4_hdr_and_payload_function = copy_l4_hdr_and_payload;
	steps[L3PROTO_IPV4][L4PROTO_UDP].l3_post_function = post_ipv6;
	steps[L3PROTO_IPV4][L4PROTO_UDP].l4_post_function = post_udp_ipv6;

	steps[L3PROTO_IPV4][L4PROTO_ICMP].l3_hdr_function = create_ipv6_hdr;
	steps[L3PROTO_IPV4][L4PROTO_ICMP].l4_hdr_and_payload_function = create_icmp6_hdr_and_payload;
	steps[L3PROTO_IPV4][L4PROTO_ICMP].l3_post_function = post_ipv6;
	steps[L3PROTO_IPV4][L4PROTO_ICMP].l4_post_function = post_icmp6;

	return 0;
}

void translate_packet_destroy(void)
{
	spin_lock_bh(&config_lock);
	/*
	 * Note that config is static (and hence its members are initialized to zero at startup),
	 * so calling destroy() before init() is not harmful.
	 */
	kfree(config.mtu_plateaus);
	spin_unlock_bh(&config_lock);
}

static enum verdict translate(struct tuple *tuple, struct fragment *in, struct fragment **out,
		struct translation_steps *steps)
{
	enum verdict result;

	*out = kmalloc(sizeof(**out), GFP_ATOMIC);
	if (!*out)
		return VER_DROP;
	frag_init(*out);

	result = steps->l3_hdr_function(tuple, in, *out);
	if (result != VER_CONTINUE)
		goto failure;
	result = steps->l4_hdr_and_payload_function(tuple, in, *out);
	if (result != VER_CONTINUE)
		goto failure;
	result = frag_create_skb(*out);
	if (result != VER_CONTINUE)
		goto failure;
	result = steps->l3_post_function(*out);
	if (result != VER_CONTINUE)
		goto failure;
	result = steps->l4_post_function(tuple, in, *out);
	if (result != VER_CONTINUE)
		goto failure;

	return result;

failure:
	frag_kfree(*out);
	return result;
}

static __be16 combine_frag_offset_and_m(u16 frag_offset, bool m)
{
	return cpu_to_be16((frag_offset << 3) | (m ? 1 : 0));
}

static void set_frag_headers(struct ipv6hdr *hdr6_old, struct ipv6hdr *hdr6_new,
		u16 packet_size, u16 offset, bool mf)
{
	struct frag_hdr *hdrfrag_old = (struct frag_hdr *) (hdr6_old + 1);
	struct frag_hdr *hdrfrag_new = (struct frag_hdr *) (hdr6_new + 1);

	if (hdr6_new != hdr6_old)
		memcpy(hdr6_new, hdr6_old, sizeof(*hdr6_new));
	hdr6_new->payload_len = cpu_to_be16(packet_size - sizeof(*hdr6_new));

	hdrfrag_new->nexthdr = hdrfrag_old->nexthdr;
	hdrfrag_new->reserved = 0;
	hdrfrag_new->frag_off = combine_frag_offset_and_m(offset, mf);
	hdrfrag_new->identification = hdrfrag_old->identification;
}

/**
 * Asume que frag trae un fragment header.
 * También asume que los siguientes campos de frag->skb están bien seteados: network_header,
 * head, data, tail.
 */
static enum verdict divide(struct fragment *frag, struct list_head *list)
{
	unsigned char *current_p;
	struct sk_buff *new_skb;
	struct fragment *new_fragment;
	struct ipv6hdr *first_hdr6 = ipv6_hdr(frag->skb);
	u16 headers_size;
	u16 payload_max_size;

	__be32 original_identification;
	u16 original_fragment_offset;
	bool original_mf;

	__u16 min_ipv6_mtu;
	__u16 head_room, tail_room;


	spin_lock_bh(&config_lock);
	min_ipv6_mtu = config.min_ipv6_mtu;
	head_room = config.skb_head_room;
	tail_room = config.skb_tail_room;
	spin_unlock_bh(&config_lock);

	headers_size = sizeof(struct ipv6hdr) + sizeof(struct frag_hdr);
	payload_max_size = min_ipv6_mtu - headers_size;

	{
		struct frag_hdr *frag_header = (struct frag_hdr *) (first_hdr6 + 1);

		original_identification = frag_header->identification;
		original_fragment_offset = be16_to_cpu(frag_header->frag_off) >> 3;
		original_mf = be16_to_cpu(frag_header->frag_off) | 0x1;
	}

	set_frag_headers(first_hdr6, first_hdr6, min_ipv6_mtu, original_fragment_offset, true);
	list_add(&frag->next, list);

	current_p = skb_network_header(frag->skb) + min_ipv6_mtu;

	while (current_p < skb_tail_pointer(frag->skb)) {
		bool is_last = (skb_tail_pointer(frag->skb) - current_p < payload_max_size);
		u16 actual_payload_size = is_last
					? skb_tail_pointer(frag->skb) - current_p
					: payload_max_size;
		u16 actual_total_size = headers_size + actual_payload_size;

		new_skb = alloc_skb(head_room /* user's reserved. */
				+ LL_MAX_HEADER /* kernel's reserved + layer 2. */
				+ actual_total_size /* l3 header + l4 header + packet data. */
				+ tail_room, /* user's reserved+. */
				GFP_ATOMIC);
		if (!new_skb)
			return VER_DROP;

		skb_reserve(new_skb, head_room + LL_MAX_HEADER);
		skb_put(new_skb, actual_total_size);
		skb_reset_mac_header(new_skb);
		skb_reset_network_header(new_skb);
		new_skb->protocol = htons(ETH_P_IPV6);

		set_frag_headers(first_hdr6, ipv6_hdr(new_skb), actual_total_size,
				original_fragment_offset + (current_p - frag->skb->data + headers_size),
				is_last ? original_mf : true);
		memcpy(skb_network_header(new_skb) + headers_size, current_p, actual_payload_size);

		new_fragment = kmalloc(sizeof(*new_fragment), GFP_ATOMIC);
		if (!new_fragment) {
			kfree_skb(new_skb);
			return VER_DROP;
		}

		new_fragment->skb = new_skb;

		list_add(&new_fragment->next, list);

		current_p += actual_payload_size;
	}

	skb_set_tail_pointer(frag->skb, min_ipv6_mtu);

	return VER_CONTINUE;
}

static enum verdict translate_fragment(struct fragment *in, struct tuple *tuple,
		struct list_head *out_list)
{
	struct fragment *out;
	enum verdict result;
	__u16 min_ipv6_mtu;


	// Translate this single fragment.
	result = translate(tuple, in, &out, &steps[in->l3_hdr.proto][in->l4_hdr.proto]);
	if (result != VER_CONTINUE)
		return result;

	// Add it to the list of outgoing fragments.
	switch (in->l3_hdr.proto) {
	case L3PROTO_IPV4:
		spin_lock_bh(&config_lock);
		min_ipv6_mtu = config.min_ipv6_mtu;
		spin_unlock_bh(&config_lock);

		if (out->skb->len > min_ipv6_mtu) {
			// It's too big, so subdivide it.

			if (is_dont_fragment_set(frag_get_ipv4_hdr(in))) {
				icmp_send(in->skb, ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED, 0); // TODO set the MTU
				return VER_DROP;
			}

			result = divide(out, out_list);
			if (result != VER_CONTINUE)
				return result;
		} else {
			// Just add that one fragment to the list.
			list_add(&out->next, out_list);
		}
		break;

	case L3PROTO_IPV6:
		list_add(&out->next, out_list);
		break;

	default:
		log_err(ERR_L3PROTO, "Unsupported network protocol: %u.", in->l3_hdr.proto);
		return VER_DROP;

	}

	return VER_CONTINUE;
}

/**
 * It's ONLY responsible for out->fragments.
 *
 * Assumes that out is already initialized.
 */
enum verdict translating_the_packet(struct tuple *tuple, struct packet *in, struct packet *out)
{
	struct fragment *current_in;
	enum verdict result;

	log_debug("Step 4: Translating the Packet");

	list_for_each_entry(current_in, &in->fragments, next) {
		result = translate_fragment(current_in, tuple, &out->fragments);
		if (result != VER_CONTINUE)
			goto error;
	}

	log_debug("Done step 4.");

	return VER_CONTINUE;

error:
	while (!list_empty(&out->fragments)) {
		/* out->fragment.next is the first element of the list. */
		frag_kfree(list_entry(out->fragments.next, struct fragment, next));
	}
	return result;
}
