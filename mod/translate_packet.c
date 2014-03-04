#include "nat64/mod/translate_packet.h"
#include "nat64/comm/types.h"
#include "nat64/comm/constants.h"
#include "nat64/mod/random.h"
#include "nat64/mod/config.h"
#include "nat64/mod/ipv6_hdr_iterator.h"
#include "nat64/mod/send_packet.h"
#include "nat64/mod/icmp_wrapper.h"

#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/list.h>
#include <linux/sort.h>
#include <linux/icmpv6.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/icmp.h>
#include <net/tcp.h>


static struct translate_config config;
static DEFINE_SPINLOCK(config_lock);

static struct translation_steps steps[L3_PROTO_COUNT][L4_PROTO_COUNT];


#include "translate_packet_6to4.c"
#include "translate_packet_4to6.c"

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
	return *(__u16 *)b - *(__u16 *)a;
}

static void be16_swap(void *a, void *b, int size)
{
	__u16 t = *(__u16 *)a;
	*(__u16 *)a = *(__u16 *)b;
	*(__u16 *)b = t;
}

int set_translate_config(__u32 operation, struct translate_config *new_config)
{
	/* Validate. */
	if (operation & MTU_PLATEAUS_MASK) {
		int i, j;

		if (new_config->mtu_plateau_count == 0) {
			log_err(ERR_MTU_LIST_EMPTY, "The MTU list received from userspace is empty.");
			return -EINVAL;
		}

		/* Sort descending. */
		sort(new_config->mtu_plateaus, new_config->mtu_plateau_count,
				sizeof(*new_config->mtu_plateaus), be16_compare, be16_swap);

		/* Remove zeroes and duplicates. */
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

	/* Update. */
	spin_lock_bh(&config_lock);

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
			config.mtu_plateaus = old_mtus; /* Should we revert the other fields? */
			spin_unlock_bh(&config_lock);
			log_err(ERR_ALLOC_FAILED, "Could not allocate the kernel's MTU plateaus list.");
			return -ENOMEM;
		}

		kfree(old_mtus);
		config.mtu_plateau_count = new_config->mtu_plateau_count;
		memcpy(config.mtu_plateaus, new_config->mtu_plateaus, new_mtus_len);
	}
	if (operation & MIN_IPV6_MTU_MASK)
		config.min_ipv6_mtu = new_config->min_ipv6_mtu;

	spin_unlock_bh(&config_lock);
	return 0;
}

static verdict empty(struct tuple *tuple, struct packet *pkt_in, struct packet *pkt_out)
{
	return VER_CONTINUE;
}

static verdict copy_payload(struct tuple *tuple, struct fragment *in, struct fragment *out)
{
	out->l4_hdr.proto = L4PROTO_NONE;
	out->l4_hdr.len = 0;
	out->l4_hdr.ptr = NULL;
	out->l4_hdr.ptr_needs_kfree = false;
	out->payload.len = in->payload.len;
	out->payload.ptr = in->payload.ptr;
	out->payload.ptr_needs_kfree = false;

	return VER_CONTINUE;
}

/**
 * layer-4 header and payload translation that assumes that neither has to be changed.
 * As such, it just copies the pointers to the original data to the pointers to the new data,
 * instead of populating new data.
 */
static verdict copy_l4_hdr_and_payload(struct tuple *tuple, struct fragment *in, struct fragment *out)
{
	out->l4_hdr = in->l4_hdr;
	out->l4_hdr.ptr_needs_kfree = false;
	out->payload = in->payload;
	out->payload.ptr_needs_kfree = false;

	return VER_CONTINUE;
}

int translate_packet_init(void)
{
	__u16 default_plateaus[] = TRAN_DEF_MTU_PLATEAUS;

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
	/*
	 * Note that config is static (and hence its members are initialized to zero at startup),
	 * so calling destroy() before init() is not harmful.
	 */
	kfree(config.mtu_plateaus);
}

verdict translate(struct tuple *tuple, struct fragment *in, struct fragment **out,
		struct translation_steps *steps)
{
	verdict result;

	if (is_error(frag_create_empty(out)))
		return VER_DROP;

	result = steps->l3_hdr_function(tuple, in, *out);
	if (result != VER_CONTINUE)
		goto failure;
	result = steps->l4_hdr_and_payload_function(tuple, in, *out);
	if (result != VER_CONTINUE)
		goto failure;

	if (is_error(frag_create_skb(*out))) {
		result = VER_DROP;
		goto failure;
	}
	if (in->skb)
		(*out)->skb->mark = in->skb->mark;
	(*out)->original_skb = in->original_skb;

	result = steps->l3_post_function(*out);
	if (result != VER_CONTINUE)
		goto failure;

	return result;

failure:
	frag_kfree(*out);
	*out = NULL;
	return result;
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
	hdrfrag_new->frag_off = build_ipv6_frag_off_field(offset, mf);
	hdrfrag_new->identification = hdrfrag_old->identification;
}

/**
 * Fragments "frag" until all the pieces are at most "min_ipv6_mtu" bytes long.
 * "min_ipv6_mtu" comes from the user's configuration.
 * The resulting smaller fragments are appended to frag's list (frag->next).
 *
 * Assumes frag has a fragment header.
 * Also assumes the following fields from frag->skb are properly set: network_header, head, data
 * and tail.
 *
 * Sorry, this function is probably our most convoluted one, but everything in it is too
 * inter-related so I don't know how to fix it without creating thousand-argument functions.
 */
static verdict divide(struct fragment *frag, struct list_head *list)
{
	unsigned char *current_p;
	struct sk_buff *new_skb;
	struct fragment *new_fragment;
	struct ipv6hdr *first_hdr6 = ipv6_hdr(frag->skb);
	u16 headers_size;
	u16 payload_max_size;
	u16 original_fragment_offset;
	bool original_mf;

	__u16 min_ipv6_mtu;

	/* Prepare the helper values. */
	spin_lock_bh(&config_lock);
	min_ipv6_mtu = config.min_ipv6_mtu & 0xFFF8;
	spin_unlock_bh(&config_lock);

	headers_size = sizeof(struct ipv6hdr) + sizeof(struct frag_hdr);
	payload_max_size = min_ipv6_mtu - headers_size;

	{
		struct frag_hdr *frag_header = (struct frag_hdr *) (first_hdr6 + 1);

		original_fragment_offset = get_fragment_offset_ipv6(frag_header);
		original_mf = is_more_fragments_set_ipv6(frag_header);
	}

	set_frag_headers(first_hdr6, first_hdr6, min_ipv6_mtu, original_fragment_offset, true);
	list_add(&frag->list_hook, list->prev);

	/* Copy frag's overweight to newly-created fragments.  */
	current_p = skb_network_header(frag->skb) + min_ipv6_mtu;
	while (current_p < skb_tail_pointer(frag->skb)) {
		bool is_last = (skb_tail_pointer(frag->skb) - current_p <= payload_max_size);
		u16 actual_payload_size = is_last
					? skb_tail_pointer(frag->skb) - current_p
					: payload_max_size & 0xFFF8;
		u16 actual_total_size = headers_size + actual_payload_size;

		new_skb = alloc_skb(LL_MAX_HEADER /* kernel's reserved + layer 2. */
				+ actual_total_size, /* l3 header + l4 header + packet data. */
				GFP_ATOMIC);
		if (!new_skb)
			return VER_DROP;

		skb_reserve(new_skb, LL_MAX_HEADER);
		skb_put(new_skb, actual_total_size);
		skb_reset_mac_header(new_skb);
		skb_reset_network_header(new_skb);
		new_skb->protocol = htons(ETH_P_IPV6);
		new_skb->mark = frag->skb->mark;

		set_frag_headers(first_hdr6, ipv6_hdr(new_skb), actual_total_size,
				original_fragment_offset + (current_p - frag->skb->data - headers_size),
				is_last ? original_mf : true);
		memcpy(skb_network_header(new_skb) + headers_size, current_p, actual_payload_size);

		if (is_error(frag_create_empty(&new_fragment))) {
			kfree_skb(new_skb);
			return VER_DROP;
		}

		new_fragment->skb = new_skb;
		new_fragment->dst = NULL;
		new_fragment->l3_hdr.proto = frag->l3_hdr.proto;
		new_fragment->l3_hdr.len = frag->l3_hdr.len;
		new_fragment->l3_hdr.ptr = skb_network_header(new_skb);
		new_fragment->l3_hdr.ptr_needs_kfree = false;
		new_fragment->l4_hdr.proto = L4PROTO_NONE;
		new_fragment->l4_hdr.len = 0;
		new_fragment->l4_hdr.ptr = NULL;
		new_fragment->l4_hdr.ptr_needs_kfree = false;
		new_fragment->payload.len = actual_payload_size;
		new_fragment->payload.ptr = new_fragment->l3_hdr.ptr + new_fragment->l3_hdr.len;
		new_fragment->payload.ptr_needs_kfree = false;

		list_add(&new_fragment->list_hook, list->prev);

		current_p += actual_payload_size;
	}

	/* Finally truncate frag and we're done. */
	skb_put(frag->skb, -(frag->skb->len - min_ipv6_mtu));
	frag->payload.len = min_ipv6_mtu - frag->l3_hdr.len - frag->l4_hdr.len;

	return VER_CONTINUE;
}

static verdict translate_fragment(struct fragment *in, struct tuple *tuple,
		struct packet *pkt_out)
{
	struct fragment *out;
	verdict result;
	__u16 min_ipv6_mtu;
	struct frag_hdr *hdr_frag;

	/* Translate this single fragment. */
	/* log_debug("Packet protocols: %d %d", in->l3_hdr.proto, in->l4_hdr.proto); */
	result = translate(tuple, in, &out, &steps[in->l3_hdr.proto][in->l4_hdr.proto]);
	if (result != VER_CONTINUE)
		return result;

	switch (out->l3_hdr.proto) {
	case L3PROTO_IPV6:
		hdr_frag = frag_get_fragment_hdr(out);
		if (!hdr_frag || get_fragment_offset_ipv6(hdr_frag) == 0)
			pkt_out->first_fragment = out;
		break;
	case L3PROTO_IPV4:
		if (get_fragment_offset_ipv4(frag_get_ipv4_hdr(out)) == 0)
			pkt_out->first_fragment = out;
		break;
	}

	/* Add it to the list of outgoing fragments. */
	switch (in->l3_hdr.proto) {
	case L3PROTO_IPV4:
		spin_lock_bh(&config_lock);
		min_ipv6_mtu = config.min_ipv6_mtu;
		spin_unlock_bh(&config_lock);

		if (out->skb->len > min_ipv6_mtu) {
			/* It's too big, so subdivide it. */
			if (is_dont_fragment_set(frag_get_ipv4_hdr(in))) {
				icmp64_send(in, ICMPERR_FRAG_NEEDED, cpu_to_be32(min_ipv6_mtu));
				log_info("Packet is too big (%u bytes; MTU: %u); dropping.",
						out->skb->len, min_ipv6_mtu);
				return VER_DROP;
			}

			result = divide(out, &pkt_out->fragments);
			if (result != VER_CONTINUE)
				return result;
		} else {
			/* Just add that one fragment to the list. */
			list_add(&out->list_hook, pkt_out->fragments.prev);
		}
		break;

	case L3PROTO_IPV6:
		list_add(&out->list_hook, pkt_out->fragments.prev);
		break;
	}

	return VER_CONTINUE;
}

/**
 * Because of simplifications, "in_inner"'s list hook is expected to not chain it to any lists.
 */
verdict translate_inner_packet(struct tuple *tuple, struct fragment *in_inner,
		struct fragment *out_outer)
{
	struct packet *dummy_pkt_in = NULL;
	struct packet *dummy_pkt_out = NULL;
	struct fragment *out_inner = NULL;
	struct translation_steps *step;
	verdict result = VER_DROP;

	step = &steps[in_inner->l3_hdr.proto][in_inner->l4_hdr.proto];

	/* Actually translate the inner packet. */
	result = translate(tuple, in_inner, &out_inner, step);
	if (result != VER_CONTINUE)
		return result;

	if (is_error(pkt_create(in_inner, &dummy_pkt_in)))
		goto end;
	if (is_error(pkt_create(out_inner, &dummy_pkt_out)))
		goto end;
	result = step->l4_post_function(tuple, dummy_pkt_in, dummy_pkt_out);
	if (result != VER_CONTINUE)
		goto end;

	/* Finally set the values this function is meant for. */
	out_outer->payload.len = out_inner->skb->len;
	out_outer->payload.ptr = kmalloc(out_outer->payload.len, GFP_ATOMIC);
	out_outer->payload.ptr_needs_kfree = true;
	if (!out_outer->payload.ptr)
		goto end;
	memcpy(out_outer->payload.ptr, skb_network_header(out_inner->skb), out_outer->payload.len);

	result = VER_CONTINUE;
	/* Fall through. */

end:
	if (dummy_pkt_out)
		pkt_kfree(dummy_pkt_out);
	else
		frag_kfree(out_inner);

	if (dummy_pkt_in) {
		/*
		 * Because we want memory allocations to be as symmetric as possible, the fragment has to
		 * be freed outside. So destroy everything but the fragment.
		 */
		list_del(&in_inner->list_hook);
		INIT_LIST_HEAD(&in_inner->list_hook); /* Unpoison. */
		pkt_kfree(dummy_pkt_in);
	}

	return result;
}

/**
 * By the time this function is called, "out"'s fields (including its fragments) are properly
 * initialized, but each fragments' skb are not.
 *
 * Of course, Linux doesn't give two shits about struct packets and struct fragments, so the skbs
 * need to be fixed eventually. Because of hairpinning (i. e. 'out' becoming an 'in' packet), I'd
 * much rather do it in this step than during the send_packet module. Also we get the added benefit
 * of translate_packet not returning half-baked output to the core.
 *
 * This is not part of the RFC; I added it because Linux needs it.
 *
 * Also note: I'm not familiar with all of skb's fields and I feel the documentation is a little
 * lacking, so I'm just fixing what I know.
 */
static verdict post_process(struct tuple *tuple, struct packet *in, struct packet *out)
{
	struct fragment *frag;
	struct sk_buff *skb;
	verdict result;
	struct translation_steps *step = &steps[pkt_get_l3proto(in)][pkt_get_l4proto(in)];

	result = step->l4_post_function(tuple, in, out);
	if (result != VER_CONTINUE)
		return result;

#ifndef UNIT_TESTING

	list_for_each_entry(frag, &out->fragments, list_hook) {
		skb = frag->skb;
		/* Moved skb->protocol to frag_create_skb() and divide(). */
		/* Moved skb->mark to translate() and divide(). */

		/*
		 * I'm not sure if I should only route the first fragment or all of them separately.
		 * Well, there's the routing cache, so this shouldn't be too slow.
		 */
		if (!frag->dst) {
			switch (frag->l3_hdr.proto) {
			case L3PROTO_IPV6:
				frag->dst = route_ipv6(frag->l3_hdr.ptr, frag->l4_hdr.ptr, frag->l4_hdr.proto,
						skb->mark);
				break;
			case L3PROTO_IPV4:
				frag->dst = route_ipv4(frag->l3_hdr.ptr, frag->l4_hdr.ptr, frag->l4_hdr.proto,
						skb->mark);
				break;
			}

			if (!frag->dst)
				return VER_DROP;
		}

		skb->dev = frag->dst->dev;
		skb_dst_set(skb, frag->dst);
	}

#endif

	return VER_CONTINUE;
}

verdict translating_the_packet(struct tuple *tuple, struct packet *in, struct packet **out)
{
	struct fragment *current_in;
	verdict result;

	log_debug("Step 4: Translating the Packet");

	if (is_error(pkt_alloc(out)))
		return VER_DROP;

	list_for_each_entry(current_in, &in->fragments, list_hook) {
		result = translate_fragment(current_in, tuple, *out);
		if (result != VER_CONTINUE)
			goto fail;
	}

	result = post_process(tuple, in, *out);
	if (result != VER_CONTINUE)
		goto fail;

	log_debug("Done step 4.");

	return VER_CONTINUE;

fail:
	pkt_kfree(*out);
	*out = NULL;
	return result;
}
