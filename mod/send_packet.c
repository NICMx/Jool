#include "nat64/mod/send_packet.h"
#include "nat64/comm/constants.h"
#include "nat64/comm/types.h"
#include "nat64/mod/stats.h"
#include "nat64/mod/icmp_wrapper.h"
#ifdef BENCHMARK
#include "nat64/mod/log_time.h"
#endif

#include <linux/version.h>
#include <linux/list.h>
#include <linux/icmp.h>
#include <net/ip.h>
#include <net/ip6_route.h>
#include <net/route.h>


static struct sendpkt_config *config;

int sendpkt_init(void)
{
	config = kmalloc(sizeof(*config), GFP_ATOMIC);
	if (!config)
		return -ENOMEM;

	config->min_ipv6_mtu = TRAN_DEF_MIN_IPV6_MTU;

	return 0;
}

void sendpkt_destroy(void)
{
	kfree(config);
}

int sendpkt_clone_config(struct sendpkt_config *clone)
{
	rcu_read_lock_bh();
	*clone = *rcu_dereference_bh(config);
	rcu_read_unlock_bh();
	return 0;
}

int sendpkt_set_config(enum sendpkt_type type, size_t size, void *value)
{
	struct sendpkt_config *tmp_config;
	struct sendpkt_config *old_config;

	if (type != MIN_IPV6_MTU) {
		log_err("Unknown config type for the 'send packet' module: %u", type);
		return -EINVAL;
	}

	if (size != sizeof(__u16)) {
		log_err("Expected an 2-byte integer, got %zu bytes.", size);
		return -EINVAL;
	}

	tmp_config = kmalloc(sizeof(*tmp_config), GFP_KERNEL);
	if (!tmp_config)
		return -ENOMEM;

	old_config = config;
	*tmp_config = *old_config;

	tmp_config->min_ipv6_mtu = *((__u16 *) value);

	rcu_assign_pointer(config, tmp_config);
	synchronize_rcu_bh();
	kfree(old_config);
	return 0;
}

int sendpkt_route4(struct sk_buff *skb)
{
	struct iphdr *hdr_ip = ip_hdr(skb);
	struct flowi4 flow;
	struct rtable *table;
	int error;

	/* Sometimes Jool needs to route prematurely, so don't sweat this on the normal pipelines. */
	if (skb_dst(skb))
		return 0;

	memset(&flow, 0, sizeof(flow));
	/* flow.flowi4_oif; */
	/* flow.flowi4_iif; */
	flow.flowi4_mark = skb->mark;
	flow.flowi4_tos = RT_TOS(hdr_ip->tos);
	flow.flowi4_scope = RT_SCOPE_UNIVERSE;
	flow.flowi4_proto = hdr_ip->protocol;
	/*
	 * TODO (help) Don't know if we should set FLOWI_FLAG_PRECOW_METRICS. Does the kernel ever
	 * create routes on Jool's behalf?
	 * TODO (help) We should probably set FLOWI_FLAG_ANYSRC (for virtual-interfaceless support).
	 * If you change it, the corresponding attribute in route_ipv6() should probably follow.
	 */
	flow.flowi4_flags = 0;
	/* Only used by XFRM ATM (kernel/Documentation/networking/secid.txt). */
	/* flow.flowi4_secid; */
	/* It appears this one only introduces noise. */
	/* flow.saddr = hdr_ip->saddr; */
	flow.daddr = hdr_ip->daddr;

	{
		struct udphdr *hdr_udp;
		struct tcphdr *hdr_tcp;
		struct icmphdr *hdr_icmp4;

		switch (skb_l4_proto(skb)) {
		case L4PROTO_TCP:
			hdr_tcp = tcp_hdr(skb);
			flow.fl4_sport = hdr_tcp->source;
			flow.fl4_dport = hdr_tcp->dest;
			break;
		case L4PROTO_UDP:
			hdr_udp = udp_hdr(skb);
			flow.fl4_sport = hdr_udp->source;
			flow.fl4_dport = hdr_udp->dest;
			break;
		case L4PROTO_ICMP:
			hdr_icmp4 = icmp_hdr(skb);
			flow.fl4_icmp_type = hdr_icmp4->type;
			flow.fl4_icmp_code = hdr_icmp4->code;
			break;
		}
	}

	/*
	 * I'm using neither ip_route_output_key() nor ip_route_output_flow() because those seem to
	 * mind about XFRM (= IPsec), which is probably just troublesome overhead given that "any
	 * protocols that protect IP header information are essentially incompatible with NAT64"
	 * (RFC 6146).
	 */
	table = __ip_route_output_key(&init_net, &flow);
	if (!table || IS_ERR(table)) {
		error = abs(PTR_ERR(table));
		log_debug("__ip_route_output_key() returned %d. Cannot route packet.", error);
		inc_stats(skb, IPSTATS_MIB_OUTNOROUTES);
		return -error;
	}
	if (table->dst.error) {
		error = abs(table->dst.error);
		log_debug("__ip_route_output_key() returned error %d. Cannot route packet.", error);
		inc_stats(skb, IPSTATS_MIB_OUTNOROUTES);
		return -error;
	}
	if (!table->dst.dev) {
		dst_release(&table->dst);
		log_debug("I found a dst entry with no dev. I don't know what to do; failing...");
		inc_stats(skb, IPSTATS_MIB_OUTNOROUTES);
		return -EINVAL;
	}

	skb_dst_set(skb, &table->dst);
	skb->dev = table->dst.dev;

	return 0;
}

int sendpkt_route6(struct sk_buff *skb)
{
	struct ipv6hdr *hdr_ip = ipv6_hdr(skb);
	struct flowi6 flow;
	struct dst_entry *dst;
	struct hdr_iterator iterator;
	hdr_iterator_result iterator_result;

	if (skb_dst(skb))
		return 0;

	hdr_iterator_init(&iterator, hdr_ip);
	iterator_result = hdr_iterator_last(&iterator);

	memset(&flow, 0, sizeof(flow));
	/* flow->flowi6_oif; */
	/* flow->flowi6_iif; */
	flow.flowi6_mark = skb->mark;
	flow.flowi6_tos = get_traffic_class(hdr_ip);
	flow.flowi6_scope = RT_SCOPE_UNIVERSE;
	flow.flowi6_proto = (iterator_result == HDR_ITERATOR_END) ? iterator.hdr_type : 0;
	flow.flowi6_flags = 0;
	/* flow->flowi6_secid; */
	flow.saddr = hdr_ip->saddr;
	flow.daddr = hdr_ip->daddr;
	flow.flowlabel = get_flow_label(hdr_ip);
	{
		struct udphdr *hdr_udp;
		struct tcphdr *hdr_tcp;
		struct icmp6hdr *hdr_icmp6;

		switch (skb_l4_proto(skb)) {
		case L4PROTO_TCP:
			hdr_tcp = tcp_hdr(skb);
			flow.fl6_sport = hdr_tcp->source;
			flow.fl6_dport = hdr_tcp->dest;
			break;
		case L4PROTO_UDP:
			hdr_udp = udp_hdr(skb);
			flow.fl6_sport = hdr_udp->source;
			flow.fl6_dport = hdr_udp->dest;
			break;
		case L4PROTO_ICMP:
			hdr_icmp6 = icmp6_hdr(skb);
			flow.fl6_icmp_type = hdr_icmp6->icmp6_type;
			flow.fl6_icmp_code = hdr_icmp6->icmp6_code;
			break;
		}
	}

	dst = ip6_route_output(&init_net, NULL, &flow);
	if (!dst) {
		log_debug("ip6_route_output() returned NULL. Cannot route packet.");
		inc_stats(skb, IPSTATS_MIB_OUTNOROUTES);
		return -EINVAL;
	}
	if (dst->error) {
		int error = abs(dst->error);
		log_debug("ip6_route_output() returned error %d. Cannot route packet.", error);
		inc_stats(skb, IPSTATS_MIB_OUTNOROUTES);
		return -error;
	}

	skb_dst_set(skb, dst);
	skb->dev = dst->dev;

	return 0;
}

static void set_frag_headers(struct ipv6hdr *hdr6_old, struct ipv6hdr *hdr6_new,
		u16 packet_size, u16 offset, bool mf)
{
	struct frag_hdr *hdrfrag_old = (struct frag_hdr *) (hdr6_old + 1);
	struct frag_hdr *hdrfrag_new = (struct frag_hdr *) (hdr6_new + 1);

	hdr6_new->payload_len = cpu_to_be16(packet_size - sizeof(*hdr6_new));

	hdrfrag_new->nexthdr = hdrfrag_old->nexthdr;
	hdrfrag_new->reserved = hdrfrag_old->reserved;
	hdrfrag_new->frag_off = build_ipv6_frag_off_field(offset, mf);
	hdrfrag_new->identification = hdrfrag_old->identification;
}

/**
 * Helper function for divide.
 * Create a fragment header to a packet if required.
 */
static void create_fragment_header(struct sk_buff *skb, struct iphdr *ip4_hdr)
{
	struct ipv6hdr *first_hdr6 = ipv6_hdr(skb);
	struct ipv6hdr *tmp_hdr6;
	struct frag_hdr *fragment_hdr;

	tmp_hdr6 = (struct ipv6hdr *) skb_push(skb, 8);
	memset(tmp_hdr6, 0, sizeof(*fragment_hdr));

	first_hdr6 = memmove(tmp_hdr6, first_hdr6, sizeof(*first_hdr6));
	fragment_hdr = (struct frag_hdr *) (first_hdr6 + 1);
	memset(fragment_hdr, 0, sizeof(*fragment_hdr));

	fragment_hdr->nexthdr = first_hdr6->nexthdr;
	first_hdr6->nexthdr = NEXTHDR_FRAGMENT;
	fragment_hdr->reserved = 0;
	fragment_hdr->frag_off = build_ipv6_frag_off_field(0, false);
	fragment_hdr->identification = cpu_to_be32(be16_to_cpu(ip4_hdr->id));

	first_hdr6->payload_len = htonl(ntohl(first_hdr6->payload_len) + sizeof(struct frag_hdr));

	skb_reset_network_header(skb);
}

static struct sk_buff *create_skb_frag(struct sk_buff *breaking_skb, u16 len)
{
	struct sk_buff *result_skb;

	result_skb = alloc_skb(LL_MAX_HEADER /* kernel's reserved + layer 2. */
			+ len, /* l3 header + l4 header + packet data. */
			GFP_ATOMIC);
	if (!result_skb) {
		inc_stats(breaking_skb, IPSTATS_MIB_FRAGFAILS);
		return NULL;
	}

	skb_reserve(result_skb, LL_MAX_HEADER);
	skb_put(result_skb, len);
	skb_reset_mac_header(result_skb);
	skb_reset_network_header(result_skb);
	skb_set_transport_header(result_skb, sizeof(struct ipv6hdr) + sizeof(struct frag_hdr));
	result_skb->protocol = breaking_skb->protocol;
	result_skb->mark = breaking_skb->mark;
	skb_dst_set(result_skb, dst_clone(skb_dst(breaking_skb)));
	result_skb->dev = breaking_skb->dev;

	skb_set_jcb(result_skb, L3PROTO_IPV6, skb_l4_proto(breaking_skb),
			skb_transport_header(result_skb),
			skb_original_skb(breaking_skb));

	return result_skb;
}

/**
 * Fragments "frag" until all the pieces are at most "min_ipv6_mtu" bytes long.
 * "min_ipv6_mtu" comes from the user's configuration.
 * The resulting smaller fragments are appended to frag's list (frag->next).
 *
 * Assumes the following:
 * - These fields from skb are properly set: network_header, head, data and tail.
 * - skb has either no extension headers (and there's reserved room for a fragment header),
 *   or a single fragment header.
 *
 * TODO all these u16, shouldn't they be unsigned ints?
 */
static int divide(struct sk_buff *skb, __u16 min_ipv6_mtu, struct iphdr *ip4_hdr)
{
	unsigned char *current_ptr;
	struct sk_buff *new_skb;
	struct sk_buff *prev_skb;
	/* "last" skb involved here. Not necessarily the last skb of the list. */
	struct sk_buff *last_skb;
	struct ipv6hdr *first_hdr6;
	u16 hdrs_size;
	u16 payload_max_size;
	u16 original_fragment_offset;
	bool original_mf;

	/* Prepare the helper values. */
	min_ipv6_mtu &= 0xFFF8;

	if (ipv6_hdr(skb)->nexthdr != NEXTHDR_FRAGMENT)
		create_fragment_header(skb, ip4_hdr);

	first_hdr6 = ipv6_hdr(skb);

	hdrs_size = sizeof(struct ipv6hdr) + sizeof(struct frag_hdr);
	payload_max_size = min_ipv6_mtu - hdrs_size;

	{
		struct frag_hdr *frag_header = (struct frag_hdr *) (first_hdr6 + 1);

		original_fragment_offset = get_fragment_offset_ipv6(frag_header);
		original_mf = is_more_fragments_set_ipv6(frag_header);
	}

	set_frag_headers(first_hdr6, first_hdr6, min_ipv6_mtu, original_fragment_offset, true);
	prev_skb = skb;
	last_skb = skb->next;

	/* Copy frag's overweight to newly-created fragments.  */
	current_ptr = skb_network_header(skb) + min_ipv6_mtu;
	do {
		bool is_last = (skb_tail_pointer(skb) - current_ptr <= payload_max_size);
		u16 actual_payload_size = is_last
					? (skb_tail_pointer(skb) - current_ptr)
					: (payload_max_size & 0xFFF8);
		u16 actual_total_size = hdrs_size + actual_payload_size;

		new_skb = create_skb_frag(skb, actual_total_size);
		if (!new_skb)
			return -ENOMEM; /* TODO is someone deleting the new skbs? */

		memcpy(ipv6_hdr(new_skb), first_hdr6, sizeof(*first_hdr6));
		set_frag_headers(first_hdr6, ipv6_hdr(new_skb), actual_total_size,
				original_fragment_offset + (current_ptr - skb->data - hdrs_size),
				is_last ? original_mf : true);
		/* TODO This looks sensitive to pages. */
		memcpy(skb_network_header(new_skb) + hdrs_size, current_ptr, actual_payload_size);

		prev_skb->next = new_skb;

		current_ptr += actual_payload_size;
		prev_skb = new_skb;

		new_skb->next = NULL;
		inc_stats(skb, IPSTATS_MIB_FRAGCREATES);
	} while (current_ptr < skb_tail_pointer(skb));

	if (last_skb)
		new_skb->next = last_skb;

	/* Finally truncate the original packet and we're done. */
	skb_put(skb, -(skb->len - min_ipv6_mtu));
	inc_stats(skb, IPSTATS_MIB_FRAGOKS);
	return 0;
}

/**
 * Might actually trim to a slightly smaller length than new_len, because I need to align new_len,
 * otherwise the checksum update will be a mess.
 * (csum_partial() seems to require the start of the data to be aligned to a 32-bit boundary.)
 */
static int icmp6_trim(struct sk_buff *skb, unsigned int new_len)
{
	struct icmp6hdr *hdr = icmp6_hdr(skb);
	__wsum csum = ~csum_unfold(hdr->icmp6_cksum);
	__be16 tmp;

	/*
	 * "After the ethernet header, the protocol header will be aligned on at least a 4-byte
	 * boundary. Nearly all of the IPV4 and IPV6 protocol processing assumes that the headers are
	 * properly aligned." (http://vger.kernel.org/~davem/skb_data.html)
	 *
	 * Therefore, simply truncate the entire packet size to a multiple of 4.
	 */
	new_len = round_down(new_len, 4);
	if (new_len < sizeof(struct ipv6hdr) + sizeof(struct icmp6hdr))
		return -EINVAL;

	/* Substract the chunk we're truncating. */
	csum = csum_sub(csum, csum_partial(skb_network_header(skb) + new_len, skb->len - new_len, 0));
	/* Substract the difference of the "length" field from the pseudoheader. */
	tmp = cpu_to_be16(skb->len - new_len);
	csum = csum_sub(csum, csum_partial(&tmp, sizeof(tmp), 0));

	hdr->icmp6_cksum = csum_fold(csum);
	/* TODO (fine) There seems to be a problem with RFC 1624... review it later. This works. */
	if (hdr->icmp6_cksum == (__force __sum16) 0xFFFF)
		hdr->icmp6_cksum = 0;

	skb_trim(skb, new_len);
	ipv6_hdr(skb)->payload_len = cpu_to_be16(skb->len - sizeof(struct ipv6hdr));
	return 0;
}

static bool skb_is_icmp6_error(struct sk_buff *skb)
{
	return (skb_l4_proto(skb) == L4PROTO_ICMP) && is_icmp6_error(icmp6_hdr(skb)->icmp6_type);
}

static bool skb_is_icmp4_error(struct sk_buff *skb)
{
	return (skb_l4_proto(skb) == L4PROTO_ICMP) && is_icmp4_error(icmp_hdr(skb)->type);
}

static void reply_frag_needed(struct sk_buff *skb, unsigned int mtu)
{
	log_debug("Packet is too big (%u bytes; MTU: %u); dropping.", skb->len, mtu);
	icmp64_send(skb, ICMPERR_FRAG_NEEDED, mtu);
	inc_stats(skb, IPSTATS_MIB_INTOOBIGERRORS);
}

static unsigned int get_nexthop_mtu(struct sk_buff *skb)
{
#ifndef UNIT_TESTING
	return skb_dst(skb)->dev->mtu;
#else
	return 1500;
#endif
}

static __u16 get_min_mtu6(void)
{
	__u16 result;

	rcu_read_lock_bh();
	result = rcu_dereference_bh(config)->min_ipv6_mtu;
	rcu_read_unlock_bh();

	return result;
}

static int fragment_if_too_big(struct sk_buff *skb_in, struct sk_buff *skb_out)
{
	unsigned int mtu;

	switch (skb_l3_proto(skb_out)) {
	case L3PROTO_IPV6: /* 4 to 6 */
		if (skb_is_icmp6_error(skb_out)) {
			mtu = get_min_mtu6();
			return (skb_out->len > mtu) ? icmp6_trim(skb_out, mtu) : 0;
		}

		if (is_dont_fragment_set(ip_hdr(skb_in))) {
			mtu = get_nexthop_mtu(skb_out);
			if (skb_out->len > mtu) {
				reply_frag_needed(skb_out, mtu - 20);
				return -EINVAL;
			}
		} else {
			mtu = get_min_mtu6();
			if (skb_out->len > mtu)
				return divide(skb_out, mtu, ip_hdr(skb_in));
		}

		return 0;

	case L3PROTO_IPV4: /* 6 to 4 */
		if (!skb_is_icmp4_error(skb_out) && is_dont_fragment_set(ip_hdr(skb_out))) {
			mtu = get_nexthop_mtu(skb_out);
			if (skb_out->len > mtu) {
				reply_frag_needed(skb_out, get_nexthop_mtu(skb_out) + 20);
				return -EINVAL;
			}
		}
		/* TODO test the kernel handles trimming and fragmentation fine. */
	}

	return 0;
}

static void revert_frag_list(struct sk_buff *skb)
{
	struct sk_buff *frag;

	skb_walk_frags(skb, frag) {
		skb->len -= skb_payload_len_frag(frag);
		skb->data_len -= skb_payload_len_frag(frag);
		skb->truesize -= frag->truesize;
	}

	skb->next = skb_shinfo(skb)->frag_list;
	skb_shinfo(skb)->frag_list = NULL;

	/* TODO revert ->data. */
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 0)
static void kfree_skb_list(struct sk_buff *segs)
{
	while (segs) {
		struct sk_buff *next = segs->next;
		kfree_skb(segs);
		segs = next;
	}
}
#endif

verdict sendpkt_send(struct sk_buff *in_skb, struct sk_buff *out_skb)
{
	struct sk_buff *next_skb = out_skb;
	struct sk_buff *tmp;
	struct dst_entry *dst;
	int error = 0;

#ifdef BENCHMARK
	struct timespec end_time;
	getnstimeofday(&end_time);
	logtime(&skb_jcb(out_skb)->start_time, &end_time, skb_l3_proto(out_skb),
			skb_l4_proto(out_skb));
#endif

	revert_frag_list(out_skb);

	while (next_skb) {
		if (WARN(!next_skb->dev, "Packet has no destination device."))
			goto fail;
		dst = skb_dst(next_skb);
		if (WARN(!dst, "Packet has no destination."))
			goto fail;
		if (WARN(!dst->dev, "Packet's destination has no device."))
			goto fail;

		if (is_error(fragment_if_too_big(in_skb, next_skb)))
			goto fail;

		out_skb = next_skb;
		next_skb = out_skb->next;
		out_skb->next = out_skb->prev = NULL;

		log_debug("Sending skb via device '%s'...", dst->dev->name);
		print_skb_mini(out_skb);

		switch (skb_l3_proto(out_skb)) {
		case L3PROTO_IPV6:
			skb_clear_cb(out_skb);
			error = ip6_local_out(out_skb); /* Implicit kfree_skb(out_skb) goes here. */
			break;
		case L3PROTO_IPV4:
			skb_clear_cb(out_skb);
			error = ip_local_out(out_skb); /* Implicit kfree_skb(out_skb) goes here. */
			break;
		}

		if (error) {
			log_debug("The kernel's packet dispatch function returned errcode %d.", error);
			goto fail;
		}
	}

	return VER_CONTINUE;

fail:
	/*
	 * The rest will also probably fail, so don't waste time trying to send them.
	 * If there were more skbs, they were fragments anyway, so the receiving node will
	 * fail to reassemble them.
	 */
	inc_stats(next_skb, IPSTATS_MIB_OUTDISCARDS);
	kfree_skb_list(next_skb);
	return VER_DROP;
}
