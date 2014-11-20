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
static int divide(struct sk_buff *skb, __u16 min_ipv6_mtu)
{
	unsigned char *current_p;
	struct sk_buff *new_skb;
	struct sk_buff *prev_skb;
	/* "last" skb involved here. Not necessarily the last skb of the list. */
	struct sk_buff *last_skb;
	struct ipv6hdr *first_hdr6 = ipv6_hdr(skb);
	u16 hdrs_size;
	u16 payload_max_size;
	u16 original_fragment_offset;
	bool original_mf;

	/* Prepare the helper values. */
	min_ipv6_mtu &= 0xFFF8;

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
	current_p = skb_network_header(skb) + min_ipv6_mtu;
	do {
		bool is_last = (skb_tail_pointer(skb) - current_p <= payload_max_size);
		u16 actual_payload_size = is_last
					? (skb_tail_pointer(skb) - current_p)
					: (payload_max_size & 0xFFF8);
		u16 actual_total_size = hdrs_size + actual_payload_size;

		new_skb = alloc_skb(LL_MAX_HEADER /* kernel's reserved + layer 2. */
				+ actual_total_size, /* l3 header + l4 header + packet data. */
				GFP_ATOMIC);
		if (!new_skb) {
			inc_stats(skb, IPSTATS_MIB_FRAGFAILS);
			return -ENOMEM;
		}

		skb_reserve(new_skb, LL_MAX_HEADER);
		skb_put(new_skb, actual_total_size);
		skb_reset_mac_header(new_skb);
		skb_reset_network_header(new_skb);
		skb_set_transport_header(new_skb, hdrs_size);
		new_skb->protocol = skb->protocol;
		new_skb->mark = skb->mark;
		skb_dst_set(new_skb, dst_clone(skb_dst(skb)));
		new_skb->dev = skb->dev;

		set_frag_headers(first_hdr6, ipv6_hdr(new_skb), actual_total_size,
				original_fragment_offset + (current_p - skb->data - hdrs_size),
				is_last ? original_mf : true);
		memcpy(skb_network_header(new_skb) + hdrs_size, current_p, actual_payload_size);

		skb_set_jcb(new_skb, L3PROTO_IPV6, skb_l4_proto(skb),
				skb_transport_header(new_skb),
				skb_original_skb(skb));

		prev_skb->next = new_skb;
		new_skb->prev = prev_skb;

		current_p += actual_payload_size;
		prev_skb = new_skb;

		new_skb->next = NULL;
		inc_stats(skb, IPSTATS_MIB_FRAGCREATES);
	} while (current_p < skb_tail_pointer(skb));

	if (last_skb) {
		last_skb->prev = new_skb;
		new_skb->next = last_skb;
	}

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
static int icmp6_trim(struct sk_buff *skb, __u16 new_len)
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

static int fragment_if_too_big(struct sk_buff *skb_in, struct sk_buff *skb_out)
{
	__u16 min_ipv6_mtu;

	if (skb_l3_proto(skb_out) == L3PROTO_IPV4) {
#ifndef UNIT_TESTING
		__u16 min_ipv4_mtu = skb_dst(skb_out)->dev->mtu;
		if (is_dont_fragment_set(ip_hdr(skb_out)) && (skb_out->len > min_ipv4_mtu)) {
			icmp64_send(skb_out, ICMPERR_FRAG_NEEDED, min_ipv4_mtu + 20);
			log_debug("Packet is too big (%u bytes; MTU: %u); dropping.", skb_out->len, min_ipv4_mtu);
			inc_stats(skb_out, IPSTATS_MIB_INTOOBIGERRORS);
			return -EINVAL;
		}
#endif
		return 0; /* IPv4 routers fragment dandily, so let them do it. */
	}

	rcu_read_lock_bh();
	min_ipv6_mtu = rcu_dereference_bh(config)->min_ipv6_mtu;
	rcu_read_unlock_bh();

	if (skb_out->len <= min_ipv6_mtu)
		return 0; /* No need for fragmentation. */

	if (skb_l4_proto(skb_out) == L4PROTO_ICMP && is_icmp6_error(icmp6_hdr(skb_out)->icmp6_type)) {
		/* ICMP errors are supposed to be truncated, not fragmented. */
		return icmp6_trim(skb_out, min_ipv6_mtu);
	}

	if (is_dont_fragment_set(ip_hdr(skb_in))) {
		/* We're not supposed to fragment; yay. */
		icmp64_send(skb_in, ICMPERR_FRAG_NEEDED, min_ipv6_mtu - 20);
		log_debug("Packet is too big (%u bytes; MTU: %u); dropping.", skb_out->len, min_ipv6_mtu);
		inc_stats(skb_in, IPSTATS_MIB_INTOOBIGERRORS);
		return -EINVAL;
	}

	return divide(skb_out, min_ipv6_mtu);
}

verdict sendpkt_send(struct sk_buff *in_skb, struct sk_buff *out_skb)
{
	struct sk_buff *next_skb = out_skb;
	struct dst_entry *dst;
	int error = 0;
#ifdef BENCHMARK
	struct timespec end_time;
	getnstimeofday(&end_time);
	logtime(&skb_jcb(out_skb)->start_time, &end_time, skb_l3_proto(out_skb),
			skb_l4_proto(out_skb));
#endif
	while (next_skb) {
		if (is_error(fragment_if_too_big(in_skb, next_skb)))
			goto fail;

		out_skb = next_skb;
		next_skb = out_skb->next;
		out_skb->next = out_skb->prev = NULL;

		dst = skb_dst(out_skb);

		if (WARN(!dst || !dst->dev, "I'm trying to send a packet that isn't routed.")) {
			kfree_skb(out_skb);
			goto fail;
		}

		log_debug("Sending skb via device '%s'...", dst->dev->name);

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
			log_debug("The kernel's packet dispatch function returned errcode %d. "
					"Could not send packet.", error);
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
	inc_stats(out_skb, IPSTATS_MIB_OUTDISCARDS);
	kfree_skb_queued(next_skb);
	return VER_DROP;
}
