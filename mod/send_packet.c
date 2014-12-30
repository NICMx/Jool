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
static const unsigned int HDRS_LEN = sizeof(struct ipv6hdr) + sizeof(struct frag_hdr);

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

/**
 * Caution: fragments created by this function will have unset header pointers.
 */
static struct sk_buff *create_skb_frag(struct sk_buff *breaking_skb, unsigned int payload_len)
{
	struct sk_buff *result_skb;

	result_skb = alloc_skb(LL_MAX_HEADER /* kernel's reserved + layer 2. */
			+ HDRS_LEN /* l3 header. */
			+ payload_len, /* packet data. */
			GFP_ATOMIC);
	if (!result_skb) {
		inc_stats(breaking_skb, IPSTATS_MIB_FRAGFAILS);
		return NULL;
	}

	skb_reserve(result_skb, LL_MAX_HEADER + HDRS_LEN);
	skb_put(result_skb, payload_len);

	result_skb->protocol = breaking_skb->protocol;
	result_skb->mark = breaking_skb->mark;
	/* TODO is this really necessary? */
	skb_dst_set(result_skb, dst_clone(skb_dst(breaking_skb)));
	result_skb->dev = breaking_skb->dev;

	skb_set_jcb(result_skb, L3PROTO_IPV6, skb_l4_proto(breaking_skb), true,
			result_skb->data,
			skb_original_skb(breaking_skb));

	return result_skb;
}

/**
 * Fragments "skb" by sending its surplus to new skbs. The surplus is defined by "trim_len" and
 * "payload_mtu".
 *
 * The resulting fragments are appended to skb's list (skb->next);
 * skb_shinfo(skb)->frag_list is ignored because this function is convoluted enough as it is.
 * Calling code needs to fix this.
 *
 * Assumes any skbs involved lack a fragment header and aren't paged.
 *
 * @param trim_len if skb's length is larger than trim_len, skb will be truncated to trim_len.
 * @param payload_mtu maximum allowable length for skb's layer 3 payload.
 *
 * "trim_len" and "payload_mtu" are separated because the kernel handles the lengths of first and
 * subsequent fragments differently.
 */
static int divide(struct sk_buff *skb, unsigned int trim_len, unsigned int payload_mtu)
{
	unsigned char *current_ptr;
	struct sk_buff *prev_skb;

	if (skb_headlen(skb) <= trim_len)
		return 0;

	/* Copy frag's overweight to newly-created fragments. */
	prev_skb = skb;
	current_ptr = skb->data + trim_len;
	do {
		bool is_last = (skb_tail_pointer(skb) - current_ptr) <= payload_mtu;
		unsigned int payload_len = is_last ? (skb_tail_pointer(skb) - current_ptr) : payload_mtu;
		struct sk_buff *new_skb;

		new_skb = create_skb_frag(skb, payload_len);
		if (!new_skb)
			return -ENOMEM;
		memcpy(new_skb->data, current_ptr, payload_len);

		new_skb->next = prev_skb->next;
		prev_skb->next = new_skb;
		prev_skb = new_skb;

		current_ptr += payload_len;
		inc_stats(skb, IPSTATS_MIB_FRAGCREATES);
	} while (current_ptr < skb_tail_pointer(skb));

	/* Truncate the original packet. */
	skb_set_tail_pointer(skb, trim_len);

	inc_stats(skb, IPSTATS_MIB_FRAGOKS);
	return 0;
}

/**
 * Might actually trim to a slightly smaller length than new_len, because I need to align new_len,
 * otherwise the checksum update will be a mess.
 * (csum_partial() seems to require the start of the data to be aligned to a 32-bit boundary.)
 *
 * **skb MUST be linearized**
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
	if (new_len < sizeof(struct ipv6hdr) + sizeof(struct icmp6hdr)) {
		log_debug("I was asked to trim an illegally short packet.");
		return -EINVAL;
	}

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

static int reply_frag_needed(struct sk_buff *skb, unsigned int mtu)
{
	log_debug("Packet is too big (%u bytes; MTU: %u); dropping.", skb->len, mtu);
	icmp64_send(skb, ICMPERR_FRAG_NEEDED, mtu);
	inc_stats(skb, IPSTATS_MIB_INTOOBIGERRORS);
	return -EINVAL;
}

static unsigned int get_nexthop_mtu(struct sk_buff *skb)
{
#ifndef UNIT_TESTING
	return skb_dst(skb)->dev->mtu;
#else
	return 1500;
#endif
}

static unsigned int get_min_mtu6(void)
{
	__u16 result;

	rcu_read_lock_bh();
	result = rcu_dereference_bh(config)->min_ipv6_mtu;
	rcu_read_unlock_bh();

	return result;
}

static void move_next_to_frag_list(struct sk_buff *skb)
{
	struct sk_buff *prev;
	struct sk_buff *tmp;

	if (!skb->next)
		return;

	for (tmp = skb->next; tmp; tmp = tmp->next) {
		skb->data_len += tmp->len;
		prev = tmp;
	}

	prev->next = skb_shinfo(skb)->frag_list;
	skb_shinfo(skb)->frag_list = skb->next;
	skb->next = NULL;
}

/* TODO test the kernel doesn't join fragments when min mtu6 < nexthop mtu. */
static int fragment_if_too_big(struct sk_buff *skb_in, struct sk_buff *skb_out)
{
	unsigned int mtu;
	int error;

	switch (skb_l3_proto(skb_out)) {
	case L3PROTO_IPV6: /* 4 to 6 */
		if (skb_is_icmp6_error(skb_out)) {
			mtu = get_min_mtu6();
			return (skb_out->len > mtu) ? icmp6_trim(skb_out, mtu) : 0;
		}

		if (is_dont_fragment_set(ip_hdr(skb_in))) {
			mtu = get_nexthop_mtu(skb_out);
			return (skb_len(skb_out) > mtu) ? reply_frag_needed(skb_out, mtu - 20) : 0;
		}

		mtu = get_min_mtu6();
		if (!skb_shinfo(skb_out)->frag_list && skb_out->len <= mtu)
			return 0;

		mtu &= 0xFFF8;
		error = divide(skb_out, mtu, mtu - HDRS_LEN);
		if (error) /* TODO rethink freeing? */
			return error;
		move_next_to_frag_list(skb_out);

		mtu -= HDRS_LEN; /* "mtu" is "l3 payload mtu" now. */
		skb_walk_frags(skb_out, skb_out) {
			error = divide(skb_out, mtu, mtu);
			if (error)
				return error;
		}

		return 0;

	case L3PROTO_IPV4: /* 6 to 4 */
		if (!skb_is_icmp4_error(skb_out) && is_dont_fragment_set(ip_hdr(skb_out))) {
			mtu = get_nexthop_mtu(skb_out);
			if (skb_out->len > mtu)
				return reply_frag_needed(skb_out, mtu + 20);
		}
		/* TODO test the kernel handles trimming and fragmentation fine. */
	}

	return 0;
}

verdict sendpkt_send(struct sk_buff *in_skb, struct sk_buff *out_skb)
{
	struct sk_buff *skb;
	struct dst_entry *dst;
	l3_protocol l3_proto;
	int error;

#ifdef BENCHMARK
	struct timespec end_time;
	getnstimeofday(&end_time);
	logtime(&skb_jcb(out_skb)->start_time, &end_time, skb_l3_proto(out_skb),
			skb_l4_proto(out_skb));
#endif

	if (WARN(!out_skb->dev, "Packet has no destination device."))
		goto fail;
	dst = skb_dst(out_skb);
	if (WARN(!dst, "Packet has no destination."))
		goto fail;
	if (WARN(!dst->dev, "Packet's destination has no device."))
		goto fail;

	error = fragment_if_too_big(in_skb, out_skb);
	if (error)
		goto fail;

	log_debug("Sending skb via device '%s'...", dst->dev->name);
	skb_print(out_skb);

	l3_proto = skb_l3_proto(out_skb);
	skb_clear_cb(out_skb);
	skb_walk_frags(out_skb, skb)
		skb_clear_cb(skb);

	/* TODO (issue #41) newer kernels don't have this. Review. */
	out_skb->local_df = true; /* FFS, kernel. */

	switch (l3_proto) {
	case L3PROTO_IPV6:
		error = ip6_local_out(out_skb); /* Implicit kfree_skb(out_skb) goes here. */
		break;
	case L3PROTO_IPV4:
		error = ip_local_out(out_skb); /* Implicit kfree_skb(out_skb) goes here. */
		break;
	}

	if (error) {
		log_debug("The kernel's packet dispatch function returned errcode %d.", error);
		return VER_DROP;
	}

	return VER_CONTINUE;

fail:
	inc_stats(out_skb, IPSTATS_MIB_OUTDISCARDS);
	kfree_skb(out_skb);
	return VER_DROP;
}
