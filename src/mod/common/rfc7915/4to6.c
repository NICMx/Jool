#include "mod/common/rfc7915/4to6.h"

#include <net/addrconf.h>
#include <net/ip6_checksum.h>

#include "common/constants.h"
#include "mod/common/linux_version.h"
#include "mod/common/log.h"
#include "mod/common/mapt.h"
#include "mod/common/rfc6052.h"
#include "mod/common/route.h"
#include "mod/common/steps/compute_outgoing_tuple.h"

/* Layer 3 only */
#define HDRS_LEN (sizeof(struct ipv6hdr) + sizeof(struct frag_hdr))

static __u8 xlat_nexthdr(__u8 protocol)
{
	return (protocol == IPPROTO_ICMP) ? NEXTHDR_ICMP : protocol;
}

static int generate_saddr6_nat64(struct xlation *state)
{
	struct jool_globals *cfg;
	struct in_addr tmp;

	cfg = &state->jool.globals;
	if (cfg->nat64.src_icmp6errs_better && pkt_is_icmp4_error(&state->in)) {
		/* Issue #132 behaviour. */
		tmp.s_addr = pkt_ip4_hdr(&state->in)->saddr;
		return __rfc6052_4to6(&cfg->pool6.prefix, &tmp,
				&state->flowx.v6.flowi.saddr);
	}

	/* RFC 6146 behaviour. */
	state->flowx.v6.flowi.saddr = state->out.tuple.src.addr6.l3;
	return 0;
}

static verdict xlat46_external_addresses(struct xlation *state)
{
	switch (xlator_get_type(&state->jool)) {
	case XT_NAT64:
		if (generate_saddr6_nat64(state))
			return drop(state, JSTAT46_SRC);
		state->flowx.v6.flowi.daddr = state->out.tuple.dst.addr6.l3;
		return VERDICT_CONTINUE;

	case XT_SIIT:
		return translate_addrs46_siit(state,
				&state->flowx.v6.flowi.saddr,
				&state->flowx.v6.flowi.daddr);
	case XT_MAPT:
		return translate_addrs46_mapt(state,
				&state->flowx.v6.flowi.saddr,
				&state->flowx.v6.flowi.daddr,
				false);
	}

	WARN(1, "xlator type is not SIIT, NAT64 nor MAP-T: %u",
			xlator_get_type(&state->jool));
	return drop(state, JSTAT_UNKNOWN);
}

static verdict xlat46_internal_addresses(struct xlation *state)
{
	struct bkp_skb_tuple bkp;
	verdict result;

	switch (xlator_get_type(&state->jool)) {
	case XT_NAT64:
		state->flowx.v6.inner_src = state->out.tuple.dst.addr6.l3;
		state->flowx.v6.inner_dst = state->out.tuple.src.addr6.l3;
		return VERDICT_CONTINUE;

	case XT_SIIT:
		result = become_inner_packet(state, &bkp, false);
		if (result != VERDICT_CONTINUE)
			return result;
		log_debug(state, "Translating internal addresses...");
		result = translate_addrs46_siit(state,
				&state->flowx.v6.inner_src,
				&state->flowx.v6.inner_dst);
		restore_outer_packet(state, &bkp, false);
		return result;

	case XT_MAPT:
		result = become_inner_packet(state, &bkp, false);
		if (result != VERDICT_CONTINUE)
			return result;
		log_debug(state, "Translating internal addresses...");
		result = translate_addrs46_mapt(state,
				&state->flowx.v6.inner_src,
				&state->flowx.v6.inner_dst,
				true);
		restore_outer_packet(state, &bkp, false);
		return result;
	}

	WARN(1, "xlator type is not SIIT, NAT64 nor MAP-T: %u",
			xlator_get_type(&state->jool));
	return drop(state, JSTAT_UNKNOWN);
}

static verdict xlat46_tcp_ports(struct xlation *state)
{
	struct flowi6 *flow6;
	struct tcphdr const *hdr;

	flow6 = &state->flowx.v6.flowi;
	switch (xlator_get_type(&state->jool)) {
	case XT_NAT64:
		flow6->fl6_sport = cpu_to_be16(state->out.tuple.src.addr6.l4);
		flow6->fl6_dport = cpu_to_be16(state->out.tuple.dst.addr6.l4);
		break;
	case XT_SIIT:
	case XT_MAPT:
		hdr = pkt_tcp_hdr(&state->in);
		flow6->fl6_sport = hdr->source;
		flow6->fl6_dport = hdr->dest;
	}

	return VERDICT_CONTINUE;
}

static verdict xlat46_udp_ports(struct xlation *state)
{
	struct flowi6 *flow6;
	struct udphdr const *udp;

	flow6 = &state->flowx.v6.flowi;
	switch (xlator_get_type(&state->jool)) {
	case XT_NAT64:
		flow6->fl6_sport = cpu_to_be16(state->out.tuple.src.addr6.l4);
		flow6->fl6_dport = cpu_to_be16(state->out.tuple.dst.addr6.l4);
		break;
	case XT_SIIT:
	case XT_MAPT:
		udp = pkt_udp_hdr(&state->in);
		flow6->fl6_sport = udp->source;
		flow6->fl6_dport = udp->dest;
	}

	return VERDICT_CONTINUE;
}

static verdict xlat46_icmp_type(struct xlation *state)
{
	struct icmphdr const *hdr;
	struct flowi6 *flow6;

	hdr = pkt_icmp4_hdr(&state->in);
	flow6 = &state->flowx.v6.flowi;

	switch (hdr->type) {
	case ICMP_ECHO:
		flow6->fl6_icmp_type = ICMPV6_ECHO_REQUEST;
		flow6->fl6_icmp_code = 0;
		return VERDICT_CONTINUE;

	case ICMP_ECHOREPLY:
		flow6->fl6_icmp_type = ICMPV6_ECHO_REPLY;
		flow6->fl6_icmp_code = 0;
		return VERDICT_CONTINUE;

	case ICMP_DEST_UNREACH:
		switch (hdr->code) {
		case ICMP_NET_UNREACH:
		case ICMP_HOST_UNREACH:
		case ICMP_SR_FAILED:
		case ICMP_NET_UNKNOWN:
		case ICMP_HOST_UNKNOWN:
		case ICMP_HOST_ISOLATED:
		case ICMP_NET_UNR_TOS:
		case ICMP_HOST_UNR_TOS:
			flow6->fl6_icmp_type = ICMPV6_DEST_UNREACH;
			flow6->fl6_icmp_code = ICMPV6_NOROUTE;
			return xlat46_internal_addresses(state);

		case ICMP_PROT_UNREACH:
			flow6->fl6_icmp_type = ICMPV6_PARAMPROB;
			flow6->fl6_icmp_code = ICMPV6_UNK_NEXTHDR;
			return xlat46_internal_addresses(state);

		case ICMP_PORT_UNREACH:
			flow6->fl6_icmp_type = ICMPV6_DEST_UNREACH;
			flow6->fl6_icmp_code = ICMPV6_PORT_UNREACH;
			return xlat46_internal_addresses(state);

		case ICMP_FRAG_NEEDED:
			flow6->fl6_icmp_type = ICMPV6_PKT_TOOBIG;
			flow6->fl6_icmp_code = 0;
			return xlat46_internal_addresses(state);

		case ICMP_NET_ANO:
		case ICMP_HOST_ANO:
		case ICMP_PKT_FILTERED:
		case ICMP_PREC_CUTOFF:
			flow6->fl6_icmp_type = ICMPV6_DEST_UNREACH;
			flow6->fl6_icmp_code = ICMPV6_ADM_PROHIBITED;
			return xlat46_internal_addresses(state);
		}
		break;

	case ICMP_TIME_EXCEEDED:
		flow6->fl6_icmp_type = ICMPV6_TIME_EXCEED;
		flow6->fl6_icmp_code = hdr->code;
		return xlat46_internal_addresses(state);

	case ICMP_PARAMETERPROB:
		flow6->fl6_icmp_type = ICMPV6_PARAMPROB;
		switch (hdr->code) {
		case ICMP_PTR_INDICATES_ERROR:
		case ICMP_BAD_LENGTH:
			flow6->fl6_icmp_code = ICMPV6_HDR_FIELD;
			return xlat46_internal_addresses(state);
		}
	}

	/*
	 * The following codes are known to fall through here:
	 * Information Request/Reply (15, 16), Timestamp and Timestamp Reply
	 * (13, 14), Address Mask Request/Reply (17, 18), Router Advertisement
	 * (9), Router Solicitation (10), Source Quench (4), Redirect (5),
	 * Alternative Host Address (6).
	 * This time there's no ICMP error.
	 */
	log_debug(state, "ICMPv4 messages type %u code %u lack an ICMPv6 counterpart.",
			hdr->type, hdr->code);
	return drop(state, JSTAT_UNKNOWN_ICMP4_TYPE);
}

static verdict compute_flowix46(struct xlation *state)
{
	struct flowi6 *flow6;
	verdict result;

	flow6 = &state->flowx.v6.flowi;

	flow6->flowi6_mark = state->in.skb->mark;
	flow6->flowi6_scope = RT_SCOPE_UNIVERSE;
	flow6->flowi6_proto = xlat_nexthdr(pkt_ip4_hdr(&state->in)->protocol);
	flow6->flowi6_flags = FLOWI_FLAG_ANYSRC;

	result = xlat46_external_addresses(state);
	if (result != VERDICT_CONTINUE)
		return result;

	switch (flow6->flowi6_proto) {
	case NEXTHDR_TCP:
		return xlat46_tcp_ports(state);
	case NEXTHDR_UDP:
		return xlat46_udp_ports(state);
	case NEXTHDR_ICMP:
		return xlat46_icmp_type(state);
	}

	return VERDICT_CONTINUE;
}

/**
 * Initializes state->dst.
 * Please note: The resulting dst might be NULL even on VERDICT_CONTINUE.
 * Handle properly.
 */
static verdict predict_route46(struct xlation *state)
{
	struct flowi6 *flow6;

#ifdef UNIT_TESTING
	return VERDICT_CONTINUE;
#endif

	if (state->is_hairpin_1) {
		log_debug(state, "Packet is hairpinning; skipping routing.");
	} else {
		flow6 = &state->flowx.v6.flowi;
		log_debug(state, "Routing: %pI6c->%pI6c", &flow6->saddr,
				&flow6->daddr);
		state->dst = route6(&state->jool, flow6);
		if (!state->dst)
			return untranslatable(state, JSTAT_FAILED_ROUTES);
	}

	if (ipv6_addr_any(&flow6->saddr)) { /* empty pool6791v6 */
		if (WARN(!xlator_is_siit(&state->jool),
			 "Zero source address on not SIIT!"))
			goto panic;
		if (WARN(!is_icmp4_error(pkt_icmp4_hdr(&state->in)->type),
			 "Zero source on not ICMP error!"))
			goto panic;

		if (ipv6_dev_get_saddr(state->jool.ns, NULL, &flow6->daddr,
				       IPV6_PREFER_SRC_PUBLIC, &flow6->saddr)) {
			log_warn_once("Can't find a sufficiently scoped primary source address to reach %pI6.",
					&flow6->daddr);
			if (state->dst) {
				dst_release(state->dst);
				state->dst = NULL;
			}
			return drop(state, JSTAT46_6791_ENOENT);
		}
	}

	return VERDICT_CONTINUE;

panic:
	if (state->dst) {
		dst_release(state->dst);
		state->dst = NULL;
	}
	return drop(state, JSTAT_UNKNOWN);
}

struct ttp46_delta {
	/* Actual delta Jool is supposed to work with. */
	int actual;
	/*
	 * This delta always include the fragment header, and it's only for
	 * allocation purposes.
	 */
	int reserve;
};

static int iphdr_delta(struct iphdr *hdr4)
{
	return sizeof(struct ipv6hdr) - (hdr4->ihl << 2);
}

/*
 * Returns the "ideal" (ie. Fast Path only) difference in size between in->skb
 * and out->skb. in->skb->len + delta should equal out->skb->len.
 *
 * Please note that there is no guarantee that delta will be positive. If the
 * IPv4 header has lots of options, it might exceed the IPv6 header length.
 */
static void get_delta(struct packet *in, struct ttp46_delta *delta)
{
	struct iphdr *hdr4;
	int __delta;

	/*
	 * The following is assumed by this code:
	 *
	 * The IPv4 header will be replaced by a IPv6 header and possibly a
	 * fragment header.
	 * The L4 header will never change in size.
	 *    (In particular, ICMPv4 hdr len == ICMPv6 hdr len)
	 * The payload will not change in TCP, UDP and ICMP infos.
	 *
	 * As for ICMP errors:
	 * The sub-IPv4 header will be replaced by an IPv6 header and possibly a
	 * fragment header.
	 * The sub-L4 header will never change in size.
	 * The subpayload will never change in size (for now).
	 */

	hdr4 = pkt_ip4_hdr(in);
	__delta = iphdr_delta(hdr4);
	/*
	 * - defrag4 always removes MF and fragment offset.
	 * - This fragment header will only included if defrag4 is not mangling
	 *   packets.
	 * - If defrag4 is mangling packets, Linux might add a fragment header
	 *   later, but it's none of Jool's concern. (Except for allocation
	 *   purposes.)
	 */
	delta->actual = will_need_frag_hdr(hdr4) ? sizeof(struct frag_hdr) : 0;
	delta->reserve = sizeof(struct frag_hdr);

	if (is_first_frag4(hdr4) && pkt_is_icmp4_error(in)) {
		hdr4 = pkt_payload(in);
		__delta += iphdr_delta(hdr4);
		if (will_need_frag_hdr(hdr4))
			__delta += sizeof(struct frag_hdr);
	}

	delta->actual += __delta;
	delta->reserve += __delta;
}

/*
 * Returns:
 *
 * - 0: No fragments exceed MTU
 * - 1: First fragment exceeds MTU
 * - 2: Subsequent fragment exceeds MTU
 */
static int fragment_exceeds_mtu46(struct packet *in, int delta,
		unsigned int mtu)
{
	unsigned short gso_size;
	unsigned int l3_len;
	struct sk_buff *iter;

	gso_size = skb_shinfo(in->skb)->gso_size;
	if (gso_size) {
		l3_len = sizeof(struct ipv6hdr)
				+ (will_need_frag_hdr(pkt_ip4_hdr(in))
				? sizeof(struct frag_hdr) : 0);
		if (l3_len + pkt_l4hdr_len(in) + gso_size > mtu)
			goto generic_too_big;
		return 0;
	}

	if (skb_headlen(in->skb) + delta > mtu)
		goto generic_too_big;

	mtu -= sizeof(struct ipv6hdr) + sizeof(struct frag_hdr);
	skb_walk_frags(in->skb, iter)
		if (iter->len > mtu)
			return 2;

	return 0;

generic_too_big:
	return is_first_frag4(pkt_ip4_hdr(in)) ? 1 : 2;
}

static verdict allocate_fast(struct xlation *state, int delta, bool ignore_df)
{
	struct packet *in = &state->in;
	struct sk_buff *out;
	struct iphdr *hdr4_inner;
	struct frag_hdr *hdr_frag;
	struct skb_shared_info *shinfo;

	/* Dunno what happens when headroom is negative, so don't risk it. */
	if (delta < 0)
		delta = 0;

	/* Allocate the outgoing packet as a copy of @in with shared pages. */
	out = __pskb_copy(in->skb, delta + skb_headroom(in->skb), GFP_ATOMIC);
	if (!out) {
		log_debug(state, "__pskb_copy() returned NULL.");
		return drop(state, JSTAT46_PSKB_COPY);
	}

	/* https://github.com/NICMx/Jool/issues/289 */
#if LINUX_VERSION_AT_LEAST(5, 4, 0, 9999, 0)
	nf_reset_ct(out);
#else
	nf_reset(out);
#endif

	/* Remove outer l3 and l4 headers from the copy. */
	skb_pull(out, pkt_hdrs_len(in));

	if (is_first_frag4(pkt_ip4_hdr(in)) && pkt_is_icmp4_error(in)) {
		hdr4_inner = pkt_payload(in);

		/* Remove inner l3 headers from the copy. */
		skb_pull(out, hdr4_inner->ihl << 2);

		/* Add inner l3 headers to the copy. */
		if (will_need_frag_hdr(hdr4_inner))
			skb_push(out, sizeof(struct frag_hdr));
		skb_push(out, sizeof(struct ipv6hdr));
	}

	/* Add outer l4 headers to the copy. */
	skb_push(out, pkt_l4hdr_len(in));

	/* Add outer l3 headers to the copy. */
	if (will_need_frag_hdr(pkt_ip4_hdr(in)))
		skb_push(out, sizeof(struct frag_hdr));
	skb_push(out, sizeof(struct ipv6hdr));

	skb_reset_mac_header(out);
	skb_reset_network_header(out);
	if (will_need_frag_hdr(pkt_ip4_hdr(in))) {
		hdr_frag = (struct frag_hdr *)(skb_network_header(out)
				+ sizeof(struct ipv6hdr));
		skb_set_transport_header(out, sizeof(struct ipv6hdr)
				+ sizeof(struct frag_hdr));
	} else {
		hdr_frag = NULL;
		skb_set_transport_header(out, sizeof(struct ipv6hdr));
	}

	/* Wrap up. */
	pkt_fill(&state->out, out, L3PROTO_IPV6, pkt_l4_proto(in),
			hdr_frag, skb_transport_header(out) + pkt_l4hdr_len(in),
			pkt_original_pkt(in));

	memset(out->cb, 0, sizeof(out->cb));
	out->ignore_df = ignore_df;
	out->mark = in->skb->mark;
	out->protocol = htons(ETH_P_IPV6);

	shinfo = skb_shinfo(out);
	if (shinfo->gso_type & SKB_GSO_TCPV4) {
		shinfo->gso_type &= ~SKB_GSO_TCPV4;
		shinfo->gso_type |= SKB_GSO_TCPV6;
	}

	return VERDICT_CONTINUE;
}

static verdict allocate_slow(struct xlation *state, unsigned int mpl)
{
	struct packet *in;
	struct sk_buff **previous;
	struct sk_buff *out;
	unsigned int payload_left; /* Payload not yet consumed */
	/* Amount of layer 3 payload we can include in each fragment */
	unsigned int payload_per_frag;
	/* Current fragment's layer 3 payload length */
	unsigned int fragment_payload_len;
	unsigned int bytes_consumed;
	struct frag_hdr *frag;
	unsigned char *l3_payload;

	in = &state->in;
	previous = &state->out.skb;
	payload_left = pkt_len(in) - pkt_l3hdr_len(in);
	payload_per_frag = (mpl - HDRS_LEN) & 0xFFFFFFF8U;
	bytes_consumed = 0;

	while (payload_left > 0) {
		if (payload_left > payload_per_frag) {
			fragment_payload_len = payload_per_frag;
			payload_left -= payload_per_frag;
		} else {
			fragment_payload_len = payload_left;
			payload_left = 0;
		}

		out = alloc_skb(skb_headroom(in->skb) + HDRS_LEN
				+ fragment_payload_len, GFP_ATOMIC);
		if (!out)
			goto fail;

		*previous = out;
		previous = &out->next;

		skb_reserve(out, skb_headroom(in->skb));
		skb_reset_mac_header(out);
		skb_reset_network_header(out);
		skb_put(out, sizeof(struct ipv6hdr));
		frag = (struct frag_hdr *)skb_put(out, sizeof(struct frag_hdr));
		l3_payload = skb_put(out, fragment_payload_len);

		if (out == state->out.skb) {
			skb_set_transport_header(out, HDRS_LEN);
			pkt_fill(&state->out, out, L3PROTO_IPV6,
					pkt_l4_proto(in), frag,
					l3_payload + pkt_l4hdr_len(in),
					pkt_original_pkt(in));
		}

		out->ignore_df = false;
		out->mark = in->skb->mark;
		out->protocol = htons(ETH_P_IPV6);

		if (skb_copy_bits(in->skb,
				skb_transport_offset(in->skb) + bytes_consumed,
				l3_payload, fragment_payload_len))
			goto fail;
		bytes_consumed += fragment_payload_len;
	}

	return VERDICT_CONTINUE;

fail:
	kfree_skb_list(state->out.skb);
	state->out.skb = NULL;
	return drop(state, JSTAT_ENOMEM);
}

static void autofill_dst(struct xlation *state)
{
	struct sk_buff *skb;

	skb = state->out.skb;
	skb_dst_set(skb, state->dst);

	for (skb = skb->next; skb != NULL; skb = skb->next)
		skb_dst_set(skb, dst_clone(state->dst));

	state->dst = NULL;
}

static verdict ttp46_alloc_skb(struct xlation *state)
{
	/*
	 * Glossary:
	 *
	 * - IPL: Ideal (Outgoing) Packet Length
	 * - MPL: Maximum Packet Length
	 * - Slow Path: Out packet(s) will have to be created from scratch, data
	 *   will be inevitably copied from In to Out(s)
	 * - Fast Path: Out packet will share In packet's fragment and paged
	 *   data if possible
	 * - PTB: Packet Too Big (ICMPv6 error type 2 code 0)
	 * - FN: Fragmentation Needed (ICMPv4 error type 3 code 4)
	 *
	 * My tools are skb_copy_bits() and friends. I intend to attempt no
	 * frags surgery whatsoever.
	 *
	 * This is a pain in the ass because of lowest-ipv6-mtu and GRO/GSO.
	 * Here's the general algorithm in pseudocode:
	 *
	 *	If ICMP error:
	 *		Fast Path
	 *
	 *	Else if fragmentation prohibited:
	 *		If first fragment exceeds MTU:
	 *			FN
	 *		Else if subsequent fragment exceeds MTU:
	 *			Silent drop
	 *		Else:
	 *			Fast Path
	 *	Else:
	 *		If at least one fragment exceeds MTU:
	 *			Slow Path
	 *		Else:
	 *			Fast Path
	 *
	 * Design notes:
	 *
	 * # MTU
	 *
	 * MTU needs to be handled with extreme caution. We do not want
	 * ip6_output() -> ip6_finish_output() -> ip6_fragment() to return
	 * PTB because we want a FN instead. (We wouldn't translate
	 * ip6_fragment()'s PTB to FN because we're stuck in prerouting, so
	 * it'd never reach us.) PMTUD depends on this. We avoid the PTB by
	 * sending the FN ourselves by querying dst_mtu() (the same MTU function
	 * ip6_fragment() uses to compute the MTU).
	 *
	 * Of course, this hinges on ip6_fragment() using dst_mtu(). If this
	 * ever stops working, this is the first thing you need to check.
	 * (Hint: The struct sock is always NULL.)
	 *
	 * (If, on the other hand, a future namespace returns a PTB, it will
	 * cross our prerouting so it'll be converted to a FN no problem.)
	 *
	 * lowest-ipv6-mtu acts as a second line of defense, since it's (in
	 * theory) guaranteeing that the kernel will never enter ip6_fragment()
	 * in the first place. Though I'm glad it's not the only one because the
	 * user could misconfigure it.
	 *
	 * # Slow/Fast Path
	 *
	 * In Fast Path the result will be a single skb, sharing the incoming
	 * packet's frag_list and frags.
	 * In Slow Path the result will be multiple skbs, connected by their
	 * next pointers. (We don't need prev for anything.)
	 *
	 * At time of writing, we need Slow Path (ie. we need to fragment
	 * ourselves) because the kernel's IPv6 fragmentator does not care about
	 * already existing fragment headers, which complicates the survival of
	 * the Fragment Identification value needed when the packet is already
	 * fragmented. If Jool sends an IPv6 packet containing a fragment header
	 * hoping that the kernel will reuse it if it needs to fragment, the
	 * kernel will just add another fragment header instead.
	 *
	 * I love you, Linux, but you can be such a moron.
	 *
	 * (Must not forget: The above might suggest that the following
	 * situation could be handled by Fast Path:
	 * - Fragmentation allowed
	 * - Packet not already fragmented
	 * - Packet too big
	 * And it seems this would be true, but it would
	 * 1. Complicate the code further. (Need to perform packet surgery in
	 * the form of IP6CB(skb)->frag_max_size.)
	 * 2. Not be particularly faster. (Because the fragmentator would end up
	 * performing an operation equivalent to our Slow Path anyway.))
	 *
	 * Obviously, we want to use Fast Path whenever possible. Problem is,
	 * it's risky because it could mess up packet sizes if done carelessly,
	 * which borks PMTUD.
	 *
	 * Slow Path always works but breaks GRO/GSO optimizations.
	 *
	 * # GRO and GSO
	 *
	 * GRO/GSO are a problem because they lack contracts. I think the most
	 * helpful documentation I found was https://lwn.net/Articles/358910/,
	 * which has some interesting claims:
	 *
	 * - "the criteria for which packets can be merged is greatly
	 *   restricted; (...) only a few TCP or IP headers can differ."
	 * - "As a result of these restrictions, merged packets can be
	 *   resegmented losslessly; as an added benefit, the GSO code can be
	 *   used to perform resegmentation."
	 *
	 * In short, "GRO aims to be lossless, strict and symmetrical to GSO."
	 *
	 * Unfortunately, it doesn't say which are the fields that are allowed
	 * to differ. Thus I need to make assumptions based on my readings of
	 * the kernel code. This is obviously not future-proof, but it's
	 * basically needed because performance is severely restricted
	 * otherwise.
	 *
	 * I believe the relevant code is inet_gro_receive() (Hint: "^" is some
	 * funny guy's smartass way of saying "!="), and these are my
	 * assumptions:
	 *
	 * 1. DF is one of the fields which are not allowed to differ. If GSO is
	 * active, then I can assume that all DFs were enabled, or all DFs were
	 * disabled. This appears to be true for all currently supported
	 * kernels.
	 *
	 * 2. The original packet size (agreed upon by way of PMTUD) will not
	 * be mangled by GRO/GSO. I can assume this because PMTUD is sacred, and
	 * I can't see any way to reconcile it with GRO/GSO if the latter
	 * mangles packet sizes. (Though I must emphasize that I could be
	 * overlooking something.)
	 *
	 * 3. IPv4 GRO/GSO and IPv6 GRO/GSO basically function the same way (ie.
	 * a translated IPv4 GRO packet will be correctly segmented by the IPv6
	 * GSO code.) (This is the biggest stretch, and I really can't prove it
	 * definitely, but has worked fine so far.)
	 *
	 * So:
	 *
	 * 1. If fragmentation is prohibited, GSO does not prevent us from using
	 * Fast Path, because it preserves packet sizes. This is awesome.
	 *
	 * 2. If fragmentation is allowed, GSO might lead us to translate a
	 * large DF-disabled IPv4 packet into a large IPv6 packet, which is a
	 * problem. We need to throw GSO away in those situations. (Or verify
	 * each page size independently. But this would definitely meander deep
	 * into the realms of "packet surgery," so I'd rather not do it.)
	 *
	 * (Note: GRO enabled on !DF suggests there might exist some potential
	 * optimization I could be missing somewhere.)
	 *
	 * Therefore: If users want performance, they need to enable DF or GTFO.
	 *
	 * # LRO
	 *
	 * I'm not worrying about LRO because
	 *
	 * a) I don't know how it works. (eg. Does it affect skb_is_gso()?)
	 * b) I'm assuming it's always disabled nowadays. (Corollary: I can't
	 * test it because I can't find any hardware that supports it.)
	 * c) It's lossy, which means it might be inherently incompatible with
	 * IP XLAT anyway.
	 * d) The code is already convoluted enough as it is.
	 *
	 * The code might or might not work if LRO is enabled.
	 */

	struct packet *in;
	struct ttp46_delta delta;
	unsigned int nexthop_mtu;
	unsigned int lim;
	unsigned int mpl;
	verdict result;

	result = compute_flowix46(state);
	if (result != VERDICT_CONTINUE)
		return result;
	result = predict_route46(state);
	if (result != VERDICT_CONTINUE)
		return result;

	in = &state->in;
	get_delta(in, &delta);

	/* Hairpinning: We'll worry about MTU during the second pass. */
	if (state->dst == NULL)
		return allocate_fast(state, delta.reserve, false);

#ifndef UNIT_TESTING
	nexthop_mtu = dst_mtu(state->dst);
#else
	nexthop_mtu = 1500;
#endif
	lim = state->jool.globals.lowest_ipv6_mtu;
	mpl = min(nexthop_mtu, lim);
	if (mpl < 1280) {
		result = drop(state, JSTAT46_BAD_MTU);
		goto fail;
	}

	if (is_icmp4_error(pkt_icmp4_hdr(in)->type)) {
		/* Fragment header will not be added because ICMP error */
		result = allocate_fast(state, delta.reserve, false);

	} else if (is_df_set(pkt_ip4_hdr(in))) {
		/*
		 * Fragment header will not be added because DF.
		 * ...Unless it's already fragmented.
		 * If defrag disabled:
		 * 	Fragment header already included in delta.
		 * Else:
		 * 	Fragment header not included in delta.
		 */
		switch (fragment_exceeds_mtu46(in, delta.actual, nexthop_mtu)) {
		case 0:
			result = allocate_fast(state, delta.reserve,
					in->skb->ignore_df);
			break;
		case 1:
			result = drop_icmp(state, JSTAT_PKT_TOO_BIG,
					ICMPERR_FRAG_NEEDED,
					max(576u, nexthop_mtu - 20u));
			break;
		case 2:
			result = drop(state, JSTAT_PKT_TOO_BIG);
			break;
		default:
			WARN(1, "fragment_exceeds_mtu() returned garbage.");
			result = drop(state, JSTAT_UNKNOWN);
			break;
		}

	} else { /* Fragmentation allowed */
		if (fragment_exceeds_mtu46(in, delta.actual, mpl))
			result = allocate_slow(state, mpl);
		else
			result = allocate_fast(state, delta.reserve, true);
	}

	if (result != VERDICT_CONTINUE)
		goto fail;

	autofill_dst(state);
	return VERDICT_CONTINUE;

fail:
	dst_release(state->dst);
	state->dst = NULL;
	return result;
}

/**
 * Returns "true" if "hdr" contains a source route option and the last address
 * from it hasn't been reached.
 *
 * Assumes the options are glued in memory after "hdr", the way sk_buffs work
 * (when linearized or pullable).
 */
EXPORT_UNIT_STATIC bool has_unexpired_src_route(struct iphdr *hdr)
{
	unsigned char *current_opt, *end_of_opts;
	__u8 src_route_len, src_route_ptr;

	/* Find a loose source route or a strict source route option. */
	current_opt = (unsigned char *)(hdr + 1);
	end_of_opts = ((unsigned char *)hdr) + (4 * hdr->ihl);
	if (current_opt >= end_of_opts)
		return false;

	while (current_opt[0] != IPOPT_LSRR && current_opt[0] != IPOPT_SSRR) {
		switch (current_opt[0]) {
		case IPOPT_END:
			return false;
		case IPOPT_NOOP:
			current_opt++;
			break;
		default:
			/*
			 * IPOPT_SEC, IPOPT_RR, IPOPT_SID, IPOPT_TIMESTAMP,
			 * IPOPT_CIPSO and IPOPT_RA are known to fall through
			 * here.
			 */
			current_opt += current_opt[1];
			break;
		}

		if (current_opt >= end_of_opts)
			return false;
	}

	/* Finally test. */
	src_route_len = current_opt[1];
	src_route_ptr = current_opt[2];
	return src_route_len >= src_route_ptr;
}
EXPORT_UNIT_SYMBOL(has_unexpired_src_route)

/**
 * One-liner for creating the Identification field of the IPv6 Fragment header.
 */
EXPORT_UNIT_STATIC __be32 build_id_field(struct iphdr *hdr4)
{
	return cpu_to_be32(be16_to_cpu(hdr4->id));
}
EXPORT_UNIT_SYMBOL(build_id_field)

/*
 * Copies the IPv6 and fragment headers from the first fragment to the
 * subsequent ones, adapting fields appropriately.
 */
static void autofill_hdr6(struct packet *out)
{
	struct sk_buff *first;
	struct sk_buff *skb;
	struct ipv6hdr *hdr6;
	struct frag_hdr *frag;
	__u16 frag_offset;
	__u16 first_mf;

	first = out->skb;
	if (!first->next)
		return;

	frag = (struct frag_hdr *)(ipv6_hdr(first) + 1);
	frag_offset = get_fragment_offset_ipv6(frag) + first->len - HDRS_LEN;
	first_mf = is_mf_set_ipv6(frag);
	frag->frag_off |= cpu_to_be16(IP6_MF);

	for (skb = first->next; skb != NULL; skb = skb->next) {
		hdr6 = ipv6_hdr(skb);
		frag = (struct frag_hdr *)(hdr6 + 1);

		memcpy(hdr6, ipv6_hdr(first), HDRS_LEN);
		hdr6->payload_len = cpu_to_be16(skb->len - sizeof(*hdr6));
		frag->frag_off = build_ipv6_frag_off_field(frag_offset,
				skb->next ? true : first_mf);

		frag_offset += skb->len - HDRS_LEN;
	}
}

static verdict ttcp46_ipv6_common(struct xlation *state)
{
	struct packet *in = &state->in;
	struct packet *out = &state->out;
	struct iphdr *hdr4 = pkt_ip4_hdr(in);
	struct ipv6hdr *hdr6 = pkt_ip6_hdr(out);
	struct frag_hdr *frag_header;

	hdr6->version = 6;
	if (state->jool.globals.reset_traffic_class) {
		hdr6->priority = 0;
		hdr6->flow_lbl[0] = 0;
	} else {
		hdr6->priority = hdr4->tos >> 4;
		hdr6->flow_lbl[0] = hdr4->tos << 4;
	}
	hdr6->flow_lbl[1] = 0;
	hdr6->flow_lbl[2] = 0;
	/* hdr6->payload_len */
	/* hdr6->nexthdr */
	if (pkt_is_outer(in) && !state->is_hairpin_2) {
		if (hdr4->ttl <= 1) {
			log_debug(state, "Packet's TTL <= 1.");
			return drop_icmp(state, JSTAT46_TTL, ICMPERR_TTL, 0);
		}
		hdr6->hop_limit = hdr4->ttl - 1;
	} else {
		hdr6->hop_limit = hdr4->ttl;
	}

	/* hdr6->saddr */
	/* hdr6->daddr */

	if (will_need_frag_hdr(hdr4) || out->skb->next) {
		frag_header = (struct frag_hdr *)(hdr6 + 1);
		frag_header->nexthdr = hdr6->nexthdr;
		hdr6->nexthdr = NEXTHDR_FRAGMENT;
		frag_header->reserved = 0;
		frag_header->frag_off = build_ipv6_frag_off_field(
				get_fragment_offset_ipv4(hdr4),
				is_mf_set_ipv4(hdr4));
		frag_header->identification = build_id_field(hdr4);
	}

	return VERDICT_CONTINUE;
}

/**
 * Infers a IPv6 header from "in"'s IPv4 header and "tuple". Places the result
 * in "out"->l3_hdr.
 * This is RFC 7915 section 4.1.
 *
 * This is used to translate both outer and inner headers.
 */
static verdict ttp46_ipv6_external(struct xlation *state)
{
	struct packet *in = &state->in;
	struct packet *out = &state->out;
	struct ipv6hdr *hdr6 = pkt_ip6_hdr(out);
	verdict result;

	if (pkt_is_outer(in) && has_unexpired_src_route(pkt_ip4_hdr(in))) {
		log_debug(state, "Packet has an unexpired source route.");
		return drop_icmp(state, JSTAT46_SRC_ROUTE, ICMPERR_SRC_ROUTE, 0);
	}

	hdr6->nexthdr = state->flowx.v6.flowi.flowi6_proto;

	result = ttcp46_ipv6_common(state);
	if (result != VERDICT_CONTINUE)
		return result;

	/*
	 * I was tempted to use the RFC formula, but it's a little difficult
	 * because we can't trust the incoming packet's total length when we
	 * need to fragment due to lowest-ipv6-mtu.
	 * Also, this avoids the need to handle differently depending on whether
	 * we're adding a fragment header.
	 */
	hdr6->payload_len = cpu_to_be16(out->skb->len - sizeof(struct ipv6hdr));
	hdr6->saddr = state->flowx.v6.flowi.saddr;
	hdr6->daddr = state->flowx.v6.flowi.daddr;

	autofill_hdr6(out);
	return VERDICT_CONTINUE;
}

static verdict ttp46_ipv6_internal(struct xlation *state)
{
	struct packet *in = &state->in;
	struct packet *out = &state->out;
	struct ipv6hdr *hdr6 = pkt_ip6_hdr(out);
	verdict result;

	hdr6->nexthdr = xlat_nexthdr(pkt_ip4_hdr(in)->protocol);

	result = ttcp46_ipv6_common(state);
	if (result != VERDICT_CONTINUE)
		return result;

	/*
	 * The RFC formula is fine, but this avoids the need to handle
	 * differently depending on whether we're adding a fragment header.
	 */
	hdr6->payload_len = cpu_to_be16(be16_to_cpu(pkt_ip4_hdr(in)->tot_len)
			- pkt_hdrs_len(in) + pkt_hdrs_len(out)
			- sizeof(struct ipv6hdr));
	hdr6->saddr = state->flowx.v6.inner_src;
	hdr6->daddr = state->flowx.v6.inner_dst;

	return VERDICT_CONTINUE;
}

/**
 * One liner for creating the ICMPv6 header's MTU field.
 * Returns the smallest out of the three first parameters. It also handles some
 * quirks. See comments inside for more info.
 */
EXPORT_UNIT_STATIC __be32 icmp6_minimum_mtu(struct xlation *state,
		unsigned int packet_mtu,
		unsigned int nexthop6_mtu,
		unsigned int nexthop4_mtu,
		__u16 tot_len_field)
{
	__u32 result;

	if (packet_mtu == 0) {
		/*
		 * Some router does not implement RFC 1191.
		 * Got to determine a likely path MTU.
		 * See RFC 1191 sections 5, 7 and 7.1.
		 */
		__u16 *plateaus = state->jool.globals.plateaus.values;
		__u16 count = state->jool.globals.plateaus.count;
		int i;

		for (i = 0; i < count; i++) {
			if (plateaus[i] < tot_len_field) {
				packet_mtu = plateaus[i];
				break;
			}
		}
	}

	/* Here's the core comparison. */
	result = min(packet_mtu + 20, min(nexthop6_mtu, nexthop4_mtu + 20));
	if (result < IPV6_MIN_MTU)
		result = IPV6_MIN_MTU;

	return cpu_to_be32(result);
}
EXPORT_UNIT_SYMBOL(icmp6_minimum_mtu)

static verdict compute_mtu6(struct xlation *state)
{
	/* Meant for hairpinning and unit tests. */
	static const unsigned int INFINITE = 0xffffffff;
	struct net_device *in_dev;
	struct dst_entry *out_dst;
	struct icmphdr *in_icmp;
	struct icmp6hdr *out_icmp;
	struct iphdr *hdr4;
	unsigned int in_mtu;
	unsigned int out_mtu;

	in_icmp = pkt_icmp4_hdr(&state->in);
	out_icmp = pkt_icmp6_hdr(&state->out);
	in_dev = state->in.skb->dev;
	in_mtu = in_dev ? in_dev->mtu : INFINITE;
	out_dst = skb_dst(state->out.skb);
	out_mtu = out_dst ? dst_mtu(out_dst) : INFINITE;

	log_debug(state, "Packet MTU: %u", be16_to_cpu(in_icmp->un.frag.mtu));
	log_debug(state, "In dev MTU: %u", in_mtu);
	log_debug(state, "Out dev MTU: %u", out_mtu);

	/*
	 * We want the length of the packet that couldn't get through,
	 * not the truncated one.
	 */
	hdr4 = pkt_payload(&state->in);
	out_icmp->icmp6_mtu = icmp6_minimum_mtu(state,
			be16_to_cpu(in_icmp->un.frag.mtu),
			out_mtu,
			in_mtu,
			be16_to_cpu(hdr4->tot_len));
	log_debug(state, "Resulting MTU: %u", be32_to_cpu(out_icmp->icmp6_mtu));

	return VERDICT_CONTINUE;
}

/**
 * One-liner for translating "Destination Unreachable" messages from ICMPv4 to
 * ICMPv6.
 */
static verdict icmp4_to_icmp6_dest_unreach(struct xlation *state)
{
	struct icmphdr *icmp4_hdr = pkt_icmp4_hdr(&state->in);
	struct icmp6hdr *icmp6_hdr = pkt_icmp6_hdr(&state->out);

	switch (icmp4_hdr->code) {
	case ICMP_NET_UNREACH:
	case ICMP_HOST_UNREACH:
	case ICMP_SR_FAILED:
	case ICMP_NET_UNKNOWN:
	case ICMP_HOST_UNKNOWN:
	case ICMP_HOST_ISOLATED:
	case ICMP_NET_UNR_TOS:
	case ICMP_HOST_UNR_TOS:
	case ICMP_PORT_UNREACH:
	case ICMP_NET_ANO:
	case ICMP_HOST_ANO:
	case ICMP_PKT_FILTERED:
	case ICMP_PREC_CUTOFF:
		icmp6_hdr->icmp6_unused = 0;
		return VERDICT_CONTINUE;

	case ICMP_PROT_UNREACH:
		icmp6_hdr->icmp6_pointer = cpu_to_be32(offsetof(struct ipv6hdr,
				nexthdr));
		return VERDICT_CONTINUE;

	case ICMP_FRAG_NEEDED:
		return compute_mtu6(state);
	}

	/* Dead code */
	WARN(1, "ICMPv4 Destination Unreachable code %u was unhandled by the switch above.",
			icmp4_hdr->code);
	return drop(state, JSTAT_UNKNOWN);
}

/**
 * One-liner for translating "Parameter Problem" messages from ICMPv4 to ICMPv6.
 */
EXPORT_UNIT_STATIC verdict icmp4_to_icmp6_param_prob(struct xlation *state)
{
#define DROP 255
	static const __u8 ptrs[] = {
		0,    1,    4,    4,
		DROP, DROP, DROP, DROP,
		7,    6,    DROP, DROP,
		8,    8,    8,    8,
		24,   24,   24,   24
	};

	struct icmphdr *icmp4_hdr = pkt_icmp4_hdr(&state->in);
	struct icmp6hdr *icmp6_hdr = pkt_icmp6_hdr(&state->out);
	__u8 ptr;

	switch (icmp4_hdr->code) {
	case ICMP_PTR_INDICATES_ERROR:
	case ICMP_BAD_LENGTH:
		ptr = be32_to_cpu(icmp4_hdr->icmp4_unused) >> 24;

		if (19 < ptr || ptrs[ptr] == DROP) {
			log_debug(state, "ICMPv4 messages type %u code %u pointer %u lack an ICMPv6 counterpart.",
					icmp4_hdr->type, icmp4_hdr->code, ptr);
			return drop(state, JSTAT46_UNTRANSLATABLE_PARAM_PROBLEM_PTR);
		}

		icmp6_hdr->icmp6_pointer = cpu_to_be32(ptrs[ptr]);
		return VERDICT_CONTINUE;
	}

	/* Dead code */
	WARN(1, "ICMPv4 Parameter Problem code %u was unhandled by the switch above.",
			icmp4_hdr->code);
	return drop(state, JSTAT_UNKNOWN);
}
EXPORT_UNIT_SYMBOL(icmp4_to_icmp6_param_prob)

/*
 * Removes L4 header, adds L4 header, adds IPv6 pseudoheader.
 */
static void update_icmp6_csum(struct xlation *state)
{
	struct ipv6hdr *out_ip6 = pkt_ip6_hdr(&state->out);
	struct icmphdr *in_icmp = pkt_icmp4_hdr(&state->in);
	struct icmp6hdr *out_icmp = pkt_icmp6_hdr(&state->out);
	struct icmphdr copy_hdr;
	__wsum csum;

	out_icmp->icmp6_cksum = 0;

	csum = ~csum_unfold(in_icmp->checksum);

	memcpy(&copy_hdr, in_icmp, sizeof(*in_icmp));
	copy_hdr.checksum = 0;
	csum = csum_sub(csum, csum_partial(&copy_hdr, sizeof(copy_hdr), 0));

	csum = csum_add(csum, csum_partial(out_icmp, sizeof(*out_icmp), 0));

	out_icmp->icmp6_cksum = csum_ipv6_magic(&out_ip6->saddr,
			&out_ip6->daddr, pkt_datagram_len(&state->in),
			IPPROTO_ICMPV6, csum);
}

static void compute_icmp6_csum(struct packet *out)
{
	struct ipv6hdr *out_ip6 = pkt_ip6_hdr(out);
	struct icmp6hdr *out_icmp = pkt_icmp6_hdr(out);
	__wsum csum;

	/*
	 * This function only gets called for ICMP error checksums, so
	 * pkt_datagram_len() is fine.
	 */
	out_icmp->icmp6_cksum = 0;
	csum = skb_checksum(out->skb, skb_transport_offset(out->skb),
			pkt_datagram_len(out), 0);
	out_icmp->icmp6_cksum = csum_ipv6_magic(&out_ip6->saddr,
			&out_ip6->daddr, pkt_datagram_len(out), IPPROTO_ICMPV6,
			csum);
	out->skb->ip_summed = CHECKSUM_NONE;
}

static verdict validate_icmp4_csum(struct xlation *state)
{
	struct packet *in = &state->in;
	__sum16 csum;

	if (in->skb->ip_summed != CHECKSUM_NONE)
		return VERDICT_CONTINUE;

	csum = csum_fold(skb_checksum(in->skb, skb_transport_offset(in->skb),
			pkt_datagram_len(in), 0));
	if (csum != 0) {
		log_debug(state, "Checksum doesn't match.");
		return drop(state, JSTAT46_ICMP_CSUM);
	}

	return VERDICT_CONTINUE;
}

static bool should_remove_ie(struct xlation *state)
{
	struct icmphdr *hdr;
	__u8 type;
	__u8 code;

	hdr = pkt_icmp4_hdr(&state->in);
	type = hdr->type;
	code = hdr->code;

	/* v4 Protocol Unreachable becomes v6 Parameter Problem. */
	if (type == 3 && code == 2)
		return true;
	/* v4 Fragmentation Needed becomes v6 Packet Too Big. */
	if (type == 3 && code == 4)
		return true;
	/* v4 Parameter Problem becomes v6 Parameter Problem. */
	if (type == 12)
		return true;

	return false;
}

static verdict handle_icmp6_extension(struct xlation *state)
{
	struct icmpext_args args;
	verdict result;
	struct packet *out;

	args.max_pkt_len = 1280;
	args.ipl = icmp4_length(pkt_icmp4_hdr(&state->in)) << 2;
	args.out_bits = 3;
	args.force_remove_ie = should_remove_ie(state);

	result = handle_icmp_extension(state, &args);
	if (result != VERDICT_CONTINUE)
		return result;

	out = &state->out;
	pkt_icmp6_hdr(out)->icmp6_length = args.ipl;
	pkt_ip6_hdr(out)->payload_len = cpu_to_be16(out->skb->len
			- sizeof(struct ipv6hdr));
	return VERDICT_CONTINUE;
}

/*
 * Though ICMPv4 errors are supposed to be max 576 bytes long, a good portion of
 * the Internet seems prepared against bigger ICMPv4 errors. Thus, the resulting
 * ICMPv6 packet might have a smaller payload than the original packet even
 * though IPv4 MTU < IPv6 MTU.
 */
static verdict trim_1280(struct xlation *state)
{
	struct packet *out;
	int error;

	out = &state->out;
	if (out->skb->len <= 1280)
		return VERDICT_CONTINUE;

	error = pskb_trim(out->skb, 1280);
	if (error) {
		log_debug(state, "pskb_trim() error: %d", error);
		return drop(state, JSTAT_ENOMEM);
	}

	pkt_ip6_hdr(out)->payload_len = cpu_to_be16(out->skb->len
			- sizeof(struct ipv6hdr));
	return VERDICT_CONTINUE;
}

static verdict post_icmp6error(struct xlation *state)
{
	verdict result;

	log_debug(state, "Translating the inner packet (4->6)...");

	/*
	 * We will later recompute the checksum from scratch, but we should not
	 * translate a corrupted ICMPv4 error into an OK-csum ICMPv6 one,
	 * so validate first.
	 */
	result = validate_icmp4_csum(state);
	if (result != VERDICT_CONTINUE)
		return result;

	result = ttpcomm_translate_inner_packet(state, &ttp46_steps);
	if (result != VERDICT_CONTINUE)
		return result;

	result = handle_icmp6_extension(state);
	if (result != VERDICT_CONTINUE)
		return result;

	result = trim_1280(state);
	if (result != VERDICT_CONTINUE)
		return result;

	compute_icmp6_csum(&state->out);
	return VERDICT_CONTINUE;
}

/**
 * Translates in's icmp4 header and payload into out's icmp6 header and payload.
 * This is the RFC 7915 sections 4.2 and 4.3, except checksum (See post_icmp6()).
 */
static verdict ttp46_icmp(struct xlation *state)
{
	struct icmphdr *icmpv4_hdr = pkt_icmp4_hdr(&state->in);
	struct icmp6hdr *icmpv6_hdr = pkt_icmp6_hdr(&state->out);
	verdict result;

	icmpv6_hdr->icmp6_type = state->flowx.v6.flowi.fl6_icmp_type;
	icmpv6_hdr->icmp6_code = state->flowx.v6.flowi.fl6_icmp_code;
	icmpv6_hdr->icmp6_cksum = icmpv4_hdr->checksum; /* default. */

	/* -- First the ICMP header. -- */
	switch (icmpv4_hdr->type) {
	case ICMP_ECHO:
	case ICMP_ECHOREPLY:
		icmpv6_hdr->icmp6_identifier =
				xlation_is_nat64(state)
				? cpu_to_be16(state->out.tuple.icmp6_id)
				: icmpv4_hdr->un.echo.id;
		icmpv6_hdr->icmp6_sequence = icmpv4_hdr->un.echo.sequence;
		update_icmp6_csum(state);
		return VERDICT_CONTINUE;

	case ICMP_DEST_UNREACH:
		result = icmp4_to_icmp6_dest_unreach(state);
		if (result != VERDICT_CONTINUE)
			return result;
		return post_icmp6error(state);

	case ICMP_TIME_EXCEEDED:
		icmpv6_hdr->icmp6_unused = 0;
		return post_icmp6error(state);

	case ICMP_PARAMETERPROB:
		result = icmp4_to_icmp6_param_prob(state);
		if (result != VERDICT_CONTINUE)
			return result;
		return post_icmp6error(state);
	}

	/* Dead code */
	WARN(1, "ICMPv6 type %u was unhandled by the switch above.",
			icmpv6_hdr->icmp6_type);
	return drop(state, JSTAT_UNKNOWN);
}

static __be16 get_src_port46(struct xlation *state)
{
	return pkt_is_inner(&state->out)
			? cpu_to_be16(state->out.tuple.dst.addr6.l4)
			: cpu_to_be16(state->out.tuple.src.addr6.l4);
}

static __be16 get_dst_port46(struct xlation *state)
{
	return pkt_is_inner(&state->out)
			? cpu_to_be16(state->out.tuple.src.addr6.l4)
			: cpu_to_be16(state->out.tuple.dst.addr6.l4);
}

/**
 * Removes the IPv4 pseudoheader and L4 header, adds the IPv6 pseudoheader and
 * L4 header. Input and result are folded.
 */
static __sum16 update_csum_4to6(__sum16 csum16,
		struct iphdr *in_ip4, void *in_l4_hdr,
		struct ipv6hdr *out_ip6, void *out_l4_hdr,
		size_t l4_hdr_len)
{
	__wsum csum, pseudohdr_csum;

	/* See comments at update_csum_6to4(). */

	csum = ~csum_unfold(csum16);

	pseudohdr_csum = csum_tcpudp_nofold(in_ip4->saddr, in_ip4->daddr,
			0, 0, 0);
	csum = csum_sub(csum, pseudohdr_csum);
	csum = csum_sub(csum, csum_partial(in_l4_hdr, l4_hdr_len, 0));

	pseudohdr_csum = ~csum_unfold(csum_ipv6_magic(&out_ip6->saddr,
			&out_ip6->daddr, 0, 0, 0));
	csum = csum_add(csum, pseudohdr_csum);
	csum = csum_add(csum, csum_partial(out_l4_hdr, l4_hdr_len, 0));

	return csum_fold(csum);
}

/**
 * Removes the IPv4 pseudoheader, adds the IPv6 pseudoheader.
 * Input and result are unfolded.
 */
static __sum16 update_csum_4to6_partial(__sum16 csum16, struct iphdr *in4,
		struct ipv6hdr *out6)
{
	__wsum csum, pseudohdr_csum;

	csum = csum_unfold(csum16);

	pseudohdr_csum = csum_tcpudp_nofold(in4->saddr, in4->daddr, 0, 0, 0);
	csum = csum_sub(csum, pseudohdr_csum);

	pseudohdr_csum = ~csum_unfold(csum_ipv6_magic(&out6->saddr,
			&out6->daddr, 0, 0, 0));
	csum = csum_add(csum, pseudohdr_csum);

	return ~csum_fold(csum);
}

static bool can_compute_csum(struct xlation *state)
{
	struct iphdr *hdr4;
	struct udphdr *hdr_udp;
	bool amend_csum0;

	if (xlation_has_defrag(state))
		return true;

	/*
	 * RFC 7915#4.5:
	 * A stateless translator cannot compute the UDP checksum of
	 * fragmented packets, so when a stateless translator receives the
	 * first fragment of a fragmented UDP IPv4 packet and the checksum
	 * field is zero, the translator SHOULD drop the packet and generate
	 * a system management event that specifies at least the IP
	 * addresses and port numbers in the packet.
	 *
	 * The "system management event" is outside. (See
	 * JSTAT46_FRAGMENTED_ZERO_CSUM.)
	 * It does not include the addresses/ports, which is OK because users
	 * don't like it: https://github.com/NICMx/Jool/pull/129
	 */
	hdr4 = pkt_ip4_hdr(&state->in);
	amend_csum0 = state->jool.globals.siit.compute_udp_csum_zero;
	if (is_mf_set_ipv4(hdr4) || !amend_csum0) {
		hdr_udp = pkt_udp_hdr(&state->in);
		log_debug(state, "Dropping zero-checksum UDP packet: %pI4#%u->%pI4#%u",
				&hdr4->saddr, ntohs(hdr_udp->source),
				&hdr4->daddr, ntohs(hdr_udp->dest));
		return false;
	}

	return true;
}

/**
 * Assumes that "out" is IPv6 and UDP, and computes and sets its l4-checksum.
 * This has to be done because the field is mandatory only in IPv6, so Jool has
 * to make up for lazy IPv4 nodes.
 * This is actually required in the Determine Incoming Tuple step, but we can't
 * modify the incoming packet, so we do it here.
 */
static int handle_zero_csum(struct xlation *state)
{
	struct packet *in = &state->in;
	struct ipv6hdr *hdr6 = pkt_ip6_hdr(&state->out);
	struct udphdr *hdr_udp = pkt_udp_hdr(&state->out);
	__wsum csum;

	if (!can_compute_csum(state))
		return -EINVAL;

	/*
	 * Here's the deal:
	 * We want to compute out's checksum. **out is a packet whose fragment
	 * offset is zero**.
	 *
	 * Problem is, out's payload hasn't been translated yet. Because it can
	 * be scattered through several fragments, moving this step would make
	 * it look annoyingly out of place way later.
	 *
	 * Instead, we can exploit the fact that the translation does not affect
	 * the UDP payload, so here's what we will actually include in the
	 * checksum:
	 * - out's pseudoheader (this will actually be summed last).
	 * - out's UDP header.
	 * - in's payload.
	 *
	 * That's the reason why we needed more than just the outgoing packet
	 * as argument.
	 */

	csum = csum_partial(hdr_udp, sizeof(*hdr_udp), 0);
	csum = skb_checksum(in->skb, in->payload_offset,
			in->skb->len - pkt_hdrs_len(in), csum);
	hdr_udp->check = csum_ipv6_magic(&hdr6->saddr, &hdr6->daddr,
			pkt_datagram_len(in), IPPROTO_UDP, csum);

	return 0;
}

static verdict ttp46_tcp(struct xlation *state)
{
	struct packet *in = &state->in;
	struct packet *out = &state->out;
	struct tcphdr *tcp_in = pkt_tcp_hdr(in);
	struct tcphdr *tcp_out = pkt_tcp_hdr(out);
	struct tcphdr tcp_copy;

	/* Header */
	memcpy(tcp_out, tcp_in, pkt_l4hdr_len(in));
	if (xlation_is_nat64(state)) {
		tcp_out->source = get_src_port46(state);
		tcp_out->dest = get_dst_port46(state);
	}

	/* Header.checksum */
	if (in->skb->ip_summed != CHECKSUM_PARTIAL) {
		memcpy(&tcp_copy, tcp_in, sizeof(*tcp_in));
		tcp_copy.check = 0;

		tcp_out->check = 0;
		tcp_out->check = update_csum_4to6(tcp_in->check,
				pkt_ip4_hdr(in), &tcp_copy,
				pkt_ip6_hdr(out), tcp_out,
				sizeof(*tcp_out));
	} else {
		tcp_out->check = update_csum_4to6_partial(tcp_in->check,
				pkt_ip4_hdr(in), pkt_ip6_hdr(out));
		partialize_skb(out->skb, offsetof(struct tcphdr, check));
	}

	return VERDICT_CONTINUE;
}

static verdict ttp46_udp(struct xlation *state)
{
	struct packet *in = &state->in;
	struct packet *out = &state->out;
	struct udphdr *udp_in = pkt_udp_hdr(in);
	struct udphdr *udp_out = pkt_udp_hdr(out);
	struct udphdr udp_copy;

	/* Header */
	memcpy(udp_out, udp_in, pkt_l4hdr_len(in));
	if (xlation_is_nat64(state)) {
		udp_out->source = get_src_port46(state);
		udp_out->dest = get_dst_port46(state);
	}

	/* Header.checksum */
	if (udp_in->check != 0) {
		if (in->skb->ip_summed != CHECKSUM_PARTIAL) {
			memcpy(&udp_copy, udp_in, sizeof(*udp_in));
			udp_copy.check = 0;

			udp_out->check = 0;
			udp_out->check = update_csum_4to6(udp_in->check,
					pkt_ip4_hdr(in), &udp_copy,
					pkt_ip6_hdr(out), udp_out,
					sizeof(*udp_out));
		} else {
			udp_out->check = update_csum_4to6_partial(udp_in->check,
					pkt_ip4_hdr(in), pkt_ip6_hdr(out));
			partialize_skb(out->skb, offsetof(struct udphdr, check));
		}
	} else {
		/*
		 * TODO (performance) handling this as partial might work just
		 * as well, or better.
		 */
		if (handle_zero_csum(state)) {
			return drop_icmp(state, JSTAT46_FRAGMENTED_ZERO_CSUM,
					ICMPERR_FILTER, 0);
		}
	}

	return VERDICT_CONTINUE;
}

const struct translation_steps ttp46_steps = {
	.skb_alloc = ttp46_alloc_skb,
	.xlat_outer_l3 = ttp46_ipv6_external,
	.xlat_inner_l3 = ttp46_ipv6_internal,
	.xlat_tcp = ttp46_tcp,
	.xlat_udp = ttp46_udp,
	.xlat_icmp = ttp46_icmp,
};
