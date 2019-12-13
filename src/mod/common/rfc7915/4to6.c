#include "mod/common/rfc7915/4to6.h"

#include <net/addrconf.h>
#include <net/ip6_checksum.h>

#include "common/constants.h"
#include "mod/common/linux_version.h"
#include "mod/common/log.h"
#include "mod/common/rfc6052.h"
#include "mod/common/route.h"

/* Layer 3 only */
#define HDRS_LEN (sizeof(struct ipv6hdr) + sizeof(struct frag_hdr))

struct ipv6_addresses {
	struct in6_addr src;
	struct in6_addr dst;
};

static int generate_saddr6_nat64(struct xlation *state,
		struct ipv6_addresses *addrs)
{
	struct globals *cfg;
	struct in_addr tmp;

	cfg = &state->jool.globals;

	if (cfg->nat64.src_icmp6errs_better && pkt_is_icmp4_error(&state->in)) {
		/* Issue #132 behaviour. */
		tmp.s_addr = pkt_ip4_hdr(&state->in)->saddr;
		return __rfc6052_4to6(&cfg->pool6.prefix, &tmp, &addrs->src);
	}

	/* RFC 6146 behaviour. */
	addrs->src = state->out.tuple.src.addr6.l3;
	return 0;
}

static verdict xlat_addresses46(struct xlation *state,
		struct ipv6_addresses *addrs)
{
	if (xlation_is_nat64(state)) {
		if (generate_saddr6_nat64(state, addrs))
			return drop(state, JSTAT46_SRC);
	} else {
		addrs->src = state->out.tuple.src.addr6.l3;
	}

	addrs->dst = state->out.tuple.dst.addr6.l3;
	return VERDICT_CONTINUE;
}

static __u8 xlat_nexthdr(__u8 protocol)
{
	return (protocol == IPPROTO_ICMP) ? NEXTHDR_ICMP : protocol;
}

static struct dst_entry *predict_route(struct xlation *state,
		struct ipv6_addresses *addrs)
{
	struct packet *in;
	struct flowi6 flow;

	in = &state->in;

	memset(&flow, 0, sizeof(flow));
	flow.flowi6_mark = in->skb->mark;
	flow.flowi6_scope = RT_SCOPE_UNIVERSE;
	flow.flowi6_proto = xlat_nexthdr(pkt_ip4_hdr(in)->protocol);
	flow.flowi6_flags = FLOWI_FLAG_ANYSRC;
	flow.saddr = addrs->src;
	flow.daddr = addrs->dst;

	switch (flow.flowi6_proto) {
	case NEXTHDR_TCP:
	case NEXTHDR_UDP:
		flow.fl6_sport = state->out.tuple.src.addr6.l4;
		flow.fl6_dport = state->out.tuple.dst.addr6.l4;
		break;
	case NEXTHDR_ICMP:
		/*
		 * type and code have not been translated yet, and I don't think
		 * they're worth the trouble.
		 * These flowi fields are probably just clutter at this point.
		 */
		break;
	}

	return route6(state->jool.ns, &flow);
}

static int hdr4len_to_hdr6len(struct iphdr *hdr4)
{
	int result;

	result = sizeof(struct ipv6hdr) - (hdr4->ihl << 2);
	if (will_need_frag_hdr(hdr4))
		result += sizeof(struct frag_hdr);

	return result;
}

/**
 * Computes and returns the "ideal" outgoing packet's length.
 *
 * "Ideal" means Fast Path. (ie. assuming Jool will not need to fragment the
 * packet further.)
 *
 * Please note that there's no guarantee that the resulting size will be greater
 * than the original (ie. delta can be negative). Handle with caution.
 */
static unsigned int predict_out_len(struct packet *in)
{
	int delta;

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

	delta = hdr4len_to_hdr6len(pkt_ip4_hdr(in));
	if (is_first_frag4(pkt_ip4_hdr(in)) && pkt_is_icmp4_error(in))
		delta += hdr4len_to_hdr6len(pkt_payload(in));

	return in->skb->len + delta;
}

static bool is_fragmentation_allowed(struct packet *in)
{
	/*
	 * intention:
	 *
	 * ignore_df    df       result
	 * false        false    allow fragmentation
	 * false        true     fragmentation prohibited
	 * true         false    allow fragmentation
	 * true         TRUE     allow fragmentation
	 */
	return in->skb->ignore_df || !is_df_set(pkt_ip4_hdr(in));
}

static verdict allocate_fast(struct xlation *state, unsigned int out_pkt_len)
{
	struct packet *in = &state->in;
	struct sk_buff *out;
	struct iphdr *hdr4_inner;
	struct frag_hdr *hdr_frag;
	struct skb_shared_info *shinfo;
	int delta;
	int error;

	delta = out_pkt_len - in->skb->len;
	/* Dunno what happens when headroom is negative, so don't risk it. */
	if (delta < 0)
		delta = 0;

	/* Allocate the outgoing packet as a copy of @in with shared pages. */
	out = __pskb_copy(in->skb, delta + skb_headroom(in->skb), GFP_ATOMIC);
	if (!out) {
		log_debug("__pskb_copy() returned NULL.");
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

	/* Prevent Linux from dropping or fragmenting ICMP errors. */
	if (pkt_is_icmp4_error(in)) {
		/*
		 * Though ICMPv4 errors are supposed to be max 576 bytes long,
		 * a good portion of the Internet seems prepared against bigger
		 * ICMPv4 errors. Thus, the resulting ICMPv6 packet might have
		 * a smaller payload than the original packet even though
		 * IPv4 MTU < IPv6 MTU.
		 */
		error = pskb_trim(out, 1280);
		if (error) {
			kfree_skb(out);
			log_debug("pskb_trim() returned errcode %d.", error);
			return drop(state, JSTAT_ENOMEM);
		}
	}

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
	payload_left = pkt_payload_len_pkt(in);
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
		frag = skb_put(out, sizeof(struct frag_hdr));
		skb_reset_transport_header(out);
		l3_payload = skb_put(out, fragment_payload_len);

		if (out == state->out.skb) {
			pkt_fill(&state->out, out, L3PROTO_IPV6,
					pkt_l4_proto(in), frag,
					l3_payload + pkt_l4hdr_len(in),
					pkt_original_pkt(in));
		}

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

static void autofill_dst(struct xlation *state, struct dst_entry *dst)
{
	struct sk_buff *skb;

	skb = state->out.skb;
	skb_dst_set(skb, dst);

	for (skb = skb->next; skb != NULL; skb = skb->next)
		skb_dst_set(skb, dst_clone(dst));
}

static bool is_zero(struct in6_addr *addr)
{
	return (addr->s6_addr32[0] == 0)
			&& (addr->s6_addr32[1] == 0)
			&& (addr->s6_addr32[2] == 0)
			&& (addr->s6_addr32[3] == 0);
}

static verdict addrs_set(struct xlation *state, struct ipv6_addresses *addrs)
{
	struct ipv6hdr *hdr6;

	hdr6 = pkt_ip6_hdr(&state->out);
	hdr6->saddr = addrs->src;
	hdr6->daddr = addrs->dst;

	if (is_zero(&hdr6->saddr)) { /* Empty 6791 pool */
		if (WARN(!xlator_is_siit(&state->jool),
				"Zero source address on not SIIT!"))
			return drop(state, JSTAT_UNKNOWN);
		if (WARN(!is_icmp4_error(pkt_icmp4_hdr(&state->in)->type),
				"Zero source on not ICMP error!"))
			return drop(state, JSTAT_UNKNOWN);

		if (ipv6_dev_get_saddr(state->jool.ns, NULL, &hdr6->daddr,
				IPV6_PREFER_SRC_PUBLIC, &hdr6->saddr)) {
			log_warn_once("Can't find a sufficiently scoped primary source address to reach %pI6.",
					&hdr6->daddr);
			return drop(state, JSTAT46_6791_ESRCH);
		}
	}

	return VERDICT_CONTINUE;
}

verdict ttp46_alloc_skb(struct xlation *state)
{
	/*
	 * Glossary:
	 *
	 * - PL: (Ideal) (Out) Packet Length
	 * - MPL: Maximum Packet Length
	 * - Slow Path: Out packet(s) will have to be created from scratch, data
	 *   will be inevitably copied from In to Out(s)
	 * - Fast Path: Out packet will share In packet's paged data if possible
	 *
	 * I have decided NOT to attempt to preserve frag_list, because past
	 * experience has suggested the semantics of that fucking thing depend
	 * on kernel version, and so there's no way I'd get it right. I intend
	 * to attempt no skb surgery whatsoever. The messy internal fields are
	 * transparent to me; my tools are skb_copy_bits() and friends.
	 *
	 * This is the algorithm in pseudocode:
	 *
	 *	If fragmentation prohibited:
	 *		If PL > netxhop MTU:
	 *			Frag Needed (ICMPv4 error type 3 code 4)
	 *		Else:
	 *			Fast Path
	 *	Else:
	 *		If PL <= MPL:
	 *			Fast Path
	 *		Else:
	 *			Slow Path
	 *
	 * In Fast Path the result will be a single skb, mirroring the incoming
	 * packet's paging.
	 * In Slow Path the result will be multiple skbs, connected by their
	 * next pointers. (We don't need prev for anything.)
	 *
	 * At time of writing, we need Slow Path for two reasons:
	 *
	 * 1. The kernel does not provide a means to fragment a packet to a
	 * specified length. We can't inform lowest-ipv6-mtu to the kernel.
	 *
	 * 2. The kernel does not care about already existing fragment headers,
	 * which complicates the survival of the Fragment Identification value
	 * needed when the packet is already fragmented. If Jool sends an IPv6
	 * packet containing a fragment header hoping that the kernel will reuse
	 * it if it needs to fragment, the kernel will just add another fragment
	 * header instead.
	 *
	 * I love you, Linux, but you can be such a moron.
	 */

	struct packet *in;
	struct ipv6_addresses addrs;
	struct dst_entry *dst;
	unsigned int out_pkt_len;
	unsigned int nexthop_mtu;
	unsigned int lowest_ipv6_mtu;
	unsigned int mpl;
	verdict result;

	in = &state->in;
	result = xlat_addresses46(state, &addrs);
	if (result != VERDICT_CONTINUE)
		return result;
	dst = predict_route(state, &addrs);
	if (!dst)
		return untranslatable(state, JSTAT_FAILED_ROUTES);
	out_pkt_len = predict_out_len(in);
	nexthop_mtu = dst->dev->mtu;
	lowest_ipv6_mtu = state->jool.globals.lowest_ipv6_mtu;
	mpl = min(nexthop_mtu, lowest_ipv6_mtu);

	if (mpl < 1280) {
		result = drop(state, JSTAT46_BAD_MTU);
		goto fail;
	}

	if (is_icmp4_error(pkt_icmp4_hdr(in)->type)) {
		result = allocate_fast(state, out_pkt_len);
		goto end;
	}

	if (is_fragmentation_allowed(in)) {
		if (out_pkt_len <= mpl)
			result = allocate_fast(state, out_pkt_len);
		else
			result = allocate_slow(state, mpl);

	} else { /* Fragmentation prohibited */
		if (out_pkt_len > nexthop_mtu) {
			result = drop_icmp(state, JSTAT_PKT_TOO_BIG,
					ICMPERR_FRAG_NEEDED, nexthop_mtu);
			goto fail;
		}
		result = allocate_fast(state, out_pkt_len);
	}

end:
	if (result != VERDICT_CONTINUE) {
		dst_release(dst);
		return result;
	}

	autofill_dst(state, dst);
	addrs_set(state, &addrs);
	return VERDICT_CONTINUE;

fail:
	dst_release(dst);
	return result;
}

static __be16 build_payload_len(struct packet *in, struct packet *out)
{
	__u16 total_len;

	if (pkt_is_inner(out)) {
		/*
		 * The RFC formula is fine, but this avoids the need to override
		 * if we later discover that we need to account for a fragment
		 * header.
		 */
		total_len = be16_to_cpu(pkt_ip4_hdr(in)->tot_len)
				- pkt_hdrs_len(in) + pkt_hdrs_len(out);
	} else {
		/*
		 * I was tempted to use the RFC formula, but it's a little
		 * difficult because we can't trust the incoming packet's total
		 * length when we need to fragment due to lowest-ipv6-mtu.
		 * Also, this avoids the need to override if we later discover
		 * that we need to account for a fragment header.
		 */
		total_len = out->skb->len;
	}

	return cpu_to_be16(total_len - sizeof(struct ipv6hdr));
}

/**
 * Returns "true" if "hdr" contains a source route option and the last address
 * from it hasn't been reached.
 *
 * Assumes the options are glued in memory after "hdr", the way sk_buffs work
 * (when linearized or pullable).
 */
static bool has_unexpired_src_route(struct iphdr *hdr)
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

/**
 * One-liner for creating the Identification field of the IPv6 Fragment header.
 */
static inline __be32 build_id_field(struct iphdr *hdr4)
{
	return cpu_to_be32(be16_to_cpu(hdr4->id));
}

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
	frag->frag_off |= IP6_MF;

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

/**
 * Infers a IPv6 header from "in"'s IPv4 header and "tuple". Places the result
 * in "out"->l3_hdr.
 * This is RFC 7915 section 4.1.
 *
 * This is used to translate both outer and inner headers.
 */
verdict ttp46_ipv6(struct xlation *state)
{
	struct packet *in = &state->in;
	struct packet *out = &state->out;
	struct iphdr *hdr4 = pkt_ip4_hdr(in);
	struct ipv6hdr *hdr6 = pkt_ip6_hdr(out);
	struct frag_hdr *frag_header;

	if (pkt_is_outer(in) && has_unexpired_src_route(hdr4)) {
		log_debug("Packet has an unexpired source route.");
		return drop_icmp(state, JSTAT46_SRC_ROUTE, ICMPERR_SRC_ROUTE, 0);
	}

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
	hdr6->payload_len = build_payload_len(in, out);
	hdr6->nexthdr = xlat_nexthdr(hdr4->protocol);
	if (pkt_is_outer(in) && !pkt_is_intrinsic_hairpin(in)) {
		if (hdr4->ttl <= 1) {
			log_debug("Packet's TTL <= 1.");
			return drop_icmp(state, JSTAT46_TTL, ICMPERR_TTL, 0);
		}
		hdr6->hop_limit = hdr4->ttl - 1;
	} else {
		hdr6->hop_limit = hdr4->ttl;
	}

	/* The addresses are already set. */

	if (will_need_frag_hdr(hdr4) || out->skb->next) {
		hdr6->nexthdr = NEXTHDR_FRAGMENT;

		frag_header = (struct frag_hdr *)(hdr6 + 1);
		frag_header->nexthdr = xlat_nexthdr(hdr4->protocol);
		frag_header->reserved = 0;
		frag_header->frag_off = build_ipv6_frag_off_field(
				get_fragment_offset_ipv4(hdr4),
				is_mf_set_ipv4(hdr4));
		frag_header->identification = build_id_field(hdr4);
	}

	autofill_hdr6(out);

	return VERDICT_CONTINUE;
}

/**
 * One liner for creating the ICMPv6 header's MTU field.
 * Returns the smallest out of the three first parameters. It also handles some
 * quirks. See comments inside for more info.
 */
static __be32 icmp6_minimum_mtu(struct xlation *state,
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

static verdict compute_mtu6(struct xlation *state)
{
	struct icmp6hdr *out_icmp = pkt_icmp6_hdr(&state->out);
#ifndef UNIT_TESTING
	struct iphdr *hdr4;
	struct icmphdr *in_icmp = pkt_icmp4_hdr(&state->in);
	unsigned int in_mtu;
	unsigned int out_mtu;

	/*
	 * 0xfffffff is intended for hairpinning (there's no IPv4 device on
	 * hairpinning).
	 */
	in_mtu = state->in.skb->dev ? state->in.skb->dev->mtu : 0xfffffff;
	out_mtu = skb_dst(state->out.skb)->dev->mtu;

	log_debug("Packet MTU: %u", be16_to_cpu(in_icmp->un.frag.mtu));
	log_debug("In dev MTU: %u", in_mtu);
	log_debug("Out dev MTU: %u", out_mtu);

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
	log_debug("Resulting MTU: %u", be32_to_cpu(out_icmp->icmp6_mtu));

#else
	out_icmp->icmp6_mtu = icmp6_minimum_mtu(state, 9999, 1500, 9999, 100);
#endif

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

	icmp6_hdr->icmp6_type = ICMPV6_DEST_UNREACH;
	icmp6_hdr->icmp6_unused = 0;

	switch (icmp4_hdr->code) {
	case ICMP_NET_UNREACH:
	case ICMP_HOST_UNREACH:
	case ICMP_SR_FAILED:
	case ICMP_NET_UNKNOWN:
	case ICMP_HOST_UNKNOWN:
	case ICMP_HOST_ISOLATED:
	case ICMP_NET_UNR_TOS:
	case ICMP_HOST_UNR_TOS:
		icmp6_hdr->icmp6_code = ICMPV6_NOROUTE;
		return VERDICT_CONTINUE;

	case ICMP_PROT_UNREACH:
		icmp6_hdr->icmp6_type = ICMPV6_PARAMPROB;
		icmp6_hdr->icmp6_code = ICMPV6_UNK_NEXTHDR;
		icmp6_hdr->icmp6_pointer = cpu_to_be32(offsetof(struct ipv6hdr,
				nexthdr));
		return VERDICT_CONTINUE;

	case ICMP_PORT_UNREACH:
		icmp6_hdr->icmp6_code = ICMPV6_PORT_UNREACH;
		return VERDICT_CONTINUE;

	case ICMP_FRAG_NEEDED:
		icmp6_hdr->icmp6_type = ICMPV6_PKT_TOOBIG;
		icmp6_hdr->icmp6_code = 0;
		return compute_mtu6(state);

	case ICMP_NET_ANO:
	case ICMP_HOST_ANO:
	case ICMP_PKT_FILTERED:
	case ICMP_PREC_CUTOFF:
		icmp6_hdr->icmp6_code = ICMPV6_ADM_PROHIBITED;
		return VERDICT_CONTINUE;
	}

	/* hostPrecedenceViolation (14) is known to fall through here. */
	log_debug("ICMPv4 messages type %u code %u lack an ICMPv6 counterpart.",
			icmp4_hdr->type, icmp4_hdr->code);
	/* No ICMP error. */
	return drop(state, JSTAT46_UNTRANSLATABLE_DEST_UNREACH);
}

/**
 * One-liner for translating "Parameter Problem" messages from ICMPv4 to ICMPv6.
 */
static verdict icmp4_to_icmp6_param_prob(struct xlation *state)
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

	icmp6_hdr->icmp6_type = ICMPV6_PARAMPROB;

	switch (icmp4_hdr->code) {
	case ICMP_PTR_INDICATES_ERROR:
	case ICMP_BAD_LENGTH: {
		ptr = be32_to_cpu(icmp4_hdr->icmp4_unused) >> 24;

		if (ptr < 0 || 19 < ptr || ptrs[ptr] == DROP) {
			log_debug("ICMPv4 messages type %u code %u pointer %u lack an ICMPv6 counterpart.",
					icmp4_hdr->type, icmp4_hdr->code, ptr);
			return drop(state, JSTAT46_UNTRANSLATABLE_PARAM_PROBLEM_PTR);
		}

		icmp6_hdr->icmp6_code = ICMPV6_HDR_FIELD;
		icmp6_hdr->icmp6_pointer = cpu_to_be32(ptrs[ptr]);
		return VERDICT_CONTINUE;
	}
	}

	/* missingARequiredOption (1) is known to fall through here. */
	log_debug("ICMPv4 messages type %u code %u lack an ICMPv6 counterpart.",
			icmp4_hdr->type, icmp4_hdr->code);
	/* No ICMP error. */
	return drop(state, JSTAT46_UNTRANSLATABLE_PARAM_PROB);
}

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
		log_debug("Checksum doesn't match.");
		return drop(state, JSTAT46_ICMP_CSUM);
	}

	return VERDICT_CONTINUE;
}

static verdict post_icmp6error(struct xlation *state)
{
	verdict result;

	log_debug("Translating the inner packet (4->6)...");

	/*
	 * We will later recompute the checksum from scratch, but we should not
	 * translate a corrupted ICMPv4 error into an OK-csum ICMPv6 one,
	 * so validate first.
	 */
	result = validate_icmp4_csum(state);
	if (result != VERDICT_CONTINUE)
		return result;

	result = ttpcomm_translate_inner_packet(state);
	if (result != VERDICT_CONTINUE)
		return result;

	compute_icmp6_csum(&state->out);
	return VERDICT_CONTINUE;
}

/**
 * Translates in's icmp4 header and payload into out's icmp6 header and payload.
 * This is the RFC 7915 sections 4.2 and 4.3, except checksum (See post_icmp6()).
 */
verdict ttp46_icmp(struct xlation *state)
{
	struct icmphdr *icmpv4_hdr = pkt_icmp4_hdr(&state->in);
	struct icmp6hdr *icmpv6_hdr = pkt_icmp6_hdr(&state->out);
	verdict result;

	icmpv6_hdr->icmp6_cksum = icmpv4_hdr->checksum; /* default. */

	/* -- First the ICMP header. -- */
	switch (icmpv4_hdr->type) {
	case ICMP_ECHO:
		icmpv6_hdr->icmp6_type = ICMPV6_ECHO_REQUEST;
		icmpv6_hdr->icmp6_code = 0;
		icmpv6_hdr->icmp6_dataun.u_echo.identifier =
				xlation_is_nat64(state)
				? cpu_to_be16(state->out.tuple.icmp6_id)
				: icmpv4_hdr->un.echo.id;
		icmpv6_hdr->icmp6_sequence = icmpv4_hdr->un.echo.sequence;
		update_icmp6_csum(state);
		return VERDICT_CONTINUE;

	case ICMP_ECHOREPLY:
		icmpv6_hdr->icmp6_type = ICMPV6_ECHO_REPLY;
		icmpv6_hdr->icmp6_code = 0;
		icmpv6_hdr->icmp6_dataun.u_echo.identifier =
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
		icmpv6_hdr->icmp6_type = ICMPV6_TIME_EXCEED;
		icmpv6_hdr->icmp6_code = icmpv4_hdr->code;
		icmpv6_hdr->icmp6_unused = 0;
		return post_icmp6error(state);

	case ICMP_PARAMETERPROB:
		result = icmp4_to_icmp6_param_prob(state);
		if (result != VERDICT_CONTINUE)
			return result;
		return post_icmp6error(state);
	}

	/*
	 * The following codes are known to fall through here:
	 * Information Request/Reply (15, 16), Timestamp and Timestamp Reply
	 * (13, 14), Address Mask Request/Reply (17, 18), Router Advertisement
	 * (9), Router Solicitation (10), Source Quench (4), Redirect (5),
	 * Alternative Host Address (6).
	 * This time there's no ICMP error.
	 */
	log_debug("ICMPv4 messages type %u lack an ICMPv6 counterpart.",
			icmpv4_hdr->type);
	return drop(state, JSTAT_UNKNOWN_ICMP4_TYPE);
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

	if (xlation_is_nat64(state))
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
		log_debug("Dropping zero-checksum UDP packet: %pI4#%u->%pI4#%u",
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
	csum = skb_checksum(in->skb, pkt_payload_offset(in),
			pkt_payload_len_pkt(in), csum);
	hdr_udp->check = csum_ipv6_magic(&hdr6->saddr, &hdr6->daddr,
			pkt_datagram_len(in), IPPROTO_UDP, csum);

	return 0;
}

verdict ttp46_tcp(struct xlation *state)
{
	struct packet *in = &state->in;
	struct packet *out = &state->out;
	struct tcphdr *tcp_in = pkt_tcp_hdr(in);
	struct tcphdr *tcp_out = pkt_tcp_hdr(out);
	struct tcphdr tcp_copy;

	/* Header */
	memcpy(tcp_out, tcp_in, pkt_l4hdr_len(in));
	if (xlation_is_nat64(state)) {
		tcp_out->source = cpu_to_be16(out->tuple.src.addr6.l4);
		tcp_out->dest = cpu_to_be16(out->tuple.dst.addr6.l4);
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

verdict ttp46_udp(struct xlation *state)
{
	struct packet *in = &state->in;
	struct packet *out = &state->out;
	struct udphdr *udp_in = pkt_udp_hdr(in);
	struct udphdr *udp_out = pkt_udp_hdr(out);
	struct udphdr udp_copy;

	/* Header */
	memcpy(udp_out, udp_in, pkt_l4hdr_len(in));
	if (xlation_is_nat64(state)) {
		udp_out->source = cpu_to_be16(out->tuple.src.addr6.l4);
		udp_out->dest = cpu_to_be16(out->tuple.dst.addr6.l4);
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
