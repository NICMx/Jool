#include "nat64/mod/common/rfc6145/4to6.h"

#include "nat64/common/constants.h"
#include "nat64/mod/common/config.h"
#include "nat64/mod/common/icmp_wrapper.h"
#include "nat64/mod/common/pool6.h"
#include "nat64/mod/common/rfc6052.h"
#include "nat64/mod/common/route.h"
#include "nat64/mod/common/stats.h"
#include "nat64/mod/stateless/blacklist4.h"
#include "nat64/mod/stateless/eam.h"
#include "nat64/mod/stateless/rfc6791v6.h"

verdict ttp46_create_skb(struct xlation *state)
{
	struct packet *in = &state->in;
	size_t l3_hdr_len;
	size_t total_len;
	size_t reserve = LL_MAX_HEADER;
	struct sk_buff *skb;
	struct frag_hdr *hdr_frag = NULL;

	/*
	 * These are my assumptions to compute total_len:
	 *
	 * The IPv4 header will be replaced by a IPv6 header and possibly a
	 * fragment header.
	 * The L4 header will never change in size
	 *    (in particular, ICMPv4 hdr len == ICMPv6 hdr len).
	 * The payload will not change in TCP, UDP and ICMP infos.
	 *
	 * As for ICMP errors:
	 * The IPv4 header will be replaced by a IPv6 header and possibly a
	 * fragment header.
	 * The sub-L4 header will never change in size.
	 * The subpayload might get truncated to maximize delivery probability.
	 */
	l3_hdr_len = sizeof(struct ipv6hdr);
	if (will_need_frag_hdr(pkt_ip4_hdr(in)))
		l3_hdr_len += sizeof(struct frag_hdr);
	else
		reserve += sizeof(struct frag_hdr);

	total_len = l3_hdr_len + pkt_l3payload_len(in);
	if (is_first_frag4(pkt_ip4_hdr(in)) && pkt_is_icmp4_error(in)) {
		struct iphdr *hdr4_inner = pkt_payload(in);

		total_len += sizeof(struct ipv6hdr) - (hdr4_inner->ihl << 2);
		if (will_need_frag_hdr(hdr4_inner))
			total_len += sizeof(struct frag_hdr);

		/* All errors from RFC 4443 share this. */
		if (total_len > IPV6_MIN_MTU)
			total_len = IPV6_MIN_MTU;
	}

	skb = alloc_skb(reserve + total_len, GFP_ATOMIC);
	if (!skb) {
		inc_stats(in, IPSTATS_MIB_INDISCARDS);
		return VERDICT_DROP;
	}

	skb_reserve(skb, reserve);
	skb_put(skb, total_len);
	skb_reset_mac_header(skb);
	skb_reset_network_header(skb);
	skb_set_transport_header(skb, l3_hdr_len);

	if (will_need_frag_hdr(pkt_ip4_hdr(in)))
		hdr_frag = (struct frag_hdr *)(ipv6_hdr(skb) + 1);

	pkt_fill(&state->out, skb, L3PROTO_IPV6, pkt_l4_proto(in),
			hdr_frag, skb_transport_header(skb) + pkt_l4hdr_len(in),
			pkt_original_pkt(in));

	skb->mark = in->skb->mark;
	skb->protocol = htons(ETH_P_IPV6);

	return VERDICT_CONTINUE;
}

static __be16 build_payload_len(struct packet *in, struct packet *out)
{
	/* See build_tot_len() for relevant comments. */

	__u16 total_len;

	if (pkt_is_inner(out)) { /* Internal packets */
		total_len = be16_to_cpu(pkt_ip4_hdr(in)->tot_len)
				- pkt_hdrs_len(in) + pkt_hdrs_len(out);

	} else if (skb_shinfo(in->skb)->frag_list) { /* Fake full packets */
		total_len = in->skb->len - pkt_hdrs_len(in) + pkt_hdrs_len(out);

	} else { /* Real full packets and fragmented packets */
		total_len = out->skb->len;
		/*
		 * Though ICMPv4 errors are supposed to be max 576 bytes long,
		 * a good portion of the Internet seems prepared against bigger
		 * ICMPv4 errors. Thus, the resulting ICMPv6 packet might have
		 * a smaller payload than the original packet even though
		 * IPv4 MTU < IPv6 MTU.
		 */
		if (pkt_is_icmp6_error(out) && total_len > IPV6_MIN_MTU)
			total_len = IPV6_MIN_MTU;

	} /* (Subsequent fragments don't reach this function) */

	return cpu_to_be16(total_len - sizeof(struct ipv6hdr));
}

static int generate_saddr6_nat64(struct xlation *state)
{
	struct packet *out = &state->out;
	bool src_better;
	struct ipv6_prefix prefix6;
	struct in_addr tmp;
	int error;

	src_better = state->jool.global->cfg.nat64.src_icmp6errs_better;

	if (src_better && pkt_is_icmp4_error(&state->in)) {
		/* Issue #132 behaviour. */
		error = pool6_find(state->jool.pool6, &out->tuple.src.addr6.l3,
				&prefix6);
		if (error)
			return error;
		tmp.s_addr = pkt_ip4_hdr(&state->in)->saddr;
		return addr_4to6(&tmp, &prefix6, &pkt_ip6_hdr(out)->saddr);
	}

	/* RFC 6146 behaviour. */
	pkt_ip6_hdr(out)->saddr = out->tuple.src.addr6.l3;
	return 0;
}

static addrxlat_verdict generate_addr6_siit(struct xlation *state,
		__be32 addr4, struct in6_addr *addr6, bool enable_eam)
{
	struct ipv6_prefix prefix;
	struct in_addr tmp = { .s_addr = addr4 };
	int error;

	if (must_not_translate(&tmp, state->jool.ns)) {
		log_debug("Address %pI4 is not supposed to be xlat'd.", &tmp);
		return ADDRXLAT_ACCEPT;
	}

	if (enable_eam) {
		error = eamt_xlat_4to6(state->jool.siit.eamt, &tmp, addr6);
		if (!error)
			return ADDRXLAT_CONTINUE;
		if (error != -ESRCH)
			return ADDRXLAT_DROP;
	}

	if (blacklist_contains(state->jool.siit.blacklist, &tmp)) {
		log_debug("Address %pI4 lacks EAMT entry and is blacklisted.",
				&tmp);
		return ADDRXLAT_ACCEPT;
	}

	error = pool6_peek(state->jool.pool6, &prefix);
	if (error) {
		log_debug("Address %pI4 lacks EAMT entry and there's no pool6 prefix.",
				&tmp);
		return ADDRXLAT_TRY_SOMETHING_ELSE;
	}
	error = addr_4to6(&tmp, &prefix, addr6);
	if (error) {
		/*
		 * This is not TRY_SOMETHING_ELSE because addr_4to6() can only
		 * fail on criticals, currently.
		 */
		return ADDRXLAT_DROP;
	}

	return ADDRXLAT_CONTINUE;
}

static bool disable_src_eam(struct packet *in, bool hairpin)
{
	struct iphdr *inner_hdr;

	if (!hairpin || pkt_is_inner(in))
		return false;
	if (!pkt_is_icmp4_error(in))
		return true;

	inner_hdr = pkt_payload(in);
	return pkt_ip4_hdr(in)->saddr == inner_hdr->daddr;
}

static bool disable_dst_eam(struct packet *in, bool hairpin)
{
	return hairpin && pkt_is_inner(in);
}

static verdict translate_addrs46_siit(struct xlation *state)
{
	struct packet *in = &state->in;
	struct iphdr *hdr4 = pkt_ip4_hdr(in);
	struct ipv6hdr *hdr6 = pkt_ip6_hdr(&state->out);
	enum eam_hairpinning_mode hairpin_mode;
	bool hairpin;
	addrxlat_verdict result;

	hairpin_mode = state->jool.global->cfg.siit.eam_hairpin_mode;
	hairpin = (hairpin_mode == EAM_HAIRPIN_SIMPLE)
			|| pkt_is_intrinsic_hairpin(in);

	/* Src address. */
	result = generate_addr6_siit(state, hdr4->saddr, &hdr6->saddr,
			!disable_src_eam(in, hairpin));
	switch (result) {
	case ADDRXLAT_CONTINUE:
		break;
	case ADDRXLAT_TRY_SOMETHING_ELSE:
		if (pkt_is_icmp4_error(in)
				&& !rfc6791_find_v6(state, &hdr6->saddr))
			break; /* Ok, success. */
		return VERDICT_ACCEPT;
	case ADDRXLAT_ACCEPT:
	case ADDRXLAT_DROP:
		return (verdict)result;
	}

	/* Dst address. */
	result = generate_addr6_siit(state, hdr4->daddr, &hdr6->daddr,
			!disable_dst_eam(in, hairpin));
	switch (result) {
	case ADDRXLAT_CONTINUE:
		break;
	case ADDRXLAT_TRY_SOMETHING_ELSE:
		return VERDICT_ACCEPT;
	case ADDRXLAT_ACCEPT:
	case ADDRXLAT_DROP:
		return (verdict)result;
	}

	log_debug("Result: %pI6c->%pI6c", &hdr6->saddr, &hdr6->daddr);
	return VERDICT_CONTINUE;
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

/**
 * Infers a IPv6 header from "in"'s IPv4 header and "tuple". Places the result
 * in "out"->l3_hdr.
 * This is RFC 6145 section 4.1.
 *
 * This is used to translate both outer and inner headers.
 */
verdict ttp46_ipv6(struct xlation *state)
{
	struct packet *in = &state->in;
	struct packet *out = &state->out;
	struct iphdr *hdr4 = pkt_ip4_hdr(in);
	struct ipv6hdr *hdr6 = pkt_ip6_hdr(out);
	int error;
	verdict result;

	/* Translate the address first because of issue #167. */
	if (xlat_is_nat64()) {
		error = generate_saddr6_nat64(state);
		if (error)
			return VERDICT_DROP;
		hdr6->daddr = out->tuple.dst.addr6.l3;
	} else {
		result = translate_addrs46_siit(state);
		if (result != VERDICT_CONTINUE)
			return result;
	}

	hdr6->version = 6;
	if (state->jool.global->cfg.reset_traffic_class) {
		hdr6->priority = 0;
		hdr6->flow_lbl[0] = 0;
	} else {
		hdr6->priority = hdr4->tos >> 4;
		hdr6->flow_lbl[0] = hdr4->tos << 4;
	}
	hdr6->flow_lbl[1] = 0;
	hdr6->flow_lbl[2] = 0;
	hdr6->payload_len = build_payload_len(in, out);
	hdr6->nexthdr = (hdr4->protocol == IPPROTO_ICMP)
			? NEXTHDR_ICMP
			: hdr4->protocol;
	if (pkt_is_outer(in) && !pkt_is_intrinsic_hairpin(in)) {
		if (hdr4->ttl <= 1) {
			icmp64_send(in, ICMPERR_HOP_LIMIT, 0);
			inc_stats(in, IPSTATS_MIB_INHDRERRORS);
			return VERDICT_DROP;
		}
		hdr6->hop_limit = hdr4->ttl - 1;
	} else {
		hdr6->hop_limit = hdr4->ttl;
	}

	/* Isn't this supposed to be covered by filtering...? */
	/*
	if (!is_address_legal(&ip6_hdr->saddr))
		return -EINVAL;
	*/

	if (pkt_is_outer(in) && has_unexpired_src_route(hdr4)) {
		log_debug("Packet has an unexpired source route.");
		icmp64_send(in, ICMPERR_SRC_ROUTE, 0);
		inc_stats(in, IPSTATS_MIB_INHDRERRORS);
		return VERDICT_DROP;
	}

	if (will_need_frag_hdr(hdr4)) {
		struct frag_hdr *frag_header = (struct frag_hdr *)(hdr6 + 1);

		/* Override some fixed header fields... */
		hdr6->nexthdr = NEXTHDR_FRAGMENT;

		/* ...and set the fragment header ones. */
		frag_header->nexthdr = (hdr4->protocol == IPPROTO_ICMP)
				? NEXTHDR_ICMP
				: hdr4->protocol;
		frag_header->reserved = 0;
		frag_header->frag_off = build_ipv6_frag_off_field(
				get_fragment_offset_ipv4(hdr4),
				is_mf_set_ipv4(hdr4));
		frag_header->identification = build_id_field(hdr4);
	}

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
		__u16 *plateaus = state->jool.global->cfg.mtu_plateaus;
		__u16 count = state->jool.global->cfg.mtu_plateau_count;
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

static int compute_mtu6(struct xlation *state)
{
	struct icmp6hdr *out_icmp = pkt_icmp6_hdr(&state->out);
#ifndef UNIT_TESTING
	struct dst_entry *out_dst;
	struct iphdr *hdr4;
	struct icmphdr *in_icmp = pkt_icmp4_hdr(&state->in);
	unsigned int in_mtu;

	out_dst = route6(state->jool.ns, &state->out);
	if (!out_dst)
		return -EINVAL;
	/*
	 * 0xfffffff is intended for hairpinning (there's no IPv4 device on
	 * hairpinning).
	 */
	in_mtu = state->in.skb->dev ? state->in.skb->dev->mtu : 0xfffffff;

	log_debug("Packet MTU: %u", be16_to_cpu(in_icmp->un.frag.mtu));
	log_debug("In dev MTU: %u", in_mtu);
	log_debug("Out dev MTU: %u", out_dst->dev->mtu);

	/*
	 * We want the length of the packet that couldn't get through,
	 * not the truncated one.
	 */
	hdr4 = pkt_payload(&state->in);
	out_icmp->icmp6_mtu = icmp6_minimum_mtu(state,
			be16_to_cpu(in_icmp->un.frag.mtu),
			out_dst->dev->mtu,
			in_mtu,
			be16_to_cpu(hdr4->tot_len));
	log_debug("Resulting MTU: %u", be32_to_cpu(out_icmp->icmp6_mtu));

#else
	out_icmp->icmp6_mtu = icmp6_minimum_mtu(state, 9999, 1500, 9999, 100);
#endif

	return 0;
}

/**
 * One-liner for translating "Destination Unreachable" messages from ICMPv4 to
 * ICMPv6.
 */
static int icmp4_to_icmp6_dest_unreach(struct xlation *state)
{
	struct icmphdr *icmp4_hdr = pkt_icmp4_hdr(&state->in);
	struct icmp6hdr *icmp6_hdr = pkt_icmp6_hdr(&state->out);
	int error;

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
		break;

	case ICMP_PROT_UNREACH:
		icmp6_hdr->icmp6_type = ICMPV6_PARAMPROB;
		icmp6_hdr->icmp6_code = ICMPV6_UNK_NEXTHDR;
		icmp6_hdr->icmp6_pointer = cpu_to_be32(offsetof(struct ipv6hdr,
				nexthdr));
		break;

	case ICMP_PORT_UNREACH:
		icmp6_hdr->icmp6_code = ICMPV6_PORT_UNREACH;
		break;

	case ICMP_FRAG_NEEDED:
		icmp6_hdr->icmp6_type = ICMPV6_PKT_TOOBIG;
		icmp6_hdr->icmp6_code = 0;
		error = compute_mtu6(state);
		if (error)
			return error;
		break;

	case ICMP_NET_ANO:
	case ICMP_HOST_ANO:
	case ICMP_PKT_FILTERED:
	case ICMP_PREC_CUTOFF:
		icmp6_hdr->icmp6_code = ICMPV6_ADM_PROHIBITED;
		break;

	default:
		/*
		 * hostPrecedenceViolation (14) is known to fall through here.
		 */
		log_debug("ICMPv4 messages type %u code %u lack an ICMPv6 counterpart.",
				icmp4_hdr->type, icmp4_hdr->code);
		inc_stats(&state->in, IPSTATS_MIB_INHDRERRORS);
		return -EINVAL; /* No ICMP error. */
	}

	return 0;
}

/**
 * One-liner for translating "Parameter Problem" messages from ICMPv4 to ICMPv6.
 */
static int icmp4_to_icmp6_param_prob(struct icmphdr *icmp4_hdr,
		struct icmp6hdr *icmp6_hdr)
{
	__u8 ptr;

	icmp6_hdr->icmp6_type = ICMPV6_PARAMPROB;

	switch (icmp4_hdr->code) {
	case ICMP_PTR_INDICATES_ERROR:
	case ICMP_BAD_LENGTH: {
		const __u8 DROP = 255;
		__u8 ptrs[] = { 0, 1, 4, 4,
				DROP, DROP, DROP, DROP,
				7, 6, DROP, DROP,
				8, 8, 8, 8,
				24, 24, 24, 24
		};

		ptr = be32_to_cpu(icmp4_hdr->icmp4_unused) >> 24;

		if (ptr < 0 || 19 < ptr || ptrs[ptr] == DROP) {
			log_debug("ICMPv4 messages type %u code %u pointer %u lack an ICMPv6 counterpart.",
					icmp4_hdr->type, icmp4_hdr->code, ptr);
			return -EINVAL;
		}

		icmp6_hdr->icmp6_code = ICMPV6_HDR_FIELD;
		icmp6_hdr->icmp6_pointer = cpu_to_be32(ptrs[ptr]);
		break;
	}
	default: /* missingARequiredOption (1) is known to fall through here. */
		log_debug("ICMPv4 messages type %u code %u lack an ICMPv6 counterpart.",
				icmp4_hdr->type, icmp4_hdr->code);
		return -EINVAL; /* No ICMP error. */
	}

	return 0;
}

static int update_icmp6_csum(struct xlation *state)
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

	return 0;
}

static int compute_icmp6_csum(struct packet *out)
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

	return 0;
}

static verdict validate_icmp4_csum(struct packet *in)
{
	__sum16 csum;

	if (in->skb->ip_summed != CHECKSUM_NONE)
		return VERDICT_CONTINUE;

	csum = csum_fold(skb_checksum(in->skb, skb_transport_offset(in->skb),
			pkt_datagram_len(in), 0));
	if (csum != 0) {
		log_debug("Checksum doesn't match.");
		inc_stats(in, IPSTATS_MIB_INHDRERRORS);
		return VERDICT_DROP;
	}

	return VERDICT_CONTINUE;
}

static int post_icmp6info(struct xlation *state)
{
	int error;

	error = copy_payload(state);
	if (error)
		return error;

	return update_icmp6_csum(state);
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
	result = validate_icmp4_csum(&state->in);
	if (result != VERDICT_CONTINUE)
		return result;

	result = ttpcomm_translate_inner_packet(state);
	if (result != VERDICT_CONTINUE)
		return result;

	return compute_icmp6_csum(&state->out) ? VERDICT_DROP : VERDICT_CONTINUE;
}

/**
 * Translates in's icmp4 header and payload into out's icmp6 header and payload.
 * This is the RFC 6145 sections 4.2 and 4.3, except checksum (See post_icmp6()).
 */
verdict ttp46_icmp(struct xlation *state)
{
	struct icmphdr *icmpv4_hdr = pkt_icmp4_hdr(&state->in);
	struct icmp6hdr *icmpv6_hdr = pkt_icmp6_hdr(&state->out);
	int error = 0;

	icmpv6_hdr->icmp6_cksum = icmpv4_hdr->checksum; /* default. */

	/* -- First the ICMP header. -- */
	switch (icmpv4_hdr->type) {
	case ICMP_ECHO:
		icmpv6_hdr->icmp6_type = ICMPV6_ECHO_REQUEST;
		icmpv6_hdr->icmp6_code = 0;
		icmpv6_hdr->icmp6_dataun.u_echo.identifier = xlat_is_nat64()
				? cpu_to_be16(state->out.tuple.icmp6_id)
				: icmpv4_hdr->un.echo.id;
		icmpv6_hdr->icmp6_sequence = icmpv4_hdr->un.echo.sequence;
		error = post_icmp6info(state);
		break;

	case ICMP_ECHOREPLY:
		icmpv6_hdr->icmp6_type = ICMPV6_ECHO_REPLY;
		icmpv6_hdr->icmp6_code = 0;
		icmpv6_hdr->icmp6_dataun.u_echo.identifier = xlat_is_nat64()
				? cpu_to_be16(state->out.tuple.icmp6_id)
				: icmpv4_hdr->un.echo.id;
		icmpv6_hdr->icmp6_sequence = icmpv4_hdr->un.echo.sequence;
		error = post_icmp6info(state);
		break;

	case ICMP_DEST_UNREACH:
		error = icmp4_to_icmp6_dest_unreach(state);
		if (error)
			return VERDICT_DROP;
		return post_icmp6error(state);

	case ICMP_TIME_EXCEEDED:
		icmpv6_hdr->icmp6_type = ICMPV6_TIME_EXCEED;
		icmpv6_hdr->icmp6_code = icmpv4_hdr->code;
		icmpv6_hdr->icmp6_unused = 0;
		return post_icmp6error(state);

	case ICMP_PARAMETERPROB:
		error = icmp4_to_icmp6_param_prob(icmpv4_hdr, icmpv6_hdr);
		if (error) {
			inc_stats(&state->in, IPSTATS_MIB_INHDRERRORS);
			return VERDICT_DROP;
		}
		return post_icmp6error(state);

	default:
		/*
		 * The following codes are known to fall through here:
		 * Information Request/Reply (15, 16), Timestamp and Timestamp
		 * Reply (13, 14), Address Mask Request/Reply (17, 18), Router
		 * Advertisement (9), Router Solicitation (10), Source Quench
		 * (4), Redirect (5), Alternative Host Address (6).
		 * This time there's no ICMP error.
		 */
		log_debug("ICMPv4 messages type %u lack an ICMPv6 counterpart.",
				icmpv4_hdr->type);
		inc_stats(&state->in, IPSTATS_MIB_INHDRERRORS);
		return VERDICT_DROP;
	}

	return error ? VERDICT_DROP : VERDICT_CONTINUE;
}

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

	if (xlat_is_nat64())
		return true;

	/*
	 * RFC 6145#4.5:
	 * A stateless translator cannot compute the UDP checksum of
	 * fragmented packets, so when a stateless translator receives the
	 * first fragment of a fragmented UDP IPv4 packet and the checksum
	 * field is zero, the translator SHOULD drop the packet and generate
	 * a system management event that specifies at least the IP
	 * addresses and port numbers in the packet.
	 */
	hdr4 = pkt_ip4_hdr(&state->in);
	amend_csum0 = state->jool.global->cfg.siit.compute_udp_csum_zero;
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
 * This is actually required in the Determine Incoming Tuple step, but it feels
 * more at home here.
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
	 * That's the reason why we needed in as an argument.
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
	if (xlat_is_nat64()) {
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

	/* Payload */
	return copy_payload(state) ? VERDICT_DROP : VERDICT_CONTINUE;
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
	if (xlat_is_nat64()) {
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
		if (handle_zero_csum(state))
			return VERDICT_DROP;
	}

	/* Payload */
	return copy_payload(state) ? VERDICT_DROP : VERDICT_CONTINUE;
}
