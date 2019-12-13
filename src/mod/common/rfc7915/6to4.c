#include "mod/common/rfc7915/6to4.h"

#include <linux/inetdevice.h>
#include <net/ip6_checksum.h>

#include "mod/common/ipv6_hdr_iterator.h"
#include "mod/common/linux_version.h"
#include "mod/common/log.h"
#include "mod/common/route.h"
#include "mod/common/rfc7915/common.h"

static __u8 ttp64_xlat_tos(struct globals *config, struct ipv6hdr *hdr)
{
	return config->reset_tos ? config->new_tos : get_traffic_class(hdr);
}

/**
 * One-liner for creating the IPv4 header's Protocol field.
 */
static __u8 ttp64_xlat_proto(struct ipv6hdr *hdr6)
{
	struct hdr_iterator iterator = HDR_ITERATOR_INIT(hdr6);
	hdr_iterator_last(&iterator);
	return (iterator.hdr_type == NEXTHDR_ICMP)
			? IPPROTO_ICMP
			: iterator.hdr_type;
}

static struct dst_entry *predict_route(struct xlation *state)
{
	struct ipv6hdr *hdr6;
	struct flowi4 flow;

	hdr6 = pkt_ip6_hdr(&state->in);

	memset(&flow, 0, sizeof(flow));
	/* flow.flowi4_oif; */
	/* flow.flowi4_iif; */
	flow.flowi4_mark = state->in.skb->mark;
	flow.flowi4_tos = ttp64_xlat_tos(&state->jool.globals, hdr6);
	flow.flowi4_scope = RT_SCOPE_UNIVERSE;
	flow.flowi4_proto = ttp64_xlat_proto(hdr6);
	/*
	 * ANYSRC disables the source address reachable validation.
	 * It's best to include it because none of the xlat addresses are
	 * required to be present in the routing table.
	 */
	flow.flowi4_flags = FLOWI_FLAG_ANYSRC;
	/* Only used by XFRM ATM (kernel/Documentation/networking/secid.txt). */
	/* flow.flowi4_secid; */
	flow.saddr = state->out.tuple.src.addr4.l3.s_addr;
	flow.daddr = state->out.tuple.dst.addr4.l3.s_addr;

	switch (flow.flowi4_proto) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
		flow.fl4_sport = state->out.tuple.src.addr4.l4;
		flow.fl4_sport = state->out.tuple.src.addr4.l4;
		break;
	case IPPROTO_ICMP:
		/*
		 * type and code have not been translated yet, and I don't think
		 * they're worth the trouble.
		 * These flowi fields are probably just clutter at this point.
		 */
		break;
	}

	return route4(state->jool.ns, &flow);
}

static verdict addrs_set(struct xlation *state)
{
	struct packet *out;
	struct iphdr *hdr;

	out = &state->out;
	hdr = pkt_ip4_hdr(out);
	hdr->saddr = out->tuple.src.addr4.l3.s_addr;
	hdr->daddr = out->tuple.src.addr4.l3.s_addr;

	if (hdr->saddr == 0) { /* Empty 6791 pool */
		if (WARN(!xlator_is_siit(&state->jool),
				"Zero source address on not SIIT!"))
			return drop(state, JSTAT_UNKNOWN);
		if (WARN(!is_icmp6_error(pkt_icmp6_hdr(&state->in)->icmp6_type),
				"Zero source on not ICMP error!"))
			return drop(state, JSTAT_UNKNOWN);

		hdr->saddr = inet_select_addr(skb_dst(out->skb)->dev,
				hdr->daddr, RT_SCOPE_UNIVERSE);
		if (hdr->saddr == 0)
			return drop(state, JSTAT64_6791_ESRCH);
	}

	return VERDICT_CONTINUE;
}

verdict ttp64_alloc_skb(struct xlation *state)
{
	struct packet *in = &state->in;
	struct sk_buff *out;
	struct skb_shared_info *shinfo;
	struct dst_entry *dst;
	int error;

	dst = predict_route(state);
	if (!dst)
		return untranslatable(state, JSTAT_FAILED_ROUTES);

	/*
	 * I'm going to use __pskb_copy() (via pskb_copy()) because I need the
	 * incoming and outgoing packets to share the same paged data. This is
	 * not only for the sake of performance (prevents lots of data copying
	 * and large contiguous skbs in memory) but also because the pages need
	 * to survive the translation for GSO to work.
	 *
	 * Since the IPv4 version of the packet is going to be invariably
	 * smaller than its IPv6 counterpart, you'd think we should reserve less
	 * memory for it. But there's a problem: __pskb_copy() only allows us to
	 * shrink the headroom; not the head. If we try to shrink the head
	 * through the headroom and the v6 packet happens to have one too many
	 * extension headers, the `headroom` we'll send to __pskb_copy() will be
	 * negative, and then skb_copy_from_linear_data() will write onto the
	 * tail area without knowing it. (I'm reading the Linux 4.4 code.)
	 *
	 * We will therefore *not* attempt to allocate less.
	 */

	out = pskb_copy(in->skb, GFP_ATOMIC);
	if (!out) {
		dst_release(dst);
		log_debug("pskb_copy() returned NULL.");
		return drop(state, JSTAT64_PSKB_COPY);
	}

	/* https://github.com/NICMx/Jool/issues/289 */
#if LINUX_VERSION_AT_LEAST(5, 4, 0, 9999, 0)
	nf_reset_ct(out);
#else
	nf_reset(out);
#endif

	/* Remove outer l3 and l4 headers from the copy. */
	skb_pull(out, pkt_hdrs_len(in));

	if (is_first_frag6(pkt_frag_hdr(in)) && pkt_is_icmp6_error(in)) {
		struct ipv6hdr *hdr = pkt_payload(in);
		struct hdr_iterator iterator = HDR_ITERATOR_INIT(hdr);
		hdr_iterator_last(&iterator);

		/* Remove inner l3 headers from the copy. */
		skb_pull(out, iterator.data - (void *)hdr);

		/* Add inner l3 headers to the copy. */
		skb_push(out, sizeof(struct iphdr));
	}

	/* Add outer l4 headers to the copy. */
	skb_push(out, pkt_l4hdr_len(in));
	/* Add outer l3 headers to the copy. */
	skb_push(out, sizeof(struct iphdr));

	/*
	 * According to my tests, if we send an ICMP error that exceeds the MTU,
	 * Linux will either drop it (if out->skb->local_df is false) or
	 * fragment it (if out->skb->local_df is true).
	 * Neither of these possibilities is even remotely acceptable.
	 * We'll maximize probability delivery by truncating to mandatory
	 * minimum size.
	 */
	if (pkt_is_icmp6_error(in)) {
		/*
		 * RFC1812 section 4.3.2.3.
		 * (I'm using a literal because the RFC does.)
		 *
		 * pskb_trim() CAN CHANGE SKB POINTERS.
		 */
		error = pskb_trim(out, 576);
		if (error) {
			kfree_skb(out);
			dst_release(dst);
			log_debug("pskb_trim() returned errcode %d.", error);
			return drop(state, JSTAT_ENOMEM);
		}
	}

	skb_reset_mac_header(out);
	skb_reset_network_header(out);
	skb_set_transport_header(out, sizeof(struct iphdr));

	/* Wrap up. */
	pkt_fill(&state->out, out, L3PROTO_IPV4, pkt_l4_proto(in),
			NULL, skb_transport_header(out) + pkt_l4hdr_len(in),
			pkt_original_pkt(in));

	memset(out->cb, 0, sizeof(out->cb));
	out->mark = in->skb->mark;
	out->protocol = htons(ETH_P_IP);

	shinfo = skb_shinfo(out);
	if (shinfo->gso_type & SKB_GSO_TCPV6) {
		shinfo->gso_type &= ~SKB_GSO_TCPV6;
		shinfo->gso_type |= SKB_GSO_TCPV4;
	}

	skb_dst_set(out, dst);
	return addrs_set(state);
}

/**
 * One-liner for creating the IPv4 header's Total Length field.
 */
static __be16 build_tot_len(struct packet *in, struct packet *out)
{
	__u16 total_len;

	/*
	 * I implemented it this way for two reasons:
	 * 1. To mirror build_payload_len().
	 * 2. To avoid having to override if it turns out we need to worry about
	 *    fragmentation.
	 */

	if (pkt_is_inner(out)) {
		total_len = get_tot_len_ipv6(in->skb) - pkt_hdrs_len(in)
				+ pkt_hdrs_len(out);
	} else {
		total_len = out->skb->len;
	}

	return cpu_to_be16(total_len);
}

/**
 * One-liner for creating the IPv4 header's Identification field.
 */
static verdict generate_ipv4_id(struct xlation *state, struct iphdr *hdr4,
    struct frag_hdr *hdr_frag)
{
	/*
	 * This if might seem pointlessly premature.
	 *
	 * We used to call get_random_bytes() instead of __ip_select_ident().
	 * The former is rather slow, so we didn't want to call it pointlessly.
	 * That's the reason why we considered fragmentation prematurely.
	 *
	 * __ip_select_ident() is not as slow, but it can still take a little
	 * more than a hundred nanoseconds. Also, it's a black box really.
	 * So I decided to leave this if here.
	 */

	if (hdr_frag) {
		hdr4->id = cpu_to_be16(be32_to_cpu(hdr_frag->identification));
		return VERDICT_CONTINUE;
	}

#if LINUX_VERSION_AT_LEAST(4, 1, 0, 7, 3)
	__ip_select_ident(state->jool.ns, hdr4, 1);
#elif LINUX_VERSION_AT_LEAST(3, 16, 0, 7, 3)
	__ip_select_ident(hdr4, 1);
#else
	__ip_select_ident(hdr4, skb_dst(state->out.skb), 1);
#endif

	return VERDICT_CONTINUE;
}

/**
 * One-liner for creating the IPv4 header's Dont Fragment flag.
 */
static bool generate_df_flag(struct packet *out)
{
	unsigned int len;

	len = pkt_is_outer(out)
			? pkt_len(out)
			: be16_to_cpu(pkt_ip4_hdr(out)->tot_len);

	return len > 1260;
}

/**
 * has_nonzero_segments_left - Returns true if @hdr6's packet has a routing
 * header, and its Segments Left field is not zero.
 *
 * @location: if the packet has nonzero segments left, the offset
 *		of the segments left field (from the start of @hdr6) will be
 *		stored here.
 */
static bool has_nonzero_segments_left(struct ipv6hdr *hdr6, __u32 *location)
{
	struct ipv6_rt_hdr *rt_hdr;
	unsigned int offset;

	rt_hdr = hdr_iterator_find(hdr6, NEXTHDR_ROUTING);
	if (!rt_hdr)
		return false;

	if (rt_hdr->segments_left == 0)
		return false;

	offset = ((void *)rt_hdr) - (void *)hdr6;
	*location = offset + offsetof(struct ipv6_rt_hdr, segments_left);
	return true;
}

/**
 * Translates @state->in's IPv6 header into @state->out's IPv4 header.
 * This is RFC 7915 sections 5.1 and 5.1.1.
 *
 * This is used to translate both outer and inner headers.
 */
verdict ttp64_ipv4(struct xlation *state)
{
	struct packet *in = &state->in;
	struct packet *out = &state->out;
	struct ipv6hdr *hdr6 = pkt_ip6_hdr(in);
	struct iphdr *hdr4 = pkt_ip4_hdr(out);
	struct frag_hdr *hdr_frag = pkt_frag_hdr(in);
	verdict result;

	hdr4->version = 4;
	hdr4->ihl = 5;
	hdr4->tos = ttp64_xlat_tos(&state->jool.globals, hdr6);
	hdr4->tot_len = build_tot_len(in, out);

	result = generate_ipv4_id(state, hdr4, hdr_frag);
	if (result != VERDICT_CONTINUE)
		return result;

	hdr4->frag_off = build_ipv4_frag_off_field(generate_df_flag(out), 0, 0);

	if (pkt_is_outer(in)) {
		if (hdr6->hop_limit <= 1) {
			log_debug("Packet's hop limit <= 1.");
			return drop_icmp(state, JSTAT64_TTL, ICMPERR_TTL, 0);
		}
		hdr4->ttl = hdr6->hop_limit - 1;
	} else {
		hdr4->ttl = hdr6->hop_limit;
	}

	hdr4->protocol = ttp64_xlat_proto(hdr6);
	/* ip4_hdr->check is set later; please scroll down. */
	/* The addresses are already taken care of. */

	if (pkt_is_outer(in)) {
		__u32 nonzero_location;
		if (has_nonzero_segments_left(hdr6, &nonzero_location)) {
			log_debug("Packet's segments left field is nonzero.");
			return drop_icmp(state, JSTAT64_SEGMENTS_LEFT,
					ICMPERR_HDR_FIELD, nonzero_location);
		}
	}

	if (hdr_frag) {
		/*
		 * hdr4->tot_len, id and protocol above already include the
		 * frag header and don't need further tweaking.
		 */
		hdr4->frag_off = build_ipv4_frag_off_field(0,
				is_mf_set_ipv6(hdr_frag),
				get_fragment_offset_ipv6(hdr_frag));
	}

	hdr4->check = 0;
	hdr4->check = ip_fast_csum(hdr4, hdr4->ihl);

	return VERDICT_CONTINUE;
}

/**
 * One liner for creating the ICMPv4 header's MTU field.
 * Returns the smallest out of the three parameters.
 */
static __be16 minimum(unsigned int mtu1, unsigned int mtu2, unsigned int mtu3)
{
	return cpu_to_be16(min(mtu1, min(mtu2, mtu3)));
}

static verdict compute_mtu4(struct xlation *state)
{
	struct icmphdr *out_icmp = pkt_icmp4_hdr(&state->out);
#ifndef UNIT_TESTING
	struct icmp6hdr *in_icmp = pkt_icmp6_hdr(&state->in);

	log_debug("Packet MTU: %u", be32_to_cpu(in_icmp->icmp6_mtu));
	log_debug("In dev MTU: %u", state->in.skb->dev->mtu);
	log_debug("Out dev MTU: %u", skb_dst(state->out.skb)->dev->mtu);

	out_icmp->un.frag.mtu = minimum(be32_to_cpu(in_icmp->icmp6_mtu) - 20,
			skb_dst(state->out.skb)->dev->mtu,
			state->in.skb->dev->mtu - 20);
	log_debug("Resulting MTU: %u", be16_to_cpu(out_icmp->un.frag.mtu));

#else
	out_icmp->un.frag.mtu = minimum(1500, 9999, 9999);
#endif

	return VERDICT_CONTINUE;
}

/**
 * One liner for translating the ICMPv6's pointer field to ICMPv4.
 * "Pointer" is a field from "Parameter Problem" ICMP messages.
 */
static verdict icmp6_to_icmp4_param_prob_ptr(struct xlation *state)
{
	struct icmp6hdr *icmpv6_hdr = pkt_icmp6_hdr(&state->in);
	struct icmphdr *icmpv4_hdr = pkt_icmp4_hdr(&state->out);
	__u32 icmp6_ptr = be32_to_cpu(icmpv6_hdr->icmp6_dataun.un_data32[0]);
	__u32 icmp4_ptr;

	if (icmp6_ptr < 0 || 39 < icmp6_ptr)
		goto failure;

	switch (icmp6_ptr) {
	case 0:
		icmp4_ptr = 0;
		goto success;
	case 1:
		icmp4_ptr = 1;
		goto success;
	case 2:
	case 3:
		goto failure;
	case 4:
	case 5:
		icmp4_ptr = 2;
		goto success;
	case 6:
		icmp4_ptr = 9;
		goto success;
	case 7:
		icmp4_ptr = 8;
		goto success;
	}

	if (icmp6_ptr >= 24) {
		icmp4_ptr = 16;
		goto success;
	}
	if (icmp6_ptr >= 8) {
		icmp4_ptr = 12;
		goto success;
	}

	/* The above ifs are supposed to cover all the possible values. */
	WARN(true, "Parameter problem pointer '%u' is unknown.", icmp6_ptr);
	goto failure;

success:
	icmpv4_hdr->icmp4_unused = cpu_to_be32(icmp4_ptr << 24);
	return VERDICT_CONTINUE;
failure:
	log_debug("Parameter problem pointer '%u' lacks an ICMPv4 counterpart.",
			icmp6_ptr);
	return drop(state, JSTAT64_UNTRANSLATABLE_PARAM_PROB_PTR);
}

/**
 * One-liner for translating "Destination Unreachable" messages from ICMPv6 to
 * ICMPv4.
 */
static verdict icmp6_to_icmp4_dest_unreach(struct xlation *state)
{
	struct icmp6hdr *icmpv6_hdr = pkt_icmp6_hdr(&state->in);
	struct icmphdr *icmpv4_hdr = pkt_icmp4_hdr(&state->out);

	icmpv4_hdr->type = ICMP_DEST_UNREACH;
	icmpv4_hdr->icmp4_unused = 0;

	switch (icmpv6_hdr->icmp6_code) {
	case ICMPV6_NOROUTE:
	case ICMPV6_NOT_NEIGHBOUR:
	case ICMPV6_ADDR_UNREACH:
		icmpv4_hdr->code = ICMP_HOST_UNREACH;
		return VERDICT_CONTINUE;

	case ICMPV6_ADM_PROHIBITED:
		icmpv4_hdr->code = ICMP_HOST_ANO;
		return VERDICT_CONTINUE;

	case ICMPV6_PORT_UNREACH:
		icmpv4_hdr->code = ICMP_PORT_UNREACH;
		return VERDICT_CONTINUE;
	}

	log_debug("ICMPv6 messages type %u code %u lack an ICMPv4 counterpart.",
			icmpv6_hdr->icmp6_type, icmpv6_hdr->icmp6_code);
	return drop(state, JSTAT64_UNTRANSLATABLE_DEST_UNREACH);
}

/**
 * One-liner for translating "Parameter Problem" messages from ICMPv6 to ICMPv4.
 */
static verdict icmp6_to_icmp4_param_prob(struct xlation *state)
{
	struct icmp6hdr *icmpv6_hdr = pkt_icmp6_hdr(&state->in);
	struct icmphdr *icmpv4_hdr = pkt_icmp4_hdr(&state->out);

	switch (icmpv6_hdr->icmp6_code) {
	case ICMPV6_HDR_FIELD:
		icmpv4_hdr->type = ICMP_PARAMETERPROB;
		icmpv4_hdr->code = 0;
		return icmp6_to_icmp4_param_prob_ptr(state);

	case ICMPV6_UNK_NEXTHDR:
		icmpv4_hdr->type = ICMP_DEST_UNREACH;
		icmpv4_hdr->code = ICMP_PROT_UNREACH;
		icmpv4_hdr->icmp4_unused = 0;
		return VERDICT_CONTINUE;
	}

	/* ICMPV6_UNK_OPTION is known to fall through here. */
	log_debug("ICMPv6 messages type %u code %u lack an ICMPv4 counterpart.",
			icmpv6_hdr->icmp6_type, icmpv6_hdr->icmp6_code);
	return drop(state, JSTAT64_UNTRANSLATABLE_PARAM_PROB);
}

/*
 * Use this when only the ICMP header changed, so all there is to do is subtract
 * the old data from the checksum and add the new one.
 */
static void update_icmp4_csum(struct xlation *state)
{
	struct ipv6hdr *in_ip6 = pkt_ip6_hdr(&state->in);
	struct icmp6hdr *in_icmp = pkt_icmp6_hdr(&state->in);
	struct icmphdr *out_icmp = pkt_icmp4_hdr(&state->out);
	struct icmp6hdr copy_hdr;
	__wsum csum, tmp;

	csum = ~csum_unfold(in_icmp->icmp6_cksum);

	/* Remove the ICMPv6 pseudo-header. */
	tmp = ~csum_unfold(csum_ipv6_magic(&in_ip6->saddr, &in_ip6->daddr,
			pkt_datagram_len(&state->in), NEXTHDR_ICMP, 0));
	csum = csum_sub(csum, tmp);

	/*
	 * Remove the ICMPv6 header.
	 * I'm working on a copy because I need to zero out its checksum.
	 * If I did that directly on the skb, I'd need to make it writable
	 * first.
	 */
	memcpy(&copy_hdr, in_icmp, sizeof(*in_icmp));
	copy_hdr.icmp6_cksum = 0;
	tmp = csum_partial(&copy_hdr, sizeof(copy_hdr), 0);
	csum = csum_sub(csum, tmp);

	/* Add the ICMPv4 header. There's no ICMPv4 pseudo-header. */
	out_icmp->checksum = 0;
	tmp = csum_partial(out_icmp, sizeof(*out_icmp), 0);
	csum = csum_add(csum, tmp);

	out_icmp->checksum = csum_fold(csum);
}

/**
 * Use this when header and payload both changed completely, so we gotta just
 * trash the old checksum and start anew.
 */
static void compute_icmp4_csum(struct packet *out)
{
	struct icmphdr *hdr = pkt_icmp4_hdr(out);

	/*
	 * This function only gets called for ICMP error checksums, so
	 * pkt_datagram_len() is fine.
	 */
	hdr->checksum = 0;
	hdr->checksum = csum_fold(skb_checksum(out->skb,
			skb_transport_offset(out->skb),
			pkt_datagram_len(out), 0));
	out->skb->ip_summed = CHECKSUM_NONE;
}

static verdict validate_icmp6_csum(struct xlation *state)
{
	struct packet *in = &state->in;
	struct ipv6hdr *hdr6;
	unsigned int len;
	__sum16 csum;

	if (in->skb->ip_summed != CHECKSUM_NONE)
		return VERDICT_CONTINUE;

	hdr6 = pkt_ip6_hdr(in);
	len = pkt_datagram_len(in);
	csum = csum_ipv6_magic(&hdr6->saddr, &hdr6->daddr, len, NEXTHDR_ICMP,
			skb_checksum(in->skb, skb_transport_offset(in->skb),
					len, 0));
	if (csum != 0) {
		log_debug("Checksum doesn't match.");
		return drop(state, JSTAT64_ICMP_CSUM);
	}

	return VERDICT_CONTINUE;
}

static verdict post_icmp4error(struct xlation *state)
{
	verdict result;

	log_debug("Translating the inner packet (6->4)...");

	result = validate_icmp6_csum(state);
	if (result != VERDICT_CONTINUE)
		return result;

	result = ttpcomm_translate_inner_packet(state);
	if (result != VERDICT_CONTINUE)
		return result;

	compute_icmp4_csum(&state->out);
	return VERDICT_CONTINUE;
}

/**
 * Translates in's icmp6 header and payload into out's icmp4 header and payload.
 * This is the core of RFC 7915 sections 5.2 and 5.3, except checksum (See
 * post_icmp4*()).
 */
verdict ttp64_icmp(struct xlation *state)
{
	struct icmp6hdr *icmpv6_hdr = pkt_icmp6_hdr(&state->in);
	struct icmphdr *icmpv4_hdr = pkt_icmp4_hdr(&state->out);
	verdict result;

	icmpv4_hdr->checksum = icmpv6_hdr->icmp6_cksum; /* default. */

	switch (icmpv6_hdr->icmp6_type) {
	case ICMPV6_ECHO_REQUEST:
		icmpv4_hdr->type = ICMP_ECHO;
		icmpv4_hdr->code = 0;
		icmpv4_hdr->un.echo.id = xlation_is_nat64(state)
				? cpu_to_be16(state->out.tuple.icmp4_id)
				: icmpv6_hdr->icmp6_identifier;
		icmpv4_hdr->un.echo.sequence = icmpv6_hdr->icmp6_sequence;
		update_icmp4_csum(state);
		return VERDICT_CONTINUE;

	case ICMPV6_ECHO_REPLY:
		icmpv4_hdr->type = ICMP_ECHOREPLY;
		icmpv4_hdr->code = 0;
		icmpv4_hdr->un.echo.id = xlation_is_nat64(state)
				? cpu_to_be16(state->out.tuple.icmp4_id)
				: icmpv6_hdr->icmp6_identifier;
		icmpv4_hdr->un.echo.sequence = icmpv6_hdr->icmp6_sequence;
		update_icmp4_csum(state);
		return VERDICT_CONTINUE;

	case ICMPV6_DEST_UNREACH:
		result = icmp6_to_icmp4_dest_unreach(state);
		if (result != VERDICT_CONTINUE)
			return result;
		return post_icmp4error(state);

	case ICMPV6_PKT_TOOBIG:
		/*
		 * BTW, I have no idea what the RFC means by "taking into
		 * account whether or not the packet in error includes a
		 * Fragment Header"... What does the fragment header have to do
		 * with anything here?
		 */
		icmpv4_hdr->type = ICMP_DEST_UNREACH;
		icmpv4_hdr->code = ICMP_FRAG_NEEDED;
		icmpv4_hdr->un.frag.__unused = htons(0);
		result = compute_mtu4(state);
		if (result != VERDICT_CONTINUE)
			return result;
		return post_icmp4error(state);

	case ICMPV6_TIME_EXCEED:
		icmpv4_hdr->type = ICMP_TIME_EXCEEDED;
		icmpv4_hdr->code = icmpv6_hdr->icmp6_code;
		icmpv4_hdr->icmp4_unused = 0;
		return post_icmp4error(state);

	case ICMPV6_PARAMPROB:
		result = icmp6_to_icmp4_param_prob(state);
		if (result != VERDICT_CONTINUE)
			return result;
		return post_icmp4error(state);
	}

	/*
	 * The following codes are known to fall through here:
	 * ICMPV6_MGM_QUERY, ICMPV6_MGM_REPORT, ICMPV6_MGM_REDUCTION, Neighbor
	 * Discover messages (133 - 137).
	 */
	log_debug("ICMPv6 messages type %u lack an ICMPv4 counterpart.",
			icmpv6_hdr->icmp6_type);
	return drop(state, JSTAT_UNKNOWN_ICMP6_TYPE);
}

static __wsum pseudohdr6_csum(struct ipv6hdr *hdr)
{
	return ~csum_unfold(csum_ipv6_magic(&hdr->saddr, &hdr->daddr, 0, 0, 0));
}

static __wsum pseudohdr4_csum(struct iphdr *hdr)
{
	return csum_tcpudp_nofold(hdr->saddr, hdr->daddr, 0, 0, 0);
}

static __sum16 update_csum_6to4(__sum16 csum16,
		struct ipv6hdr *in_ip6, void *in_l4_hdr, size_t in_l4_hdr_len,
		struct iphdr *out_ip4, void *out_l4_hdr, size_t out_l4_hdr_len)
{
	__wsum csum;

	csum = ~csum_unfold(csum16);

	/*
	 * Regarding the pseudoheaders:
	 * The length is pretty hard to obtain if there's TCP and fragmentation,
	 * and whatever it is, it's not going to change. Therefore, instead of
	 * computing it only to cancel it out with itself later, simply sum
	 * (and substract) zero.
	 * Do the same with proto since we're feeling ballsy.
	 */

	/* Remove the IPv6 crap. */
	csum = csum_sub(csum, pseudohdr6_csum(in_ip6));
	csum = csum_sub(csum, csum_partial(in_l4_hdr, in_l4_hdr_len, 0));

	/* Add the IPv4 crap. */
	csum = csum_add(csum, pseudohdr4_csum(out_ip4));
	csum = csum_add(csum, csum_partial(out_l4_hdr, out_l4_hdr_len, 0));

	return csum_fold(csum);
}

static __sum16 update_csum_6to4_partial(__sum16 csum16, struct ipv6hdr *in_ip6,
		struct iphdr *out_ip4)
{
	__wsum csum = csum_unfold(csum16);
	csum = csum_sub(csum, pseudohdr6_csum(in_ip6));
	csum = csum_add(csum, pseudohdr4_csum(out_ip4));
	return ~csum_fold(csum);
}

verdict ttp64_tcp(struct xlation *state)
{
	struct packet *in = &state->in;
	struct packet *out = &state->out;
	struct tcphdr *tcp_in = pkt_tcp_hdr(in);
	struct tcphdr *tcp_out = pkt_tcp_hdr(out);
	struct tcphdr tcp_copy;

	/* Header */
	memcpy(tcp_out, tcp_in, pkt_l4hdr_len(in));
	if (xlation_is_nat64(state)) {
		tcp_out->source = cpu_to_be16(out->tuple.src.addr4.l4);
		tcp_out->dest = cpu_to_be16(out->tuple.dst.addr4.l4);
	}

	/* Header.checksum */
	if (in->skb->ip_summed != CHECKSUM_PARTIAL) {
		memcpy(&tcp_copy, tcp_in, sizeof(*tcp_in));
		tcp_copy.check = 0;

		tcp_out->check = 0;
		tcp_out->check = update_csum_6to4(tcp_in->check,
				pkt_ip6_hdr(in), &tcp_copy, sizeof(tcp_copy),
				pkt_ip4_hdr(out), tcp_out, sizeof(*tcp_out));
		out->skb->ip_summed = CHECKSUM_NONE;
	} else {
		tcp_out->check = update_csum_6to4_partial(tcp_in->check,
				pkt_ip6_hdr(in), pkt_ip4_hdr(out));
		partialize_skb(out->skb, offsetof(struct tcphdr, check));
	}

	return VERDICT_CONTINUE;
}

verdict ttp64_udp(struct xlation *state)
{
	struct packet *in = &state->in;
	struct packet *out = &state->out;
	struct udphdr *udp_in = pkt_udp_hdr(in);
	struct udphdr *udp_out = pkt_udp_hdr(out);
	struct udphdr udp_copy;

	/* Header */
	memcpy(udp_out, udp_in, pkt_l4hdr_len(in));
	if (xlation_is_nat64(state)) {
		udp_out->source = cpu_to_be16(out->tuple.src.addr4.l4);
		udp_out->dest = cpu_to_be16(out->tuple.dst.addr4.l4);
	}

	/* Header.checksum */
	if (in->skb->ip_summed != CHECKSUM_PARTIAL) {
		memcpy(&udp_copy, udp_in, sizeof(*udp_in));
		udp_copy.check = 0;

		udp_out->check = 0;
		udp_out->check = update_csum_6to4(udp_in->check,
				pkt_ip6_hdr(in), &udp_copy, sizeof(udp_copy),
				pkt_ip4_hdr(out), udp_out, sizeof(*udp_out));
		if (udp_out->check == 0)
			udp_out->check = CSUM_MANGLED_0;
		out->skb->ip_summed = CHECKSUM_NONE;
	} else {
		udp_out->check = update_csum_6to4_partial(udp_in->check,
				pkt_ip6_hdr(in), pkt_ip4_hdr(out));
		partialize_skb(out->skb, offsetof(struct udphdr, check));
	}

	return VERDICT_CONTINUE;
}
