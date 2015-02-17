#include "nat64/mod/common/rfc6145/6to4.h"

#include <linux/ip.h>
#include <net/ipv6.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>

#include "nat64/mod/common/config.h"
#include "nat64/mod/common/icmp_wrapper.h"
#include "nat64/mod/common/ipv6_hdr_iterator.h"
#include "nat64/mod/common/rfc6052.h"
#include "nat64/mod/common/stats.h"
#include "nat64/mod/common/route.h"
#include "nat64/mod/stateless/pool4.h"
#include "nat64/mod/stateless/pool6.h"
#include "nat64/mod/stateless/eam.h"

verdict ttp64_create_skb(struct sk_buff *in, struct sk_buff **out)
{
	int total_len;
	struct sk_buff *new_skb;
	bool is_first;

	is_first = is_first_fragment_ipv6(hdr_iterator_find(ipv6_hdr(in), NEXTHDR_FRAGMENT));

	/*
	 * These are my assumptions to compute total_len:
	 *
	 * Any L3 headers will be replaced by an IPv4 header.
	 * The L4 header will never change in size (in particular, ICMPv4 hdr len == ICMPv6 hdr len).
	 * The payload will not change in TCP, UDP and ICMP infos.
	 *
	 * As for ICMP errors:
	 * Any sub-L3 headers will be replaced by an IPv4 header.
	 * The sub-L4 header will never change in size.
	 * The subpayload will never change in size (unless it gets truncated later, but that's send
	 * packet's responsibility).
	 */
	total_len = sizeof(struct iphdr) + skb_l3payload_len(in);
	if (is_first && skb_is_icmp6_error(in)) {
		struct hdr_iterator iterator = HDR_ITERATOR_INIT((struct ipv6hdr *) skb_payload(in));
		hdr_iterator_last(&iterator);

		/* Add the IPv4 subheader, remove the IPv6 subheaders. */
		total_len += sizeof(struct iphdr) - (iterator.data - skb_payload(in));

		/* RFC1812 section 4.3.2.3. I'm using a literal because the RFC does. */
		if (total_len > 576)
			total_len = 576;
	}

	new_skb = alloc_skb(LL_MAX_HEADER + total_len, GFP_ATOMIC);
	if (!new_skb) {
		inc_stats(in, IPSTATS_MIB_INDISCARDS);
		return VER_DROP;
	}

	skb_reserve(new_skb, LL_MAX_HEADER);
	skb_put(new_skb, total_len);
	skb_reset_mac_header(new_skb);
	skb_reset_network_header(new_skb);
	skb_set_transport_header(new_skb, sizeof(struct iphdr));

	/* if this is a subsequent fragment... */
	if (in->data == skb_payload(in))
		/* ->data has to point to the payload because kernel logic. */
		skb_pull(new_skb, sizeof(struct iphdr) + skb_l4hdr_len(in));

	skb_set_jcb(new_skb, L3PROTO_IPV4, skb_l4_proto(in), skb_is_fragment(in),
			skb_transport_header(new_skb) + skb_l4hdr_len(in),
			skb_original_skb(in));

	new_skb->mark = in->mark;
	new_skb->protocol = htons(ETH_P_IP);
	new_skb->next = NULL;
	new_skb->prev = NULL;

	*out = new_skb;
	return VER_CONTINUE;
}

/**
 * One-liner for creating the IPv4 header's Total Length field.
 */
static __be16 build_tot_len(struct sk_buff *in, struct sk_buff *out)
{
	/*
	 * The RFC's equation is plain wrong, as the errata claims.
	 * However, this still looks different than the proposed version because:
	 *
	 * - I don't know what all that ESP stuff is since ESP is not supposed to be translated.
	 *   TODO (warning) perhaps there's a new RFC that adds support for ESP?
	 * - ICMP error quirks the RFC doesn't account for:
	 *
	 * ICMPv6 errors are supposed to be max 1280 bytes.
	 * ICMPv4 errors are supposed to be max 576 bytes.
	 * Therefore, the resulting ICMP4 packet might have a smaller payload than the original packet.
	 *
	 * This is further complicated by the kernel's fragmentation hacks; we can't do
	 * "result = skb_len(out)" because the first fragment's tot_len has to also cover the rest of
	 * the fragments...
	 *
	 * SIGH.
	 */

	__u16 total_len;

	if (skb_is_inner(out)) { /* Inner packet. */
		total_len = get_tot_len_ipv6(in) - skb_hdrs_len(in) + skb_hdrs_len(out);

	} else if (!skb_is_fragment(out)) { /* Not fragment. */
		total_len = out->len;
		if (skb_is_icmp4_error(out) && total_len > 576)
			total_len = 576;

	} else if (skb_shinfo(out)->frag_list) { /* First fragment. */
		/* This would also normally be "result = out->len", but out->len is incomplete. */
		total_len = in->len - skb_hdrs_len(in) + skb_hdrs_len(out);

	} else { /* Subsequent fragment. */
		total_len = skb_hdrs_len(out) + out->len;

	}

	return cpu_to_be16(total_len);
}

/**
 * One-liner for creating the IPv4 header's Identification field.
 * It assumes that the packet will not contain a fragment header.
 */
static __be16 generate_ipv4_id_nofrag(struct sk_buff *skb_out)
{
	__be16 random;

	if (skb_len(skb_out) <= 1260) {
		get_random_bytes(&random, 2);
		return random;
	}

	return 0; /* Because the DF flag will be set. */
}

/**
 * One-liner for creating the IPv4 header's Dont Fragment flag.
 */
static bool generate_df_flag(struct sk_buff *skb_out)
{
	return skb_len(skb_out) > 1260;
}

/**
 * One-liner for creating the IPv4 header's Protocol field.
 */
static __u8 build_protocol_field(struct ipv6hdr *ip6_header)
{
	struct hdr_iterator iterator = HDR_ITERATOR_INIT(ip6_header);

	/* Skip stuff that does not exist in IPv4. */
	while (iterator.hdr_type == NEXTHDR_HOP
			|| iterator.hdr_type == NEXTHDR_ROUTING
			|| iterator.hdr_type == NEXTHDR_DEST)
		hdr_iterator_next(&iterator);

	if (iterator.hdr_type == NEXTHDR_ICMP)
		return IPPROTO_ICMP;
	if (iterator.hdr_type == NEXTHDR_FRAGMENT) {
		hdr_iterator_last(&iterator);
		return iterator.hdr_type;
	}

	return iterator.hdr_type;
}

static verdict generate_addr4_siit(struct in6_addr *addr6, __be32 *addr4, struct sk_buff *skb)
{
	struct ipv6_prefix prefix;
	struct in_addr tmp;
	int error;

	error = eamt_get_ipv4_by_ipv6(addr6, &tmp);
	if (error && error != -ESRCH)
		return VER_DROP;
	if (!error)
		goto end;

	error = pool6_get(addr6, &prefix);
	if (error) {
		log_debug("Looks like an IP address doesn't have a NAT64 prefix (errcode %d).", error);
		return VER_ACCEPT;
	}
	error = addr_6to4(addr6, &prefix, &tmp);
	if (error)
		return VER_DROP;
	/* Fall through. */

end:
	*addr4 = tmp.s_addr;
	return VER_CONTINUE;
}

static verdict translate_addrs_siit(struct sk_buff *in, struct sk_buff *out)
{
	struct ipv6hdr *ip6_hdr = ipv6_hdr(in);
	struct iphdr *ip4_hdr = ip_hdr(out);
	struct in_addr addr;
	verdict result;
	int error;

	/* Src address. */
	result = generate_addr4_siit(&ip6_hdr->saddr, &ip4_hdr->saddr, in);
	if (result == VER_ACCEPT && skb_is_icmp6_error(in)) {
		addr.s_addr = ip4_hdr->saddr;
		error = pool4_get(&addr); /* Why? RFC 6791. */
		if (error)
			return VER_DROP;
		ip4_hdr->saddr = addr.s_addr;
	} else if (result != VER_CONTINUE) {
		return result;
	}

	/* Dst address. */
	result = generate_addr4_siit(&ip6_hdr->daddr, &ip4_hdr->daddr, in);
	if (result != VER_CONTINUE)
		return result;

	log_debug("Result: %pI4->%pI4", &ip4_hdr->saddr, &ip4_hdr->daddr);
	return VER_CONTINUE;
}

/**
 * Returns "true" if ip6_hdr's first routing header contains a Segments Field which is not zero.
 *
 * @param ip6_hdr IPv6 header of the packet you want to test.
 * @param field_location (out parameter) if the header contains a routing header, the offset of the
 *		segments left field (from the start of ip6_hdr) will be stored here.
 * @return whether ip6_hdr's first routing header contains a Segments Field which is not zero.
 */
static bool has_nonzero_segments_left(struct ipv6hdr *ip6_hdr, __u32 *field_location)
{
	struct ipv6_rt_hdr *rt_hdr;
	__u32 rt_hdr_offset, segments_left_offset;

	rt_hdr = hdr_iterator_find(ip6_hdr, NEXTHDR_ROUTING);
	if (!rt_hdr)
		return false;

	rt_hdr_offset = ((void *) rt_hdr) - ((void *) ip6_hdr);
	segments_left_offset = offsetof(struct ipv6_rt_hdr, segments_left);
	*field_location = rt_hdr_offset + segments_left_offset;

	return (rt_hdr->segments_left != 0);
}

/**
 * One-liner for creating the IPv4 header's Identification field.
 * It assumes that the packet will contain a fragment header.
 */
static __be16 generate_ipv4_id_dofrag(struct frag_hdr *ipv6_frag_hdr)
{
	return cpu_to_be16(be32_to_cpu(ipv6_frag_hdr->identification));
}

/**
 * Translates in's ipv6 header into out's ipv4 header.
 * This is RFC 6145 sections 5.1 and 5.1.1.
 *
 * Aside from the main call (to translate a normal IPv6 packet's layer 3 header), this function can
 * also be called to translate a packet's inner packet.
 */
verdict ttp64_ipv4(struct tuple *tuple4, struct sk_buff *in, struct sk_buff *out)
{
	struct ipv6hdr *ip6_hdr = ipv6_hdr(in);
	struct frag_hdr *ip6_frag_hdr;
	struct iphdr *ip4_hdr;
	verdict result;

	bool reset_tos, build_ipv4_id, df_always_on;
	__u8 dont_fragment, new_tos;

	config_get_hdr4_config(&reset_tos, &new_tos, &build_ipv4_id, &df_always_on);

	ip4_hdr = ip_hdr(out);
	ip4_hdr->version = 4;
	ip4_hdr->ihl = 5;
	ip4_hdr->tos = reset_tos ? new_tos : get_traffic_class(ip6_hdr);
	ip4_hdr->tot_len = build_tot_len(in, out);
	ip4_hdr->id = build_ipv4_id ? generate_ipv4_id_nofrag(out) : 0;
	dont_fragment = df_always_on ? 1 : generate_df_flag(out);
	ip4_hdr->frag_off = build_ipv4_frag_off_field(dont_fragment, 0, 0);
	if (skb_is_outer(in)) {
		if (ip6_hdr->hop_limit <= 1) {
			icmp64_send(in, ICMPERR_HOP_LIMIT, 0);
			inc_stats(in, IPSTATS_MIB_INHDRERRORS);
			return VER_DROP;
		}
		ip4_hdr->ttl = ip6_hdr->hop_limit - 1;
	} else {
		ip4_hdr->ttl = ip6_hdr->hop_limit;
	}
	ip4_hdr->protocol = build_protocol_field(ip6_hdr);
	/* ip4_hdr->check is set later; please scroll down. */

	if (nat64_is_stateful()) {
		ip4_hdr->saddr = tuple4->src.addr4.l3.s_addr;
		ip4_hdr->daddr = tuple4->dst.addr4.l3.s_addr;
	} else {
		result = translate_addrs_siit(in, out);
		if (result != VER_CONTINUE)
			return result;
	}

	if (skb_is_outer(in)) {
		__u32 nonzero_location;
		if (has_nonzero_segments_left(ip6_hdr, &nonzero_location)) {
			log_debug("Packet's segments left field is nonzero.");
			icmp64_send(in, ICMPERR_HDR_FIELD, nonzero_location);
			inc_stats(in, IPSTATS_MIB_INHDRERRORS);
			return VER_DROP;
		}
	}

	ip6_frag_hdr = hdr_iterator_find(ip6_hdr, NEXTHDR_FRAGMENT);
	if (ip6_frag_hdr) {
		struct hdr_iterator iterator = HDR_ITERATOR_INIT(ip6_hdr);
		hdr_iterator_last(&iterator);

		/* The logic above already includes the frag header in tot_len. */
		ip4_hdr->id = generate_ipv4_id_dofrag(ip6_frag_hdr);
		ip4_hdr->frag_off = build_ipv4_frag_off_field(0,
				is_more_fragments_set_ipv6(ip6_frag_hdr),
				get_fragment_offset_ipv6(ip6_frag_hdr));

		/*
		 * This kinda contradicts the RFC.
		 * But following its logic, if the last extension header says ICMPv6 it wouldn't be switched
		 * to ICMPv4.
		 */
		ip4_hdr->protocol = (iterator.hdr_type == NEXTHDR_ICMP) ? IPPROTO_ICMP : iterator.hdr_type;
	}

	ip4_hdr->check = 0;
	ip4_hdr->check = ip_fast_csum(ip4_hdr, ip4_hdr->ihl);

	/*
	 * The kernel already drops packets if they don't allow fragmentation
	 * and the next hop MTU is smaller than their size.
	 */

	/* Adapt to kernel hacks. */
	if (skb_shinfo(in)->frag_list)
		ip4_hdr->frag_off &= cpu_to_be16(~IP_MF);

	return VER_CONTINUE;
}

/**
 * One liner for creating the ICMPv4 header's MTU field.
 * Returns the smallest out of the three parameters.
 */
static __be16 icmp4_minimum_mtu(__u32 packet_mtu, __u16 nexthop4_mtu, __u16 nexthop6_mtu)
{
	__u16 result;

	if (nexthop4_mtu < packet_mtu)
		result = (nexthop4_mtu < nexthop6_mtu) ? nexthop4_mtu : nexthop6_mtu;
	else
		result = (packet_mtu < nexthop6_mtu) ? packet_mtu : nexthop6_mtu;

	return cpu_to_be16(result);
}

static int compute_mtu4(struct sk_buff *in, struct sk_buff *out)
{
	struct icmphdr *out_icmp = icmp_hdr(out);
#ifndef UNIT_TESTING
	struct dst_entry *out_dst;
	struct icmp6hdr *in_icmp = icmp6_hdr(in);
	int error;

	error = route4(out);
	if (error)
		return error;

	log_debug("Packet MTU: %u", be32_to_cpu(in_icmp->icmp6_mtu));

	if (!in || !in->dev)
		return -EINVAL;
	log_debug("In dev MTU: %u", in->dev->mtu);

	out_dst = skb_dst(out);
	log_debug("Out dev MTU: %u", out_dst->dev->mtu);

	out_icmp->un.frag.mtu = icmp4_minimum_mtu(be32_to_cpu(in_icmp->icmp6_mtu) - 20,
			out_dst->dev->mtu,
			in->dev->mtu - 20);
	log_debug("Resulting MTU: %u", be16_to_cpu(out_icmp->un.frag.mtu));

#else
	out_icmp->un.frag.mtu = cpu_to_be16(1500);
#endif

	return 0;
}

/**
 * One liner for translating the ICMPv6's pointer field to ICMPv4.
 * "Pointer" is a field from "Parameter Problem" ICMP messages.
 */
static int icmp6_to_icmp4_param_prob_ptr(struct icmp6hdr *icmpv6_hdr,
		struct icmphdr *icmpv4_hdr)
{
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

	/* This is critical because the above ifs are supposed to cover all the possible values. */
	WARN(true, "Unknown pointer '%u' for parameter problem message.", icmp6_ptr);
	goto failure;

success:
	icmpv4_hdr->icmp4_unused = cpu_to_be32(icmp4_ptr << 24);
	return 0;
failure:
	log_debug("ICMP parameter problem pointer %u has no ICMP4 counterpart.", icmp6_ptr);
	return -EINVAL;
}

/**
 * One-liner for translating "Destination Unreachable" messages from ICMPv6 to ICMPv4.
 */
static int icmp6_to_icmp4_dest_unreach(struct icmp6hdr *icmpv6_hdr, struct icmphdr *icmpv4_hdr)
{
	icmpv4_hdr->type = ICMP_DEST_UNREACH;
	icmpv4_hdr->icmp4_unused = 0;

	switch (icmpv6_hdr->icmp6_code) {
	case ICMPV6_NOROUTE:
	case ICMPV6_NOT_NEIGHBOUR:
	case ICMPV6_ADDR_UNREACH:
		icmpv4_hdr->code = ICMP_HOST_UNREACH;
		break;

	case ICMPV6_ADM_PROHIBITED:
		icmpv4_hdr->code = ICMP_HOST_ANO;
		break;

	case ICMPV6_PORT_UNREACH:
		icmpv4_hdr->code = ICMP_PORT_UNREACH;
		break;

	default:
		log_debug("ICMPv6 messages type %u code %u do not exist in ICMPv4.",
				icmpv6_hdr->icmp6_type, icmpv6_hdr->icmp6_code);
		return -EINVAL;
	}

	return 0;
}

/**
 * One-liner for translating "Parameter Problem" messages from ICMPv6 to ICMPv4.
 */
static int icmp6_to_icmp4_param_prob(struct icmp6hdr *icmpv6_hdr, struct icmphdr *icmpv4_hdr)
{
	int error;

	switch (icmpv6_hdr->icmp6_code) {
	case ICMPV6_HDR_FIELD:
		icmpv4_hdr->type = ICMP_PARAMETERPROB;
		icmpv4_hdr->code = 0;
		error = icmp6_to_icmp4_param_prob_ptr(icmpv6_hdr, icmpv4_hdr);
		if (error)
			return error;
		break;

	case ICMPV6_UNK_NEXTHDR:
		icmpv4_hdr->type = ICMP_DEST_UNREACH;
		icmpv4_hdr->code = ICMP_PROT_UNREACH;
		icmpv4_hdr->icmp4_unused = 0;
		break;

	default:
		/* ICMPV6_UNK_OPTION is known to fall through here. */
		log_debug("ICMPv6 messages type %u code %u do not exist in ICMPv4.", icmpv6_hdr->icmp6_type,
				icmpv6_hdr->icmp6_code);
		return -EINVAL;
	}

	return 0;
}

/*
 * Use this when only the ICMP header changed, so all there is to do is subtract the old data from
 * the checksum and add the new one.
 */
static int update_icmp4_csum(struct sk_buff *in, struct sk_buff *out)
{
	struct ipv6hdr *in_ip6 = ipv6_hdr(in);
	struct icmp6hdr *in_icmp = icmp6_hdr(in);
	struct icmphdr *out_icmp = icmp_hdr(out);
	struct icmp6hdr copy_hdr;
	__wsum csum, tmp;

	csum = ~csum_unfold(in_icmp->icmp6_cksum);

	/* Remove the ICMPv6 pseudo-header. */
	tmp = ~csum_unfold(csum_ipv6_magic(&in_ip6->saddr, &in_ip6->daddr, skb_datagram_len(in),
			NEXTHDR_ICMP, 0));
	csum = csum_sub(csum, tmp);

	/*
	 * Remove the ICMPv6 header.
	 * I'm working on a copy because I need to zero out its checksum.
	 * If I did that directly on the skb, I'd need to make it writable first.
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
	return 0;
}

/**
 * Use this when header and payload both changed completely, so we gotta just trash the old
 * checksum and start anew.
 */
static int compute_icmp4_csum(struct sk_buff *out)
{
	struct icmphdr *hdr = icmp_hdr(out);

	/* This function only gets called for ICMP error checksums, so skb_datagram_len() is fine. */
	hdr->checksum = 0;
	hdr->checksum = csum_fold(skb_checksum(out, skb_transport_offset(out),
			skb_datagram_len(out), 0));

	return 0;
}

static int post_icmp4info(struct sk_buff *in, struct sk_buff *out)
{
	int error;

	error = copy_payload(in, out);
	if (error)
		return error;

	return update_icmp4_csum(in, out);
}

static verdict post_icmp4error(struct tuple *tuple4, struct sk_buff *in, struct sk_buff *out)
{
	verdict result;

	log_debug("Translating the inner packet (6->4)...");

	result = ttpcomm_translate_inner_packet(tuple4, in, out);
	if (result != VER_CONTINUE)
		return result;

	return compute_icmp4_csum(out) ? VER_DROP : VER_CONTINUE;
}

/**
 * Translates in's icmp6 header and payload into out's icmp4 header and payload.
 * This is the core of RFC 6145 sections 5.2 and 5.3, except checksum (See post_icmp4*()).
 */
verdict ttp64_icmp(struct tuple* tuple4, struct sk_buff *in, struct sk_buff *out)
{
	struct icmp6hdr *icmpv6_hdr = icmp6_hdr(in);
	struct icmphdr *icmpv4_hdr = icmp_hdr(out);
	int error = 0;

	icmpv4_hdr->checksum = icmpv6_hdr->icmp6_cksum; /* default. */

	switch (icmpv6_hdr->icmp6_type) {
	case ICMPV6_ECHO_REQUEST:
		icmpv4_hdr->type = ICMP_ECHO;
		icmpv4_hdr->code = 0;
		icmpv4_hdr->un.echo.id = nat64_is_stateful()
				? cpu_to_be16(tuple4->icmp4_id)
				: icmpv6_hdr->icmp6_identifier;
		icmpv4_hdr->un.echo.sequence = icmpv6_hdr->icmp6_dataun.u_echo.sequence;
		error = post_icmp4info(in, out);
		break;

	case ICMPV6_ECHO_REPLY:
		icmpv4_hdr->type = ICMP_ECHOREPLY;
		icmpv4_hdr->code = 0;
		icmpv4_hdr->un.echo.id = nat64_is_stateful()
				? cpu_to_be16(tuple4->icmp4_id)
				: icmpv6_hdr->icmp6_identifier;
		icmpv4_hdr->un.echo.sequence = icmpv6_hdr->icmp6_dataun.u_echo.sequence;
		error = post_icmp4info(in, out);
		break;

	case ICMPV6_DEST_UNREACH:
		error = icmp6_to_icmp4_dest_unreach(icmpv6_hdr, icmpv4_hdr);
		if (error) {
			inc_stats(in, IPSTATS_MIB_INHDRERRORS);
			return VER_DROP;
		}
		return post_icmp4error(tuple4, in, out);

	case ICMPV6_PKT_TOOBIG:
		/*
		 * BTW, I have no idea what the RFC means by "taking into account whether or not
		 * the packet in error includes a Fragment Header"... What does the fragment header
		 * have to do with anything here?
		 */
		icmpv4_hdr->type = ICMP_DEST_UNREACH;
		icmpv4_hdr->code = ICMP_FRAG_NEEDED;
		icmpv4_hdr->un.frag.__unused = htons(0);
		error = compute_mtu4(in, out);
		if (error)
			return VER_DROP;
		return post_icmp4error(tuple4, in, out);

	case ICMPV6_TIME_EXCEED:
		icmpv4_hdr->type = ICMP_TIME_EXCEEDED;
		icmpv4_hdr->code = icmpv6_hdr->icmp6_code;
		icmpv4_hdr->icmp4_unused = 0;
		return post_icmp4error(tuple4, in, out);

	case ICMPV6_PARAMPROB:
		error = icmp6_to_icmp4_param_prob(icmpv6_hdr, icmpv4_hdr);
		if (error) {
			inc_stats(in, IPSTATS_MIB_INHDRERRORS);
			return VER_DROP;
		}
		return post_icmp4error(tuple4, in, out);

	default:
		/*
		 * The following codes are known to fall through here:
		 * ICMPV6_MGM_QUERY, ICMPV6_MGM_REPORT, ICMPV6_MGM_REDUCTION,
		 * Neighbor Discover messages (133 - 137).
		 */
		log_debug("ICMPv6 messages type %u do not exist in ICMPv4.", icmpv6_hdr->icmp6_type);
		/*
		 * We return VER_ACCEPT instead of VER_DROP because the neighbor discovery code happens
		 * after Jool, apparently.
		 * This message, which is likely single-hop, might actually be intended for the kernel.
		 */
		return VER_ACCEPT;
	}

	return error ? VER_DROP : VER_CONTINUE;
}

static __sum16 update_csum_6to4(__sum16 csum16,
		struct ipv6hdr *in_ip6, void *in_l4_hdr, size_t in_l4_hdr_len,
		struct iphdr *out_ip4, void *out_l4_hdr, size_t out_l4_hdr_len)
{
	__wsum csum, pseudohdr_csum;

	csum = ~csum_unfold(csum16);

	/*
	 * Regarding the pseudoheaders:
	 * The length is pretty hard to obtain if there's fragmentation, and whatever it is,
	 * it's not going to change. Therefore, instead of computing it only to cancel it out with
	 * itself later, simply sum (and substract) zero.
	 * Do the same with proto since we're feeling hackish.
	 */

	/* Remove the IPv6 crap. */
	pseudohdr_csum = ~csum_unfold(csum_ipv6_magic(&in_ip6->saddr, &in_ip6->daddr, 0, 0, 0));
	csum = csum_sub(csum, pseudohdr_csum);
	csum = csum_sub(csum, csum_partial(in_l4_hdr, in_l4_hdr_len, 0));

	/* Add the IPv4 crap. */
	pseudohdr_csum = csum_tcpudp_nofold(out_ip4->saddr, out_ip4->daddr, 0, 0, 0);
	csum = csum_add(csum, pseudohdr_csum);
	csum = csum_add(csum, csum_partial(out_l4_hdr, out_l4_hdr_len, 0));

	return csum_fold(csum);
}

verdict ttp64_tcp(struct tuple *tuple4, struct sk_buff *in, struct sk_buff *out)
{
	struct tcphdr *tcp_in = tcp_hdr(in);
	struct tcphdr *tcp_out = tcp_hdr(out);
	struct tcphdr tcp_copy;

	/* Header */
	memcpy(tcp_out, tcp_in, skb_l4hdr_len(in));
	if (nat64_is_stateful()) {
		tcp_out->source = cpu_to_be16(tuple4->src.addr4.l4);
		tcp_out->dest = cpu_to_be16(tuple4->dst.addr4.l4);
	}

	memcpy(&tcp_copy, tcp_in, sizeof(*tcp_in));
	tcp_copy.check = 0;

	tcp_out->check = 0;
	tcp_out->check = update_csum_6to4(tcp_in->check,
			ipv6_hdr(in), &tcp_copy, sizeof(tcp_copy),
			ip_hdr(out), tcp_out, sizeof(*tcp_out));

	/* Payload */
	return copy_payload(in, out) ? VER_DROP : VER_CONTINUE;
}

verdict ttp64_udp(struct tuple *tuple4, struct sk_buff *in, struct sk_buff *out)
{
	struct udphdr *udp_in = udp_hdr(in);
	struct udphdr *udp_out = udp_hdr(out);
	struct udphdr udp_copy;

	/* Header */
	memcpy(udp_out, udp_in, skb_l4hdr_len(in));
	if (nat64_is_stateful()) {
		udp_out->source = cpu_to_be16(tuple4->src.addr4.l4);
		udp_out->dest = cpu_to_be16(tuple4->dst.addr4.l4);
	}

	memcpy(&udp_copy, udp_in, sizeof(*udp_in));
	udp_copy.check = 0;

	udp_out->check = 0;
	udp_out->check = update_csum_6to4(udp_in->check,
			ipv6_hdr(in), &udp_copy, sizeof(udp_copy),
			ip_hdr(out), udp_out, sizeof(*udp_out));
	if (udp_out->check == 0)
		udp_out->check = CSUM_MANGLED_0;

	/* Payload */
	return copy_payload(in, out) ? VER_DROP : VER_CONTINUE;
}
