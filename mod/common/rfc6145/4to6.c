#include "nat64/mod/common/rfc6145/4to6.h"

#include <linux/ip.h>
#include <net/ipv6.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>

#include "nat64/common/constants.h"
#include "nat64/mod/common/config.h"
#include "nat64/mod/common/icmp_wrapper.h"
#include "nat64/mod/common/rfc6052.h"
#include "nat64/mod/common/route.h"
#include "nat64/mod/common/stats.h"
#include "nat64/mod/stateless/pool6.h"
#include "nat64/mod/stateless/eam.h"

verdict ttp46_create_skb(struct sk_buff *in, struct sk_buff **out)
{
	int l3_hdr_len;
	int total_len;
	int reserve;
	struct sk_buff *new_skb;
	bool is_first;

	is_first = is_first_fragment_ipv4(ip_hdr(in));
	reserve = LL_MAX_HEADER;

	/*
	 * These are my assumptions to compute total_len:
	 *
	 * The IPv4 header will be replaced by a IPv6 header and possibly a fragment header.
	 * The L4 header will never change in size (in particular, ICMPv4 hdr len == ICMPv6 hdr len).
	 * The payload will not change in TCP, UDP and ICMP infos.
	 *
	 * As for ICMP errors:
	 * The IPv4 header will be replaced by a IPv6 header and possibly a fragment header.
	 * The sub-L4 header will never change in size.
	 * The subpayload will never change in size (unless it gets truncated later, but that's send
	 * packet's responsibility).
	 */
	l3_hdr_len = sizeof(struct ipv6hdr);
	if (will_need_frag_hdr(ip_hdr(in)))
		l3_hdr_len += sizeof(struct frag_hdr);
	else
		reserve += sizeof(struct frag_hdr);

	total_len = l3_hdr_len + skb_l3payload_len(in);
	if (is_first && skb_is_icmp4_error(in)) {
		total_len += sizeof(struct ipv6hdr) - sizeof(struct iphdr);
		if (will_need_frag_hdr(skb_payload(in)))
			total_len += sizeof(struct frag_hdr);

		/* All errors from RFC 4443 share this. */
		if (total_len > IPV6_MIN_MTU)
			total_len = IPV6_MIN_MTU;
	}

	new_skb = alloc_skb(reserve + total_len, GFP_ATOMIC);
	if (!new_skb) {
		inc_stats(in, IPSTATS_MIB_INDISCARDS);
		return VER_DROP;
	}

	skb_reserve(new_skb, reserve);
	skb_put(new_skb, total_len);
	skb_reset_mac_header(new_skb);
	skb_reset_network_header(new_skb);
	skb_set_transport_header(new_skb, l3_hdr_len);

	/* if this is a subsequent fragment... */
	if (in->data == skb_payload(in))
		/* ->data has to point to the payload because kernel logic. */
		skb_pull(new_skb, l3_hdr_len + skb_l4hdr_len(in));

	skb_set_jcb(new_skb, L3PROTO_IPV6, skb_l4_proto(in), skb_is_fragment(in),
			skb_transport_header(new_skb) + skb_l4hdr_len(in),
			skb_original_skb(in));

	new_skb->mark = in->mark;
	new_skb->protocol = htons(ETH_P_IPV6);
	new_skb->next = NULL;
	new_skb->prev = NULL;

	*out = new_skb;
	return VER_CONTINUE;
}

static __be16 build_payload_len(struct sk_buff *in, struct sk_buff *out)
{
	/* See build_tot_len() for relevant comments. */

	__u16 total_len;

	if (skb_is_inner(out)) { /* Inner packet. */
		total_len = be16_to_cpu(ip_hdr(in)->tot_len) - skb_hdrs_len(in) + skb_hdrs_len(out);

	} else if (!skb_is_fragment(out)) { /* Not fragment. */
		total_len = out->len;
		/*
		 * Though ICMPv4 errors are supposed to be max 576 bytes long, a good portion of the
		 * Internet seems prepared against bigger ICMPv4 errors.
		 * Thus, the resulting ICMPv6 packet might have a smaller payload than the original
		 * packet even though IPv4 MTU < IPv6 MTU.
		 */
		if (skb_is_icmp6_error(out) && total_len > IPV6_MIN_MTU)
			total_len = IPV6_MIN_MTU;

	} else if (skb_shinfo(out)->frag_list) { /* First fragment. */
		total_len = in->len - skb_hdrs_len(in) + skb_hdrs_len(out);

	} else { /* Subsequent fragment. */
		total_len = skb_hdrs_len(out) + out->len;

	}

	return cpu_to_be16(total_len - sizeof(struct ipv6hdr));
}

static int generate_addr6_siit(__be32 addr4, struct in6_addr *addr6)
{
	struct ipv6_prefix prefix;
	struct in_addr tmp;
	int error;

	tmp.s_addr = addr4;
	error = eamt_get_ipv6_by_ipv4(&tmp, addr6);
	if (error && error != -ESRCH)
		return error;
	if (!error)
		goto end;

	error = pool6_peek(&prefix);
	if (error)
		return error;
	error = addr_4to6(&tmp, &prefix, addr6);
	if (error)
		return error;

end:
	return 0;
}

/**
 * Returns "true" if "hdr" contains a source route option and the last address from it hasn't been
 * reached.
 *
 * Assumes the options are glued in memory after "hdr", the way sk_buffs work (when linearized or
 * pullable).
 */
static bool has_unexpired_src_route(struct iphdr *hdr)
{
	unsigned char *current_option, *end_of_options;
	__u8 src_route_length, src_route_pointer;

	/* Find a loose source route or a strict source route option. */
	current_option = (unsigned char *) (hdr + 1);
	end_of_options = ((unsigned char *) hdr) + (4 * hdr->ihl);
	if (current_option >= end_of_options)
		return false;

	while (current_option[0] != IPOPT_LSRR && current_option[0] != IPOPT_SSRR) {
		switch (current_option[0]) {
		case IPOPT_END:
			return false;
		case IPOPT_NOOP:
			current_option++;
			break;
		default:
			/*
			 * IPOPT_SEC, IPOPT_RR, IPOPT_SID, IPOPT_TIMESTAMP, IPOPT_CIPSO and IPOPT_RA
			 * are known to fall through here.
			 */
			current_option += current_option[1];
			break;
		}

		if (current_option >= end_of_options)
			return false;
	}

	/* Finally test. */
	src_route_length = current_option[1];
	src_route_pointer = current_option[2];
	return src_route_length >= src_route_pointer;
}

/**
 * One-liner for creating the Identification field of the IPv6 Fragment header.
 */
static inline __be32 build_id_field(struct iphdr *ip4_hdr)
{
	return cpu_to_be32(be16_to_cpu(ip4_hdr->id));
}

/**
 * Infers a IPv6 header from "in"'s IPv4 header and "tuple". Places the result in "out"->l3_hdr.
 * This is RFC 6145 section 4.1.
 *
 * Aside from the main call (to translate a normal IPv4 packet's layer 3 header), this function can
 * also be called to translate a packet's inner packet.
 */
verdict ttp46_ipv6(struct tuple *tuple6, struct sk_buff *in, struct sk_buff *out)
{
	struct iphdr *ip4_hdr = ip_hdr(in);
	struct ipv6hdr *ip6_hdr;
	int error;

	ip6_hdr = ipv6_hdr(out);
	ip6_hdr->version = 6;
	if (config_get_reset_traffic_class()) {
		ip6_hdr->priority = 0;
		ip6_hdr->flow_lbl[0] = 0;
	} else {
		ip6_hdr->priority = ip4_hdr->tos >> 4;
		ip6_hdr->flow_lbl[0] = ip4_hdr->tos << 4;
	}
	ip6_hdr->flow_lbl[1] = 0;
	ip6_hdr->flow_lbl[2] = 0;
	ip6_hdr->payload_len = build_payload_len(in, out);
	ip6_hdr->nexthdr = (ip4_hdr->protocol == IPPROTO_ICMP) ? NEXTHDR_ICMP : ip4_hdr->protocol;
	if (skb_is_outer(in)) {
		if (ip4_hdr->ttl <= 1) {
			icmp64_send(in, ICMPERR_HOP_LIMIT, 0);
			inc_stats(in, IPSTATS_MIB_INHDRERRORS);
			return VER_DROP;
		}
		ip6_hdr->hop_limit = ip4_hdr->ttl - 1;
	} else {
		ip6_hdr->hop_limit = ip4_hdr->ttl;
	}

	if (nat64_is_stateful()) {
		ip6_hdr->saddr = tuple6->src.addr6.l3;
		ip6_hdr->daddr = tuple6->dst.addr6.l3;
	} else {
		error = generate_addr6_siit(ip4_hdr->saddr, &ip6_hdr->saddr);
		if (error)
			return VER_DROP;
		error = generate_addr6_siit(ip4_hdr->daddr, &ip6_hdr->daddr);
		if (error)
			return VER_DROP;
		log_debug("Result: %pI6c->%pI6c", &ip6_hdr->saddr, &ip6_hdr->daddr);
	}

	/* Isn't this supposed to be covered by filtering...? */
	/*
	if (!is_address_legal(&ip6_hdr->saddr))
		return -EINVAL;
	*/

	if (skb_is_outer(in) && has_unexpired_src_route(ip4_hdr)) {
		log_debug("Packet has an unexpired source route.");
		icmp64_send(in, ICMPERR_SRC_ROUTE, 0);
		inc_stats(in, IPSTATS_MIB_INHDRERRORS);
		return VER_DROP;
	}

	if (will_need_frag_hdr(ip_hdr(in))) {
		struct frag_hdr *frag_header = (struct frag_hdr *) (ip6_hdr + 1);

		/* Override some fixed header fields... */
		ip6_hdr->nexthdr = NEXTHDR_FRAGMENT;

		/* ...and set the fragment header ones. */
		frag_header->nexthdr = (ip4_hdr->protocol == IPPROTO_ICMP)
				? NEXTHDR_ICMP
				: ip4_hdr->protocol;
		frag_header->reserved = 0;
		frag_header->frag_off = build_ipv6_frag_off_field(get_fragment_offset_ipv4(ip4_hdr),
				is_more_fragments_set_ipv4(ip4_hdr));
		frag_header->identification = build_id_field(ip4_hdr);
	}

	return VER_CONTINUE;
}

/**
 * One liner for creating the ICMPv6 header's MTU field.
 * Returns the smallest out of the three first parameters. It also handles some quirks. See comments
 * inside for more info.
 */
static __be32 icmp6_minimum_mtu(__u16 packet_mtu, __u16 nexthop6_mtu, __u16 nexthop4_mtu,
		__u16 tot_len_field)
{
	__u32 result;

	if (packet_mtu == 0) {
		/*
		 * Some router does not implement RFC 1191.
		 * Got to determine a likely path MTU.
		 * See RFC 1191 sections 5, 7 and 7.1 to understand the logic here.
		 */
		__u16 *plateaus;
		__u16 plateau_count;
		int plateau;

		rcu_read_lock_bh();
		config_get_mtu_plateaus(&plateaus, &plateau_count);

		for (plateau = 0; plateau < plateau_count; plateau++) {
			if (plateaus[plateau] < tot_len_field) {
				packet_mtu = plateaus[plateau];
				break;
			}
		}

		rcu_read_unlock_bh();
	}

	packet_mtu += 20;
	nexthop4_mtu += 20;

	/* Core comparison to find the minimum value. */
	if (nexthop6_mtu < packet_mtu)
		result = (nexthop6_mtu < nexthop4_mtu) ? nexthop6_mtu : nexthop4_mtu;
	else
		result = (packet_mtu < nexthop4_mtu) ? packet_mtu : nexthop4_mtu;

	if (config_get_lower_mtu_fail() && result < IPV6_MIN_MTU) {
		/*
		 * Probably some router does not implement RFC 4890, section 4.3.1.
		 * Gotta override and hope for the best.
		 * See RFC 6145 section 6, second approach, to understand the logic here.
		 */
		result = IPV6_MIN_MTU;
	}

	return cpu_to_be32(result);
}

static int compute_mtu6(struct sk_buff *in, struct sk_buff *out)
{
	struct icmp6hdr *out_icmp = icmp6_hdr(out);
#ifndef UNIT_TESTING
	struct dst_entry *out_dst;
	struct iphdr *hdr4;
	struct icmphdr *in_icmp = icmp_hdr(in);
	int error;

	error = route6(out);
	if (error)
		return error;

	log_debug("Packet MTU: %u", be16_to_cpu(in_icmp->un.frag.mtu));

	if (!in || !in->dev)
		return -EINVAL;
	log_debug("In dev MTU: %u", in->dev->mtu);

	out_dst = skb_dst(out);
	log_debug("Out dev MTU: %u", out_dst->dev->mtu);

	/* We want the length of the packet that couldn't get through, not the truncated one. */
	hdr4 = skb_payload(in);

	out_icmp->icmp6_mtu = icmp6_minimum_mtu(be16_to_cpu(in_icmp->un.frag.mtu),
			out_dst->dev->mtu,
			in->dev->mtu,
			be16_to_cpu(hdr4->tot_len));
	log_debug("Resulting MTU: %u", be32_to_cpu(out_icmp->icmp6_mtu));

#else
	out_icmp->icmp6_mtu = cpu_to_be32(1500);
#endif

	return 0;
}

/**
 * One-liner for translating "Destination Unreachable" messages from ICMPv4 to ICMPv6.
 */
static int icmp4_to_icmp6_dest_unreach(struct sk_buff *in, struct sk_buff *out)
{
	struct icmphdr *icmpv4_hdr = icmp_hdr(in);
	struct icmp6hdr *icmpv6_hdr = icmp6_hdr(out);
	int error;

	icmpv6_hdr->icmp6_type = ICMPV6_DEST_UNREACH;
	icmpv6_hdr->icmp6_unused = 0;

	switch (icmpv4_hdr->code) {
	case ICMP_NET_UNREACH:
	case ICMP_HOST_UNREACH:
	case ICMP_SR_FAILED:
	case ICMP_NET_UNKNOWN:
	case ICMP_HOST_UNKNOWN:
	case ICMP_HOST_ISOLATED:
	case ICMP_NET_UNR_TOS:
	case ICMP_HOST_UNR_TOS:
		icmpv6_hdr->icmp6_code = ICMPV6_NOROUTE;
		break;

	case ICMP_PROT_UNREACH:
		icmpv6_hdr->icmp6_type = ICMPV6_PARAMPROB;
		icmpv6_hdr->icmp6_code = ICMPV6_UNK_NEXTHDR;
		icmpv6_hdr->icmp6_pointer = cpu_to_be32(offsetof(struct ipv6hdr, nexthdr));
		break;

	case ICMP_PORT_UNREACH:
		icmpv6_hdr->icmp6_code = ICMPV6_PORT_UNREACH;
		break;

	case ICMP_FRAG_NEEDED:
		icmpv6_hdr->icmp6_type = ICMPV6_PKT_TOOBIG;
		icmpv6_hdr->icmp6_code = 0;
		error = compute_mtu6(in, out);
		if (error)
			return error;
		break;

	case ICMP_NET_ANO:
	case ICMP_HOST_ANO:
	case ICMP_PKT_FILTERED:
	case ICMP_PREC_CUTOFF:
		icmpv6_hdr->icmp6_code = ICMPV6_ADM_PROHIBITED;
		break;

	default: /* hostPrecedenceViolation (14) is known to fall through here. */
		log_debug("ICMPv4 messages type %u code %u do not exist in ICMPv6.",
				icmpv4_hdr->type, icmpv4_hdr->code);
		inc_stats(in, IPSTATS_MIB_INHDRERRORS);
		return -EINVAL; /* No ICMP error. */
	}

	return 0;
}

/**
 * One-liner for translating "Parameter Problem" messages from ICMPv4 to ICMPv6.
 */
static int icmp4_to_icmp6_param_prob(struct icmphdr *icmpv4_hdr, struct icmp6hdr *icmpv6_hdr)
{
	icmpv6_hdr->icmp6_type = ICMPV6_PARAMPROB;

	switch (icmpv4_hdr->code) {
	case ICMP_PTR_INDICATES_ERROR:
	case ICMP_BAD_LENGTH: {
		__u8 icmp4_pointer = be32_to_cpu(icmpv4_hdr->icmp4_unused) >> 24;
		const __u8 DROP = 255;
		__u8 pointers[] = { 0, 1, 4, 4,
				DROP, DROP, DROP, DROP,
				7, 6, DROP, DROP,
				8, 8, 8, 8,
				24, 24, 24, 24
		};

		if (icmp4_pointer < 0 || 19 < icmp4_pointer || pointers[icmp4_pointer] == DROP) {
			log_debug("ICMPv4 messages type %u code %u pointer %u do not exist in ICMPv6.",
					icmpv4_hdr->type, icmpv4_hdr->code, icmp4_pointer);
			return -EINVAL;
		}

		icmpv6_hdr->icmp6_code = ICMPV6_HDR_FIELD;
		icmpv6_hdr->icmp6_pointer = cpu_to_be32(pointers[icmp4_pointer]);
		break;
	}
	default: /* missingARequiredOption (1) is known to fall through here. */
		log_debug("ICMPv4 messages type %u code %u do not exist in ICMPv6.",
				icmpv4_hdr->type, icmpv4_hdr->code);
		return -EINVAL; /* No ICMP error. */
	}

	return 0;
}

static int update_icmp6_csum(struct sk_buff *in, struct sk_buff *out)
{
	struct ipv6hdr *out_ip6 = ipv6_hdr(out);
	struct icmphdr *in_icmp = icmp_hdr(in);
	struct icmp6hdr *out_icmp = icmp6_hdr(out);
	struct icmphdr copy_hdr;
	__wsum csum;

	out_icmp->icmp6_cksum = 0;

	csum = ~csum_unfold(in_icmp->checksum);

	memcpy(&copy_hdr, in_icmp, sizeof(*in_icmp));
	copy_hdr.checksum = 0;
	csum = csum_sub(csum, csum_partial(&copy_hdr, sizeof(copy_hdr), 0));

	csum = csum_add(csum, csum_partial(out_icmp, sizeof(*out_icmp), 0));

	out_icmp->icmp6_cksum = csum_ipv6_magic(&out_ip6->saddr, &out_ip6->daddr,
			skb_datagram_len(in), IPPROTO_ICMPV6, csum);

	return 0;
}

static int compute_icmp6_csum(struct sk_buff *out)
{
	struct ipv6hdr *out_ip6 = ipv6_hdr(out);
	struct icmp6hdr *out_icmp = icmp6_hdr(out);
	__wsum csum;

	/* This function only gets called for ICMP error checksums, so skb_datagram_len() is fine. */
	out_icmp->icmp6_cksum = 0;
	csum = skb_checksum(out, skb_transport_offset(out), skb_datagram_len(out), 0);
	out_icmp->icmp6_cksum = csum_ipv6_magic(&out_ip6->saddr, &out_ip6->daddr,
			skb_datagram_len(out), IPPROTO_ICMPV6, csum);

	return 0;
}

static int post_icmp6info(struct sk_buff *in, struct sk_buff *out)
{
	int error;

	error = copy_payload(in, out);
	if (error)
		return error;

	return update_icmp6_csum(in, out);
}

static verdict post_icmp6error(struct tuple *tuple6, struct sk_buff *in, struct sk_buff *out)
{
	verdict result;

	log_debug("Translating the inner packet (4->6)...");

	result = ttpcomm_translate_inner_packet(tuple6, in, out);
	if (result != VER_CONTINUE)
		return result;

	return compute_icmp6_csum(out) ? VER_DROP : VER_CONTINUE;
}

/**
 * Translates in's icmp4 header and payload into out's icmp6 header and payload.
 * This is the RFC 6145 sections 4.2 and 4.3, except checksum (See post_icmp6()).
 */
verdict ttp46_icmp(struct tuple* tuple6, struct sk_buff *in, struct sk_buff *out)
{
	struct icmphdr *icmpv4_hdr = icmp_hdr(in);
	struct icmp6hdr *icmpv6_hdr = icmp6_hdr(out);
	int error = 0;

	icmpv6_hdr->icmp6_cksum = icmpv4_hdr->checksum; /* default. */

	/* -- First the ICMP header. -- */
	switch (icmpv4_hdr->type) {
	case ICMP_ECHO:
		icmpv6_hdr->icmp6_type = ICMPV6_ECHO_REQUEST;
		icmpv6_hdr->icmp6_code = 0;
		icmpv6_hdr->icmp6_dataun.u_echo.identifier = nat64_is_stateful()
				? cpu_to_be16(tuple6->icmp6_id)
				: icmpv4_hdr->un.echo.id;
		icmpv6_hdr->icmp6_dataun.u_echo.sequence = icmpv4_hdr->un.echo.sequence;
		error = post_icmp6info(in, out);
		break;

	case ICMP_ECHOREPLY:
		icmpv6_hdr->icmp6_type = ICMPV6_ECHO_REPLY;
		icmpv6_hdr->icmp6_code = 0;
		icmpv6_hdr->icmp6_dataun.u_echo.identifier = nat64_is_stateful()
				? cpu_to_be16(tuple6->icmp6_id)
				: icmpv4_hdr->un.echo.id;
		icmpv6_hdr->icmp6_dataun.u_echo.sequence = icmpv4_hdr->un.echo.sequence;
		error = post_icmp6info(in, out);
		break;

	case ICMP_DEST_UNREACH:
		error = icmp4_to_icmp6_dest_unreach(in, out);
		if (error)
			return VER_DROP;
		return post_icmp6error(tuple6, in, out);

	case ICMP_TIME_EXCEEDED:
		icmpv6_hdr->icmp6_type = ICMPV6_TIME_EXCEED;
		icmpv6_hdr->icmp6_code = icmpv4_hdr->code;
		icmpv6_hdr->icmp6_unused = 0;
		return post_icmp6error(tuple6, in, out);

	case ICMP_PARAMETERPROB:
		error = icmp4_to_icmp6_param_prob(icmpv4_hdr, icmpv6_hdr);
		if (error) {
			inc_stats(in, IPSTATS_MIB_INHDRERRORS);
			return VER_DROP;
		}
		return post_icmp6error(tuple6, in, out);

	default:
		/*
		 * The following codes are known to fall through here:
		 * Information Request/Reply (15, 16), Timestamp and Timestamp Reply (13, 14),
		 * Address Mask Request/Reply (17, 18), Router Advertisement (9),
		 * Router Solicitation (10), Source Quench (4),
		 * Redirect (5), Alternative Host Address (6).
		 * This time there's no ICMP error.
		 */
		log_debug("ICMPv4 messages type %u do not exist in ICMPv6.", icmpv4_hdr->type);
		inc_stats(in, IPSTATS_MIB_INHDRERRORS);
		return VER_DROP;
	}

	return error ? VER_DROP : VER_CONTINUE;
}

static __sum16 update_csum_4to6(__sum16 csum16,
		struct iphdr *in_ip4, void *in_l4_hdr, size_t in_l4_hdr_len,
		struct ipv6hdr *out_ip6, void *out_l4_hdr, size_t out_l4_hdr_len)
{
	__wsum csum, pseudohdr_csum;

	/* See comments at update_csum_6to4(). */

	csum = ~csum_unfold(csum16);

	pseudohdr_csum = csum_tcpudp_nofold(in_ip4->saddr, in_ip4->daddr, 0, 0, 0);
	csum = csum_sub(csum, pseudohdr_csum);
	csum = csum_sub(csum, csum_partial(in_l4_hdr, in_l4_hdr_len, 0));

	pseudohdr_csum = ~csum_unfold(csum_ipv6_magic(&out_ip6->saddr, &out_ip6->daddr, 0, 0, 0));
	csum = csum_add(csum, pseudohdr_csum);
	csum = csum_add(csum, csum_partial(out_l4_hdr, out_l4_hdr_len, 0));

	return csum_fold(csum);
}

/**
 * Assumes that "out" is IPv6 and UDP, and computes and sets its l4-checksum.
 * This has to be done because the field is mandatory only in IPv6, so Jool has to make up for lazy
 * IPv4 nodes.
 * This is actually required in the Determine Incoming Tuple step, but it feels more at home here.
 */
static void handle_zero_csum(struct sk_buff *in, struct sk_buff *out)
{
	struct ipv6hdr *hdr6 = ipv6_hdr(out);
	struct udphdr *hdr_udp = udp_hdr(out);
	__wsum csum;

	/*
	 * Here's the deal:
	 * We want to compute out's checksum. **out is a packet whose fragment offset is zero**.
	 *
	 * Problem is, out's payload hasn't been translated yet. Because it can be scattered through
	 * several fragments, moving this step would make it look annoyingly out of place way later.
	 *
	 * Instead, we can exploit the fact that the translation does not affect the UDP payload,
	 * so here's what we will actually include in the checksum:
	 * - out's pseudoheader (this will actually be summed last).
	 * - out's UDP header.
	 * - in's payload.
	 *
	 * That's the reason why we needed in as an argument.
	 */

	csum = csum_partial(hdr_udp, sizeof(*hdr_udp), 0);
	csum = skb_checksum(in, skb_payload_offset(in), skb_payload_len_pkt(in), csum);
	hdr_udp->check = csum_ipv6_magic(&hdr6->saddr, &hdr6->daddr, skb_datagram_len(in),
			IPPROTO_UDP, csum);
}

verdict ttp46_tcp(struct tuple *tuple6, struct sk_buff *in, struct sk_buff *out)
{
	struct tcphdr *tcp_in = tcp_hdr(in);
	struct tcphdr *tcp_out = tcp_hdr(out);
	struct tcphdr tcp_copy;

	/* Header */
	memcpy(tcp_out, tcp_in, skb_l4hdr_len(in));
	if (nat64_is_stateful()) {
		tcp_out->source = cpu_to_be16(tuple6->src.addr6.l4);
		tcp_out->dest = cpu_to_be16(tuple6->dst.addr6.l4);
	}

	memcpy(&tcp_copy, tcp_in, sizeof(*tcp_in));
	tcp_copy.check = 0;

	tcp_out->check = 0;
	tcp_out->check = update_csum_4to6(tcp_in->check,
			ip_hdr(in), &tcp_copy, sizeof(tcp_copy),
			ipv6_hdr(out), tcp_out, sizeof(*tcp_out));

	/* Payload */
	return copy_payload(in, out) ? VER_DROP : VER_CONTINUE;
}

verdict ttp46_udp(struct tuple *tuple6, struct sk_buff *in, struct sk_buff *out)
{
	struct udphdr *udp_in = udp_hdr(in);
	struct udphdr *udp_out = udp_hdr(out);
	struct udphdr udp_copy;

	/* Header */
	memcpy(udp_out, udp_in, skb_l4hdr_len(in));
	if (nat64_is_stateful()) {
		udp_out->source = cpu_to_be16(tuple6->src.addr6.l4);
		udp_out->dest = cpu_to_be16(tuple6->dst.addr6.l4);
	}

	if (udp_in->check != 0) {
		memcpy(&udp_copy, udp_in, sizeof(*udp_in));
		udp_copy.check = 0;

		udp_out->check = 0;
		udp_out->check = update_csum_4to6(udp_in->check,
				ip_hdr(in), &udp_copy, sizeof(udp_copy),
				ipv6_hdr(out), udp_out, sizeof(*udp_out));
	} else {
		handle_zero_csum(in, out);
	}

	/* Payload */
	return copy_payload(in, out) ? VER_DROP : VER_CONTINUE;
}
