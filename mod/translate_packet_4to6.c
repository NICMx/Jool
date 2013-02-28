/**
 * @file
 * Functions from Translate the Packet which specifically target the IPv4 -> IPv6 direction.
 * Would normally be part of translate_packet.c; the constant scrolling was killing me.
 */

/**
 * Assumes that "l3_hdr" points to a iphdr, and returns its size, options included.
 */
static __u16 compute_ipv4_hdr_len(void *l3_hdr)
{
	return 4 * ((struct iphdr *) l3_hdr)->ihl;
}

/**
 * Initializes "in" using the data from "tuple", "skb_in", and the assumption that we're translating
 * from 4 to 6.
 */
static bool init_packet_in_4to6(struct nf_conntrack_tuple *tuple, struct sk_buff *skb_in,
				struct packet_in *in)
{
	struct iphdr *ip4_hdr = ip_hdr(skb_in);

	in->packet = skb_in;
	in->tuple = tuple;

	in->l3_hdr = ip4_hdr;
	in->l3_hdr_type = PF_INET;
	in->l3_hdr_len = skb_transport_header(skb_in) - skb_network_header(skb_in);
	in->l3_hdr_basic_len = sizeof(*ip4_hdr);
	in->compute_l3_hdr_len = compute_ipv4_hdr_len;

	in->l4_hdr_type = ip4_hdr->protocol;
	switch (in->l4_hdr_type) {
	case IPPROTO_TCP:
		in->l4_hdr_len = tcp_hdrlen(skb_in);
		break;
	case IPPROTO_UDP:
		in->l4_hdr_len = sizeof(struct udphdr);
		break;
	case IPPROTO_ICMP:
		in->l4_hdr_len = sizeof(struct icmphdr);
		break;
	default:
		log_err(ERR_L4PROTO, "Unsupported transport protocol: %u.", in->l4_hdr_type);
		return false;
	}

	in->payload = skb_transport_header(skb_in) + in->l4_hdr_len;
	in->payload_len = be16_to_cpu(ip4_hdr->tot_len) - in->l3_hdr_len - in->l4_hdr_len;

	return true;
}

/*************************************************************************************************
 * -- Layer 3 --
 * (This is RFC 6145 section 4.1. Translates IPv4 headers to IPv6)
 *************************************************************************************************/

/**
 * Returns 1 if the Don't Fragments flag from the "header" header is set, 0 otherwise.
 */
static inline __u16 is_dont_fragment_set(struct iphdr *hdr)
{
	__u16 frag_off = be16_to_cpu(hdr->frag_off);
	return (frag_off & IP_DF) >> 14;
}

/**
 * Returns 1 if the More Fragments flag from the "header" header is set, 0 otherwise.
 */
static inline __u16 is_more_fragments_set(struct iphdr *hdr)
{
	__u16 frag_off = be16_to_cpu(hdr->frag_off);
	return (frag_off & IP_MF) >> 13;
}

/**
 * Returns "true" if "hdr" contains a source route option and the last address from it hasn't been
 * reached.
 *
 * Assumes the options are glued in memory after "hdr", the way sk_buffs work (when linearized).
 */
static bool has_unexpired_src_route(struct iphdr *hdr)
{
	unsigned char *current_option, *end_of_options;
	__u8 src_route_length, src_route_pointer;

	// Find a loose source route or a strict source route option.
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
			// IPOPT_SEC, IPOPT_RR, IPOPT_SID, IPOPT_TIMESTAMP, IPOPT_CIPSO and IPOPT_RA
			// are known to fall through here.
			current_option += current_option[1];
			break;
		}

		if (current_option >= end_of_options)
			return false;
	}

	// Finally test.
	src_route_length = current_option[1];
	src_route_pointer = current_option[2];
	return src_route_length >= src_route_pointer;
}

/**
 * One-liner for creating the { Fragment Offset, Res, M } field of the IPv6 Fragment header.
 */
static inline __be16 build_ipv6_frag_off_field(struct iphdr *ip4_hdr)
{
	__u16 fragment_offset = be16_to_cpu(ip4_hdr->frag_off) & IP_OFFSET;
	__u16 res = 0;
	__u16 m = is_more_fragments_set(ip4_hdr);

	return cpu_to_be16((fragment_offset << 3) | (res << 1) | m);
}

/**
 * One-liner for creating the Identification field of the IPv6 Fragment header.
 */
static inline __be32 build_id_field(struct iphdr *ip4_hdr)
{
	return cpu_to_be32(be16_to_cpu(ip4_hdr->id));
}

/**
 * Infers a IPv6 header from in's IPv4 header and tuple. Places the result in out->fixed_hdr.
 * This is RFC 6145 section 4.1, except Payload Length (See post_ipv6()).
 *
 * Aside from the main call (to translate a normal IPv4 packet's layer 3 header), this function can
 * also be called to translate a packet's inner packet, which severely constraints the information
 * from "in" it can use; see translate_inner_packet().
 */
static bool create_ipv6_hdr(struct packet_in *in, struct packet_out *out)
{
	struct iphdr *ip4_hdr = in->l3_hdr;
	struct ipv6hdr *ip6_hdr;
	bool reset_traffic_class;

	bool has_frag_hdr = !is_dont_fragment_set(ip4_hdr);

	out->l3_hdr_type = IPPROTO_IPV6;
	out->l3_hdr_len = sizeof(struct ipv6hdr) + (has_frag_hdr ? sizeof(struct frag_hdr) : 0);
	out->l3_hdr = kmalloc(out->l3_hdr_len, GFP_ATOMIC);
	if (!out->l3_hdr) {
		log_err(ERR_ALLOC_FAILED, "Allocation of the IPv6 header failed.");
		return false;
	}

	spin_lock_bh(&config_lock);
	reset_traffic_class = config.reset_traffic_class;
	spin_unlock_bh(&config_lock);

	ip6_hdr = out->l3_hdr;
	ip6_hdr->version = 6;
	if (reset_traffic_class) {
		ip6_hdr->priority = 0;
		ip6_hdr->flow_lbl[0] = 0;
	} else {
		ip6_hdr->priority = ip4_hdr->tos >> 4;
		ip6_hdr->flow_lbl[0] = ip4_hdr->tos << 4;
	}
	ip6_hdr->flow_lbl[1] = 0;
	ip6_hdr->flow_lbl[2] = 0;
	// ip6_hdr->payload_len is set during post-processing.
	ip6_hdr->nexthdr = (ip4_hdr->protocol == IPPROTO_ICMP) ? NEXTHDR_ICMP : ip4_hdr->protocol;
	ip6_hdr->hop_limit = ip4_hdr->ttl; // The TTL is decremented by the kernel.
	ip6_hdr->saddr = in->tuple->ipv6_src_addr;
	ip6_hdr->daddr = in->tuple->ipv6_dst_addr;

	// This is already covered by the kernel, by logging martians
	// (see the installation instructions).
	// if (!is_address_legal(&ip6_hdr->saddr)) {
	// // This time there's no ICMP error.
	// return false;
	// }

	if (has_unexpired_src_route(ip4_hdr) && in->packet != NULL) {
		log_info("Packet has an unexpired source route.");
		icmp_send(in->packet, ICMP_DEST_UNREACH, ICMP_SR_FAILED, 0);
		return false;
	}

	if (has_frag_hdr) {
		struct frag_hdr *frag_header = (struct frag_hdr *) (ip6_hdr + 1);

		// Override some fixed header fields...
		// ip6_hdr->payload_len is set during post-processing.
		ip6_hdr->nexthdr = NEXTHDR_FRAGMENT;

		// ...and set the fragment header ones.
		frag_header->nexthdr = (ip4_hdr->protocol == IPPROTO_ICMP)
				? NEXTHDR_ICMP
				: ip4_hdr->protocol;
		frag_header->reserved = 0;
		frag_header->frag_off = build_ipv6_frag_off_field(ip4_hdr);
		frag_header->identification = build_id_field(ip4_hdr);
	}

	return true;
}

/**
 * Sets the Payload Length field from out's IPv6 header.
 */
static bool post_ipv6(struct packet_out *out)
{
	struct ipv6hdr *ip6_hdr = ipv6_hdr(out->packet);
	__u16 l3_hdr_len = out->l3_hdr_len - sizeof(struct ipv6hdr);

	ip6_hdr->payload_len = cpu_to_be16(l3_hdr_len + out->l4_hdr_len + out->payload_len);

	return true;
}


/*************************************************************************************************
 * -- Layer 4 --
 * (Because UDP and TCP almost require no translation, you'll find that this is mostly RFC 6145
 * sections 4.2 and 4.3 (ICMP).)
 *************************************************************************************************/

/**
 * One liner for creating the ICMPv6 header's MTU field.
 * Returns the smallest out of the three first parameters. It also handles some quirks. See comments
 * inside for more info.
 */
static __be16 icmp6_minimum_mtu(__u16 packet_mtu, __u16 in_mtu, __u16 out_mtu, __u16 tot_len_field)
{
	__u16 result;

	if (packet_mtu == 0) {
		// Some router does not implement RFC 1191.
		// Got to determine a likely path MTU.
		// See RFC 1191 sections 5, 7 and 7.1 to understand the logic here.
		int plateau;
		spin_lock_bh(&config_lock);
		for (plateau = 0; plateau < config.mtu_plateau_count; plateau++) {
			if (config.mtu_plateaus[plateau] < tot_len_field) {
				packet_mtu = config.mtu_plateaus[plateau];
				break;
			}
		}
		spin_unlock_bh(&config_lock);
	}

	// Core comparison to find the minimum value.
	if (in_mtu < packet_mtu)
		result = (in_mtu < out_mtu) ? in_mtu : out_mtu;
	else
		result = (packet_mtu < out_mtu) ? packet_mtu : out_mtu;

	spin_lock_bh(&config_lock);
	if (config.lower_mtu_fail && result < 1280) {
		// Probably some router does not implement RFC 4890, section 4.3.1.
		// Gotta override and hope for the best.
		// See RFC 6145 section 6, second approach, to understand the logic here.
		result = 1280;
	}
	spin_unlock_bh(&config_lock);

	return cpu_to_be16(result);
}

/**
 * Returns "true" if "icmp_type" is defined by RFC 792 to contain a subpacket as payload.
 */
static bool icmp4_has_inner_packet(__u8 icmp_type)
{
	return (icmp_type == ICMP_DEST_UNREACH)
			|| (icmp_type == ICMP_TIME_EXCEEDED)
			|| (icmp_type == ICMP_PARAMETERPROB)
			|| (icmp_type == ICMP_SOURCE_QUENCH)
			|| (icmp_type == ICMP_REDIRECT);
}

/**
 * One-liner for translating "Destination Unreachable" messages from ICMPv4 to ICMPv6.
 */
static bool icmp4_to_icmp6_dest_unreach(struct icmphdr *icmpv4_hdr, struct icmp6hdr *icmpv6_hdr,
		__u16 tot_len_field)
{
	__u16 ipv6_mtu, ipv4_mtu;

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
		icmpv6_hdr->icmp6_pointer = offsetof(struct ipv6hdr, nexthdr);
		break;

	case ICMP_PORT_UNREACH:
		icmpv6_hdr->icmp6_code = ICMPV6_PORT_UNREACH;
		break;

	case ICMP_FRAG_NEEDED:
		spin_lock_bh(&config_lock);
		ipv6_mtu = config.ipv6_nexthop_mtu;
		ipv4_mtu = config.ipv4_nexthop_mtu;
		spin_unlock_bh(&config_lock);

		icmpv6_hdr->icmp6_type = ICMPV6_PKT_TOOBIG;
		icmpv6_hdr->icmp6_code = 0;
		icmpv6_hdr->icmp6_mtu = icmp6_minimum_mtu(be16_to_cpu(icmpv4_hdr->un.frag.mtu) + 20,
				ipv6_mtu,
				ipv4_mtu + 20,
				tot_len_field);
		break;

	case ICMP_NET_ANO:
	case ICMP_HOST_ANO:
	case ICMP_PKT_FILTERED:
	case ICMP_PREC_CUTOFF:
		icmpv6_hdr->icmp6_code = ICMPV6_ADM_PROHIBITED;
		break;

	default: // hostPrecedenceViolation (14) is known to fall through here.
		log_info("ICMPv4 messages type %u code %u do not exist in ICMPv6.", icmpv4_hdr->type,
				icmpv4_hdr->code);
		return false; // No ICMP error.
	}

	return true;
}

/**
 * One-liner for translating "Parameter Problem" messages from ICMPv4 to ICMPv6.
 */
static bool icmp4_to_icmp6_param_prob(struct icmphdr *icmpv4_hdr, struct icmp6hdr *icmpv6_hdr)
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
			log_info("ICMPv4 messages type %u code %u pointer %u do not exist in ICMPv6.",
					icmpv4_hdr->type, icmpv4_hdr->code, icmp4_pointer);
			return false;
		}

		icmpv6_hdr->icmp6_code = ICMPV6_HDR_FIELD;
		icmpv6_hdr->icmp6_pointer = cpu_to_be32(pointers[icmp4_pointer]);
		break;
	}
	default: // missingARequiredOption (1) is known to fall through here.
		log_info("ICMPv4 messages type %u code %u do not exist in ICMPv6.", icmpv4_hdr->type,
				icmpv4_hdr->code);
		return false; // No ICMP error.
	}

	return true;
}

/**
 * Translates in's icmp4 header and payload into out's icmp6 header and payload.
 * This is the RFC 6145 sections 4.2 and 4.3, except checksum (See post_icmp6()).
 */
static bool create_icmp6_hdr_and_payload(struct packet_in *in, struct packet_out *out)
{
	struct icmphdr *icmpv4_hdr = icmp_hdr(in->packet);
	struct icmp6hdr *icmpv6_hdr = kmalloc(sizeof(struct icmp6hdr), GFP_ATOMIC);
	if (!icmpv6_hdr) {
		log_err(ERR_ALLOC_FAILED, "Allocation of the ICMPv6 header failed.");
		return false;
	}

	out->l4_hdr_type = NEXTHDR_ICMP;
	out->l4_hdr_len = sizeof(*icmpv6_hdr);
	out->l4_hdr = icmpv6_hdr;

	// -- First the ICMP header. --
	switch (icmpv4_hdr->type) {
	case ICMP_ECHO:
		icmpv6_hdr->icmp6_type = ICMPV6_ECHO_REQUEST;
		icmpv6_hdr->icmp6_code = 0;
		icmpv6_hdr->icmp6_dataun.u_echo.identifier = in->tuple->icmp_id;
		icmpv6_hdr->icmp6_dataun.u_echo.sequence = icmpv4_hdr->un.echo.sequence;
		break;

	case ICMP_ECHOREPLY:
		icmpv6_hdr->icmp6_type = ICMPV6_ECHO_REPLY;
		icmpv6_hdr->icmp6_code = 0;
		icmpv6_hdr->icmp6_dataun.u_echo.identifier = in->tuple->icmp_id;
		icmpv6_hdr->icmp6_dataun.u_echo.sequence = icmpv4_hdr->un.echo.sequence;
		break;

	case ICMP_DEST_UNREACH: {
		__u16 tot_len = be16_to_cpu(ip_hdr(in->packet)->tot_len);
		if (!icmp4_to_icmp6_dest_unreach(icmpv4_hdr, icmpv6_hdr, tot_len))
			return false;
		break;
	}

	case ICMP_TIME_EXCEEDED:
		icmpv6_hdr->icmp6_type = ICMPV6_TIME_EXCEED;
		icmpv6_hdr->icmp6_code = icmpv4_hdr->code;
		icmpv6_hdr->icmp6_unused = 0;
		break;

	case ICMP_PARAMETERPROB:
		if (!icmp4_to_icmp6_param_prob(icmpv4_hdr, icmpv6_hdr))
			return false;
		break;

	default:
		// The following codes are known to fall through here:
		// Information Request/Reply (15, 16), Timestamp and Timestamp Reply (13, 14),
		// Address Mask Request/Reply (17, 18), Router Advertisement (9),
		// Router Solicitation (10), Source Quench (4),
		// Redirect (5), Alternative Host Address (6).
		// This time there's no ICMP error.
		log_info("ICMPv4 messages type %u do not exist in ICMPv6.", icmpv4_hdr->type);
		return false;
	}

	// -- Then the payload. --
	if (icmp4_has_inner_packet(icmpv4_hdr->type)) {
		if (!translate_inner_packet(in, out, create_ipv6_hdr))
			return false;
	} else {
		// The payload won't change, so don't bother re-creating it.
		out->payload = in->payload;
		out->payload_len = in->payload_len;
	}

	return true;
}

/**
 * Sets the Checksum field from out's ICMPv6 header.
 */
static bool post_icmp6(struct packet_in *in, struct packet_out *out)
{
	struct ipv6hdr *ip6_hdr = ipv6_hdr(out->packet);
	struct icmp6hdr *icmpv6_hdr = icmp6_hdr(out->packet);
	unsigned int datagram_len = out->l4_hdr_len + out->payload_len;

	icmpv6_hdr->icmp6_cksum = 0;
	icmpv6_hdr->icmp6_cksum = csum_ipv6_magic(&ip6_hdr->saddr, &ip6_hdr->daddr,
			datagram_len, IPPROTO_ICMPV6, csum_partial(icmpv6_hdr, datagram_len, 0));

	return true;
}

/**
 * Sets the Checksum field from out's TCP header.
 */
static bool post_tcp_ipv6(struct packet_in *in, struct packet_out *out)
{
	struct ipv6hdr *ip6_hdr = ipv6_hdr(out->packet);
	struct tcphdr *tcp_header = tcp_hdr(out->packet);
	__u16 datagram_len = out->l4_hdr_len + out->payload_len;

	tcp_header->source = in->tuple->src_port;
	tcp_header->dest = in->tuple->dst_port;
	tcp_header->check = 0;
	tcp_header->check = csum_ipv6_magic(&ip6_hdr->saddr, &ip6_hdr->daddr,
			datagram_len, IPPROTO_TCP, csum_partial(tcp_header, datagram_len, 0));

	return true;
}

/**
 * Sets the Length and Checksum fields from out's UDP header.
 */
static bool post_udp_ipv6(struct packet_in *in, struct packet_out *out)
{
	struct ipv6hdr *ip6_hdr = ipv6_hdr(out->packet);
	struct udphdr *udp_header = udp_hdr(out->packet);
	__u16 datagram_len = out->l4_hdr_len + out->payload_len;

	udp_header->source = in->tuple->src_port;
	udp_header->dest = in->tuple->dst_port;
	udp_header->len = cpu_to_be16(datagram_len);
	udp_header->check = 0;
	udp_header->check = csum_ipv6_magic(&ip6_hdr->saddr, &ip6_hdr->daddr,
			datagram_len, IPPROTO_UDP, csum_partial(udp_header, datagram_len, 0));

	return true;
}
