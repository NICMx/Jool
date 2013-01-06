/**
 * Assumes that "l3_hdr" points to a ipv6hdr, and returns its size, extension headers included.
 */
static __u16 compute_ipv6_hdr_len(void *l3_hdr)
{
	struct hdr_iterator iterator = HDR_ITERATOR_INIT((struct ipv6hdr *) l3_hdr);
	hdr_iterator_last(&iterator);
	return iterator.data - l3_hdr;
}

/**
 * Initializes "in" using the data from "tuple", "skb_in", and the assumption that we're translating
 * from 6 to 4.
 */
static bool init_packet_in_6to4(struct nf_conntrack_tuple *tuple, struct sk_buff *skb_in,
				struct packet_in *in)
{
	struct ipv6hdr *ip6_hdr = ipv6_hdr(skb_in);
	struct hdr_iterator iterator = HDR_ITERATOR_INIT(ip6_hdr);

	in->packet = skb_in;
	in->tuple = tuple;

	in->l3_hdr = ip6_hdr;
	in->l3_hdr_type = IPPROTO_IPV6;
	in->l3_hdr_len = skb_transport_header(skb_in) - skb_network_header(skb_in);
	in->l3_hdr_basic_len = sizeof(*ip6_hdr);
	in->compute_l3_hdr_len = compute_ipv6_hdr_len;

	hdr_iterator_last(&iterator);
	in->l4_hdr_type = iterator.hdr_type;
	switch (in->l4_hdr_type) {
	case NEXTHDR_TCP:
		in->l4_hdr_len = tcp_hdrlen(skb_in);
		break;
	case NEXTHDR_UDP:
		in->l4_hdr_len = sizeof(struct udphdr);
		break;
	case NEXTHDR_ICMP:
		in->l4_hdr_len = sizeof(struct icmp6hdr);
		break;
	default:
		log_warning("  Unsupported l4 protocol (%d). Cannot translate.", in->l4_hdr_type);
		return false;
	}

	in->payload = iterator.data + in->l4_hdr_len;
	in->payload_len = be16_to_cpu(ip6_hdr->payload_len) //
			- (in->l3_hdr_len - sizeof(*ip6_hdr)) //
			- in->l4_hdr_len;

	return true;
}

/*************************************************************************************************
 * -- Layer 3 --
 * (This is RFC 6145 sections 5.1 and 5.1.1. Translates IPv6 headers to IPv4.)
 *************************************************************************************************/

/**
 * One-liner for creating the IPv4 header's Type of Service field.
 */
static __u8 build_tos_field(struct ipv6hdr *ip6_hdr)
{
	__u8 upper_bits = ip6_hdr->priority;
	__u8 lower_bits = ip6_hdr->flow_lbl[0] >> 4;

	return (upper_bits << 4) | lower_bits;
}

/**
 * One-liner for creating the IPv4 header's Identification field.
 * It assumes that the packet will not contain a fragment header.
 */
static __be16 generate_ipv4_id_nofrag(struct ipv6hdr *ip6_header)
{
	__u16 packet_len, random;

	packet_len = sizeof(*ip6_header) + be16_to_cpu(ip6_header->payload_len);
	if (88 < packet_len && packet_len <= 1280) {
		get_random_bytes(&random, 2);
		return random;
	}

	return 0; // Because the DF flag will be set.
}

/**
 * One-liner for creating the IPv4 header's Dont Fragment flag.
 */
static __be16 generate_df_flag(struct ipv6hdr *ip6_header)
{
	__u16 packet_len = sizeof(*ip6_header) + be16_to_cpu(ip6_header->payload_len);
	return (88 < packet_len && packet_len <= 1280) ? 0 : 1;
}

/**
 * One-liner for creating the IPv4 header's Fragment Offset field.
 */
static __be16 build_ipv4_frag_off_field(__u16 dont_fragment, __u16 more_fragments,
		__u16 fragment_offset)
{
	__u16 result = (dont_fragment << 14)
			| (more_fragments << 13)
			| (fragment_offset << 0);

	return cpu_to_be16(result);
}

/**
 * One-liner for creating the IPv4 header's Protocol field.
 */
static __u8 build_protocol_field(struct ipv6hdr *ip6_header)
{
	struct hdr_iterator iterator = HDR_ITERATOR_INIT(ip6_header);

	// Skip stuff that does not exist in IPv4.
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

	rt_hdr = get_extension_header(ip6_hdr, NEXTHDR_ROUTING);
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
 * This is RFC 6145 sections 5.1 and 5.1.1, except lengths and checksum (See post_ipv4()).
 *
 * Aside from the main call (to translate a normal IPv6 packet's layer 3 header), this function can
 * also be called to translate a packet's inner packet, which severely constraints the information
 * from "in" it can use; see translate_inner_packet().
 */
static bool create_ipv4_hdr(struct packet_in *in, struct packet_out *out)
{
	__u8 dont_fragment;

	struct ipv6hdr *ip6_hdr = in->l3_hdr;
	struct frag_hdr *ip6_frag_hdr;
	struct iphdr *ip4_hdr;

	out->l3_hdr_type = IPPROTO_IP;
	out->l3_hdr_len = sizeof(struct iphdr);
	out->l3_hdr = kmalloc(out->l3_hdr_len, GFP_ATOMIC);
	if (!out->l3_hdr) {
		log_warning("  Allocation of the IPv4 header failed.");
		return false;
	}

	ip4_hdr = out->l3_hdr;
	ip4_hdr->version = 4;
	ip4_hdr->ihl = 5;
	ip4_hdr->tos = config.override_ipv4_traffic_class ? 0 : build_tos_field(ip6_hdr);
	// ip4_hdr->tot_len is set during post-processing.
	ip4_hdr->id = config.generate_ipv4_id ? generate_ipv4_id_nofrag(ip6_hdr) : 0;
	dont_fragment = config.df_always_set ? 1 : generate_df_flag(ip6_hdr);
	ip4_hdr->frag_off = build_ipv4_frag_off_field(dont_fragment, 0, 0);
	ip4_hdr->ttl = ip6_hdr->hop_limit; // The TTL is decremented by the kernel.
	ip4_hdr->protocol = build_protocol_field(ip6_hdr);
	// ip4_hdr->check is set during post-processing.
	ip4_hdr->saddr = in->tuple->ipv4_src_addr.s_addr;
	ip4_hdr->daddr = in->tuple->ipv4_dst_addr.s_addr;

	// if in->packet == NULL, we're translating a inner packet, so don't care.
	if (in->packet != NULL) {
		__u32 nonzero_location;
		if (has_nonzero_segments_left(ip6_hdr, &nonzero_location)) {
			log_debug("  Cannot translate: Packet's segments left field is nonzero.");
			icmpv6_send(in->packet, ICMPV6_PARAMPROB, ICMPV6_HDR_FIELD, nonzero_location);
			return false;
		}
	}

	ip6_frag_hdr = get_extension_header(ip6_hdr, NEXTHDR_FRAGMENT);
	if (ip6_frag_hdr) {
		__u16 ipv6_fragment_offset = be16_to_cpu(ip6_frag_hdr->frag_off) >> 3;
		__u16 ipv6_m = be16_to_cpu(ip6_frag_hdr->frag_off) & 0x1;

		struct hdr_iterator iterator = HDR_ITERATOR_INIT(ip6_hdr);
		hdr_iterator_last(&iterator);

		// ip4_hdr->tot_len is set during post-processing.
		ip4_hdr->id = generate_ipv4_id_dofrag(ip6_frag_hdr);
		ip4_hdr->frag_off = build_ipv4_frag_off_field(0, ipv6_m, ipv6_fragment_offset);
		ip4_hdr->protocol = (iterator.hdr_type == NEXTHDR_ICMP) ? IPPROTO_ICMP : iterator.hdr_type;
	}

	// The kernel already drops packets if they don't allow fragmentation
	// and the next hop MTU is smaller than their size.

	return true;
}

/**
 * Sets the Total Length and Checksum fields from out's IPv4 header.
 */
static bool post_ipv4(struct packet_out *out)
{
	struct iphdr *ip4_hdr = ip_hdr(out->packet);

	ip4_hdr->tot_len = cpu_to_be16(out->l3_hdr_len + out->l4_hdr_len + out->payload_len);
	ip4_hdr->check = 0;
	ip4_hdr->check = ip_fast_csum(ip4_hdr, ip4_hdr->ihl);

	return true;
}


/*************************************************************************************************
 * -- Layer 4 --
 * (Because UDP and TCP almost require no translation, you'll find that this is mostly RFC 6145
 * sections 5.2 and 5.3 (ICMP).)
 *************************************************************************************************/

/**
 * One liner for creating the ICMPv4 header's MTU field.
 * Returns the smallest out of the three parameters.
 */
static __be16 icmp4_minimum_mtu(__u32 packet_mtu, __u16 in_mtu, __u16 out_mtu)
{
	__u16 result;

	if (in_mtu < packet_mtu)
		result = (in_mtu < out_mtu) ? in_mtu : out_mtu;
	else
		result = (packet_mtu < out_mtu) ? packet_mtu : out_mtu;

	return cpu_to_be16(result);
}

/**
 * Returns "true" if "icmp6_type" is defined by RFC 4443 to contain a subpacket as payload.
 */
static bool icmpv6_has_inner_packet(__u8 icmp6_type)
{
	return (icmp6_type == ICMPV6_DEST_UNREACH) //
			|| (icmp6_type == ICMPV6_PKT_TOOBIG) //
			|| (icmp6_type == ICMPV6_TIME_EXCEED) //
			|| (icmp6_type == ICMPV6_PARAMPROB); //
}

/**
 * One liner for translating the ICMPv6's pointer field to ICMPv4.
 * "Pointer" is a field from "Parameter Problem" ICMP messages.
 */
static bool icmp6_to_icmp4_param_prob_ptr(struct icmp6hdr *icmpv6_hdr, struct icmphdr *icmpv4_hdr)
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

	log_crit("  Programming error: Unknown pointer '%u' for parameter problem message.", icmp6_ptr);
	goto failure;

success:
	icmpv4_hdr->icmp4_unused = cpu_to_be32(icmp4_ptr << 24);
	return true;
failure:
	log_info("  ICMP parameter problem pointer %u has no ICMP4 counterpart.", icmp6_ptr);
	return false;
}

/**
 * One-liner for translating "Destination Unreachable" messages from ICMPv6 to ICMPv4.
 */
static bool icmp6_to_icmp4_dest_unreach(struct icmp6hdr *icmpv6_hdr, struct icmphdr *icmpv4_hdr)
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
		log_info("  ICMPv6 messages type %u code %u do not exist in ICMPv4.",
				icmpv6_hdr->icmp6_type, icmpv6_hdr->icmp6_code);
		return false;
	}

	return true;
}

/**
 * One-liner for translating "Parameter Problem" messages from ICMPv6 to ICMPv4.
 */
static bool icmp6_to_icmp4_param_prob(struct icmp6hdr *icmpv6_hdr, struct icmphdr *icmpv4_hdr)
{
	switch (icmpv6_hdr->icmp6_code) {
	case ICMPV6_HDR_FIELD:
		icmpv4_hdr->type = ICMP_PARAMETERPROB;
		icmpv4_hdr->code = 0;
		if (!icmp6_to_icmp4_param_prob_ptr(icmpv6_hdr, icmpv4_hdr))
			return false;
		break;

	case ICMPV6_UNK_NEXTHDR:
		icmpv4_hdr->type = ICMP_DEST_UNREACH;
		icmpv4_hdr->code = ICMP_PROT_UNREACH;
		icmpv4_hdr->icmp4_unused = 0;
		break;

	default:
		// ICMPV6_UNK_OPTION is known to fall through here.
		log_info("  ICMPv6 messages type %u code %u do not exist in ICMPv4.",
				icmpv6_hdr->icmp6_type, icmpv6_hdr->icmp6_code);
		return false;
	}

	return true;
}

/**
 * Translates in's icmp6 header and payload into out's icmp4 header and payload.
 * This is the core of RFC 6145 sections 5.2 and 5.3, except checksum (See post_icmp4()).
 */
static bool create_icmp4_hdr_and_payload(struct packet_in *in, struct packet_out *out)
{
	struct icmp6hdr *icmpv6_hdr = icmp6_hdr(in->packet);
	struct icmphdr *icmpv4_hdr = kmalloc(sizeof(struct icmphdr), GFP_ATOMIC);
	if (!icmpv4_hdr) {
		log_warning("  Allocation of the ICMPv4 header failed.");
		return false;
	}

	out->l4_hdr_type = IPPROTO_ICMP;
	out->l4_hdr_len = sizeof(*icmpv4_hdr);
	out->l4_hdr = icmpv4_hdr;

	// -- First the ICMP header. --
	switch (icmpv6_hdr->icmp6_type) {
	case ICMPV6_ECHO_REQUEST:
		icmpv4_hdr->type = ICMP_ECHO;
		icmpv4_hdr->code = 0;
		icmpv4_hdr->un.echo.id = icmpv6_hdr->icmp6_dataun.u_echo.identifier;
		icmpv4_hdr->un.echo.sequence = icmpv6_hdr->icmp6_dataun.u_echo.sequence;
		break;

	case ICMPV6_ECHO_REPLY:
		icmpv4_hdr->type = ICMP_ECHOREPLY;
		icmpv4_hdr->code = 0;
		icmpv4_hdr->un.echo.id = icmpv6_hdr->icmp6_dataun.u_echo.identifier;
		icmpv4_hdr->un.echo.sequence = icmpv6_hdr->icmp6_dataun.u_echo.sequence;
		break;

	case ICMPV6_DEST_UNREACH:
		if (!icmp6_to_icmp4_dest_unreach(icmpv6_hdr, icmpv4_hdr))
			return false;
		break;

	case ICMPV6_PKT_TOOBIG:
		icmpv4_hdr->type = ICMP_DEST_UNREACH;
		icmpv4_hdr->code = ICMP_FRAG_NEEDED;
		icmpv4_hdr->un.frag.__unused = 0;
		// BTW, I have no idea what the RFC means by "taking into account whether or not
		// the packet in error includes a Fragment Header"... What does the fragment header
		// have to do with anything here?
		icmpv4_hdr->un.frag.mtu = icmp4_minimum_mtu(be32_to_cpu(icmpv6_hdr->icmp6_mtu) - 20, //
				config.ipv4_nexthop_mtu, //
				config.ipv6_nexthop_mtu - 20);
		break;

	case ICMPV6_TIME_EXCEED:
		icmpv4_hdr->type = ICMP_TIME_EXCEEDED;
		icmpv4_hdr->code = icmpv6_hdr->icmp6_code;
		icmpv4_hdr->icmp4_unused = 0;
		break;

	case ICMPV6_PARAMPROB:
		if (!icmp6_to_icmp4_param_prob(icmpv6_hdr, icmpv4_hdr))
			return false;
		break;

	default:
		// The following codes are known to fall through here:
		// ICMPV6_MGM_QUERY, ICMPV6_MGM_REPORT, ICMPV6_MGM_REDUCTION,
		// Neighbor Discover messages (133 - 137).
		log_info("  ICMPv6 messages type %u do not exist in ICMPv4.", icmpv6_hdr->icmp6_type);
		return false;
	}

	// -- Then the payload. --
	if (icmpv6_has_inner_packet(icmpv6_hdr->icmp6_type)) {
		if (!translate_inner_packet(in, out, create_ipv4_hdr))
			return false;
	} else {
		// The payload won't change, so don't bother re-creating it.
		out->payload = in->payload;
		out->payload_len = in->payload_len;
	}

	return true;
}

/**
 * Sets the Checksum field from out's ICMPv4 header.
 */
static bool post_icmp4(struct packet_out *out)
{
	struct icmphdr *icmp4_hdr = icmp_hdr(out->packet);

	icmp4_hdr->checksum = 0;
	icmp4_hdr->checksum = ip_compute_csum(icmp4_hdr, out->l4_hdr_len + out->payload_len);

	return true;
}

/**
 * Sets the Checksum field from out's TCP header.
 */
static bool post_tcp_ipv4(struct packet_out *out)
{
	struct iphdr *ip4_hdr = ip_hdr(out->packet);
	struct tcphdr *tcp_header = tcp_hdr(out->packet);
	__u16 datagram_len = out->l4_hdr_len + out->payload_len;

	tcp_header->check = 0;
	tcp_header->check = csum_tcpudp_magic(ip4_hdr->saddr, ip4_hdr->daddr, //
			datagram_len, IPPROTO_TCP, csum_partial(tcp_header, datagram_len, 0));

	return true;
}

/**
 * Sets the Length and Checksum fields from out's UDP header.
 */
static bool post_udp_ipv4(struct packet_out *out)
{
	struct iphdr *ip4_hdr = ip_hdr(out->packet);
	struct udphdr *udp_header = udp_hdr(out->packet);
	__u16 datagram_len = out->l4_hdr_len + out->payload_len;

	udp_header->len = cpu_to_be16(datagram_len);
	udp_header->check = 0;
	udp_header->check =  csum_tcpudp_magic(ip4_hdr->saddr, ip4_hdr->daddr, //
			datagram_len, IPPROTO_UDP, csum_partial(udp_header, datagram_len, 0));

	return true;
}
