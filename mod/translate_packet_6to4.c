/**
 * @file
 * Functions from Translate the Packet which specifically target the IPv6 -> IPv4 direction.
 * Would normally be part of translate_packet.c; the constant scrolling was killing me.
 *
 * TODO read the erratas (6145 and 6146).
 */

/*************************************************************************************************
 * -- Layer 3 --
 * (This is RFC 6145 sections 5.1 and 5.1.1. Translates IPv6 headers to IPv4.)
 *************************************************************************************************/

/**
 * One-liner for creating the IPv4 header's Identification field.
 * It assumes that the packet will not contain a fragment header.
 */
static __be16 generate_ipv4_id_nofrag(struct ipv6hdr *ip6_header)
{
	__u16 packet_len;
	__be16 random;

	packet_len = sizeof(*ip6_header) + be16_to_cpu(ip6_header->payload_len);
	if (88 < packet_len && packet_len <= 1280) {
		get_random_bytes(&random, 2);
		return random;
	}

	return 0; /* Because the DF flag will be set. */
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
static verdict create_ipv4_hdr(struct tuple *tuple, struct fragment *in, struct fragment *out)
{
	struct ipv6hdr *ip6_hdr = frag_get_ipv6_hdr(in);
	struct frag_hdr *ip6_frag_hdr;
	struct iphdr *ip4_hdr;

	bool reset_tos, build_ipv4_id, df_always_on;
	__u8 dont_fragment;

	out->l3_hdr.proto = L3PROTO_IPV4;
	out->l3_hdr.len = sizeof(struct iphdr);
	out->l3_hdr.ptr_needs_kfree = true;
	out->l3_hdr.ptr = kmalloc(out->l3_hdr.len, GFP_ATOMIC);
	if (!out->l3_hdr.ptr) {
		log_err(ERR_ALLOC_FAILED, "Allocation of the IPv4 header failed.");
		return VER_DROP;
	}

	spin_lock_bh(&config_lock);
	reset_tos = config.reset_tos;
	build_ipv4_id = config.build_ipv4_id;
	df_always_on = config.df_always_on;
	spin_unlock_bh(&config_lock);

	ip4_hdr = frag_get_ipv4_hdr(out);
	ip4_hdr->version = 4;
	ip4_hdr->ihl = 5;
	ip4_hdr->tos = reset_tos ? 0 : get_traffic_class(ip6_hdr);
	/* ip4_hdr->tot_len is set during post-processing. */
	ip4_hdr->id = build_ipv4_id ? generate_ipv4_id_nofrag(ip6_hdr) : 0;
	dont_fragment = df_always_on ? 1 : generate_df_flag(ip6_hdr);
	ip4_hdr->frag_off = build_ipv4_frag_off_field(dont_fragment, 0, 0);
	ip4_hdr->ttl = ip6_hdr->hop_limit; /* The TTL is decremented by the kernel. */
	ip4_hdr->protocol = build_protocol_field(ip6_hdr);
	/* ip4_hdr->check is set during post-processing. */
	ip4_hdr->saddr = tuple->src.addr.ipv4.s_addr;
	ip4_hdr->daddr = tuple->dst.addr.ipv4.s_addr;

	/* if in->packet == NULL, we're translating a inner packet, so don't care. */
	if (in->skb != NULL) {
		__u32 nonzero_location;
		if (has_nonzero_segments_left(ip6_hdr, &nonzero_location)) {
			log_info("Packet's segments left field is nonzero.");
			icmpv6_send(in->skb, ICMPV6_PARAMPROB, ICMPV6_HDR_FIELD, nonzero_location);
			return VER_DROP;
		}
	}

	ip6_frag_hdr = get_extension_header(ip6_hdr, NEXTHDR_FRAGMENT);
	if (ip6_frag_hdr) {
		__u16 ipv6_fragment_offset = get_fragment_offset_ipv6(ip6_frag_hdr);
		__u16 ipv6_m = is_more_fragments_set_ipv6(ip6_frag_hdr);

		struct hdr_iterator iterator = HDR_ITERATOR_INIT(ip6_hdr);
		hdr_iterator_last(&iterator);

		/* ip4_hdr->tot_len is set during post-processing. */
		ip4_hdr->id = generate_ipv4_id_dofrag(ip6_frag_hdr);
		ip4_hdr->frag_off = build_ipv4_frag_off_field(0, ipv6_m, ipv6_fragment_offset);
		/*
		 * This kinda contradicts the RFC.
		 * But following its logic, if the last extension header says ICMPv6 it wouldn't be switched
		 * to ICMPv4.
		 */
		ip4_hdr->protocol = (iterator.hdr_type == NEXTHDR_ICMP) ? IPPROTO_ICMP : iterator.hdr_type;
	}

	/*
	 * The kernel already drops packets if they don't allow fragmentation
	 * and the next hop MTU is smaller than their size.
	 */

	return VER_CONTINUE;
}

/**
 * Sets the Total Length and Checksum fields from out's IPv4 header.
 */
static verdict post_ipv4(struct fragment *out)
{
	struct iphdr *ip4_hdr = frag_get_ipv4_hdr(out);

	ip4_hdr->tot_len = cpu_to_be16(out->l3_hdr.len + out->l4_hdr.len + out->payload.len);
	ip4_hdr->check = 0;
	ip4_hdr->check = ip_fast_csum(ip4_hdr, ip4_hdr->ihl);

	return VER_CONTINUE;
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
static __be16 icmp4_minimum_mtu(__u32 packet_mtu, __u16 nexthop4_mtu, __u16 nexthop6_mtu)
{
	__u16 result;

	if (nexthop4_mtu < packet_mtu)
		result = (nexthop4_mtu < nexthop6_mtu) ? nexthop4_mtu : nexthop6_mtu;
	else
		result = (packet_mtu < nexthop6_mtu) ? packet_mtu : nexthop6_mtu;

	return cpu_to_be16(result);
}

/**
 * Returns "true" if "icmp6_type" is defined by RFC 4443 to contain a subpacket as payload.
 */
static bool icmpv6_has_inner_packet(__u8 icmp6_type)
{
	return (icmp6_type == ICMPV6_DEST_UNREACH)
			|| (icmp6_type == ICMPV6_PKT_TOOBIG)
			|| (icmp6_type == ICMPV6_TIME_EXCEED)
			|| (icmp6_type == ICMPV6_PARAMPROB);
}

/**
 * One liner for translating the ICMPv6's pointer field to ICMPv4.
 * "Pointer" is a field from "Parameter Problem" ICMP messages.
 */
static verdict icmp6_to_icmp4_param_prob_ptr(struct icmp6hdr *icmpv6_hdr,
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

	log_crit(ERR_UNKNOWN_ERROR, "Unknown pointer '%u' for parameter problem message.", icmp6_ptr);
	goto failure;

success:
	icmpv4_hdr->icmp4_unused = cpu_to_be32(icmp4_ptr << 24);
	return VER_CONTINUE;
failure:
	log_info("ICMP parameter problem pointer %u has no ICMP4 counterpart.", icmp6_ptr);
	return VER_DROP;
}

/**
 * One-liner for translating "Destination Unreachable" messages from ICMPv6 to ICMPv4.
 */
static verdict icmp6_to_icmp4_dest_unreach(struct icmp6hdr *icmpv6_hdr,
		struct icmphdr *icmpv4_hdr)
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
		log_info("ICMPv6 messages type %u code %u do not exist in ICMPv4.",
				icmpv6_hdr->icmp6_type, icmpv6_hdr->icmp6_code);
		return VER_DROP;
	}

	return VER_CONTINUE;
}

/**
 * One-liner for translating "Parameter Problem" messages from ICMPv6 to ICMPv4.
 */
static verdict icmp6_to_icmp4_param_prob(struct icmp6hdr *icmpv6_hdr,
		struct icmphdr *icmpv4_hdr)
{
	verdict result;

	switch (icmpv6_hdr->icmp6_code) {
	case ICMPV6_HDR_FIELD:
		icmpv4_hdr->type = ICMP_PARAMETERPROB;
		icmpv4_hdr->code = 0;
		result = icmp6_to_icmp4_param_prob_ptr(icmpv6_hdr, icmpv4_hdr);
		if (result != VER_CONTINUE)
			return result;
		break;

	case ICMPV6_UNK_NEXTHDR:
		icmpv4_hdr->type = ICMP_DEST_UNREACH;
		icmpv4_hdr->code = ICMP_PROT_UNREACH;
		icmpv4_hdr->icmp4_unused = 0;
		break;

	default:
		/* ICMPV6_UNK_OPTION is known to fall through here. */
		log_info("ICMPv6 messages type %u code %u do not exist in ICMPv4.", icmpv6_hdr->icmp6_type,
				icmpv6_hdr->icmp6_code);
		return VER_DROP;
	}

	return VER_CONTINUE;
}

/**
 * Translates in's icmp6 header and payload into out's icmp4 header and payload.
 * This is the core of RFC 6145 sections 5.2 and 5.3, except checksum (See post_icmp4()).
 */
static verdict create_icmp4_hdr_and_payload(struct tuple* tuple, struct fragment *in,
		struct fragment *out)
{
	verdict result;
	struct icmp6hdr *icmpv6_hdr = frag_get_icmp6_hdr(in);
	struct icmphdr *icmpv4_hdr = kmalloc(sizeof(struct icmphdr), GFP_ATOMIC);
	if (!icmpv4_hdr) {
		log_err(ERR_ALLOC_FAILED, "Allocation of the ICMPv4 header failed.");
		return VER_DROP;
	}

	out->l4_hdr.proto = L4PROTO_ICMP;
	out->l4_hdr.len = sizeof(*icmpv4_hdr);
	out->l4_hdr.ptr = icmpv4_hdr;
	out->l4_hdr.ptr_needs_kfree = true;

	/* -- First the ICMP header. -- */
	switch (icmpv6_hdr->icmp6_type) {
	case ICMPV6_ECHO_REQUEST:
		icmpv4_hdr->type = ICMP_ECHO;
		icmpv4_hdr->code = 0;
		icmpv4_hdr->un.echo.id = cpu_to_be16(tuple->icmp_id);
		icmpv4_hdr->un.echo.sequence = icmpv6_hdr->icmp6_dataun.u_echo.sequence;
		break;

	case ICMPV6_ECHO_REPLY:
		icmpv4_hdr->type = ICMP_ECHOREPLY;
		icmpv4_hdr->code = 0;
		icmpv4_hdr->un.echo.id = cpu_to_be16(tuple->icmp_id);
		icmpv4_hdr->un.echo.sequence = icmpv6_hdr->icmp6_dataun.u_echo.sequence;
		break;

	case ICMPV6_DEST_UNREACH:
		result = icmp6_to_icmp4_dest_unreach(icmpv6_hdr, icmpv4_hdr);
		if (result != VER_CONTINUE)
			return result;
		break;

	case ICMPV6_PKT_TOOBIG:
		/*
		 * BTW, I have no idea what the RFC means by "taking into account whether or not
		 * the packet in error includes a Fragment Header"... What does the fragment header
		 * have to do with anything here?
		 */
		icmpv4_hdr->type = ICMP_DEST_UNREACH;
		icmpv4_hdr->code = ICMP_FRAG_NEEDED;
		icmpv4_hdr->un.frag.__unused = 0;

#ifndef UNIT_TESTING
		out->dst = route_ipv4(frag_get_ipv4_hdr(out), icmpv4_hdr, L4PROTO_ICMP, in->skb->mark);
		if (!out->dst)
			return VER_DROP;

		icmpv4_hdr->un.frag.mtu = icmp4_minimum_mtu(be32_to_cpu(icmpv6_hdr->icmp6_mtu) - 20,
				out->dst->dev->mtu,
				in->skb->dev->mtu - 20);
#else
		icmpv4_hdr->un.frag.mtu = 1500;
#endif
		break;

	case ICMPV6_TIME_EXCEED:
		icmpv4_hdr->type = ICMP_TIME_EXCEEDED;
		icmpv4_hdr->code = icmpv6_hdr->icmp6_code;
		icmpv4_hdr->icmp4_unused = 0;
		break;

	case ICMPV6_PARAMPROB:
		result = icmp6_to_icmp4_param_prob(icmpv6_hdr, icmpv4_hdr);
		if (result != VER_CONTINUE)
			return result;
		break;

	default:
		/*
		 * The following codes are known to fall through here:
		 * ICMPV6_MGM_QUERY, ICMPV6_MGM_REPORT, ICMPV6_MGM_REDUCTION,
		 * Neighbor Discover messages (133 - 137).
		 */
		log_info("ICMPv6 messages type %u do not exist in ICMPv4.", icmpv6_hdr->icmp6_type);
		return VER_DROP;
	}

	/* -- Then the payload. -- */
	if (icmpv6_has_inner_packet(icmpv6_hdr->icmp6_type)) {
		result = translate_inner_packet_6to4(tuple, in, out);
		if (result != VER_CONTINUE)
			return result;
	} else {
		/* The payload won't change, so don't bother re-creating it. */
		out->payload.len = in->payload.len;
		out->payload.ptr = in->payload.ptr;
		out->payload.ptr_needs_kfree = false;
	}

	return VER_CONTINUE;
}

/**
 * Sets the Checksum field from out's ICMPv4 header.
 */
static verdict post_icmp4(struct tuple *tuple, struct packet *pkt_in, struct packet *pkt_out)
{
	struct fragment *in = pkt_in->first_fragment;
	struct fragment *out = pkt_out->first_fragment;
	struct ipv6hdr *in_ip6 = frag_get_ipv6_hdr(in);
	struct icmp6hdr *in_icmp = frag_get_icmp6_hdr(in);
	struct icmphdr *out_icmp = frag_get_icmp4_hdr(out);

	if (is_icmp4_error(out_icmp->type)) {
		/*
		 * Header and payload both changed completely, so just trash the old checksum
		 * and start anew.
		 */
		out_icmp->checksum = 0;
		out_icmp->checksum = ip_compute_csum(out_icmp, out->l4_hdr.len + out->payload.len);
	} else {
		/*
		 * Only the ICMP header changed, so subtract the old data from the checksum
		 * and add the new one.
		 */
		__wsum csum;
		int i, len;
		verdict result;

		result = pkt_get_total_len_ipv6(pkt_in, &len);
		if (result != VER_CONTINUE)
			return result;

		csum = ~csum_unfold(in_icmp->icmp6_cksum);

		/* Remove the ICMPv6 pseudo-header */
		for (i = 0; i < 8; i++)
			csum = csum_sub(csum, in_ip6->saddr.s6_addr16[i]);
		for (i = 0; i < 8; i++)
			csum = csum_sub(csum, in_ip6->daddr.s6_addr16[i]);

		csum = csum_sub(csum, cpu_to_be16(len));
		csum = csum_sub(csum, cpu_to_be16(NEXTHDR_ICMP));

		/* Remove the ICMPv6 header */
		csum = csum_sub(csum, cpu_to_be16(in_icmp->icmp6_type << 8 | in_icmp->icmp6_code));
		csum = csum_sub(csum, in_icmp->icmp6_dataun.u_echo.identifier);
		csum = csum_sub(csum, in_icmp->icmp6_dataun.u_echo.sequence);

		/* There's no ICMPv4 pseudo-header. */

		/* Add the ICMPv4 header */
		csum = csum_add(csum, cpu_to_be16(out_icmp->type << 8 | out_icmp->code));
		csum = csum_add(csum, out_icmp->un.echo.id);
		csum = csum_add(csum, out_icmp->un.echo.sequence);

		out_icmp->checksum = csum_fold(csum);
	}

	return VER_CONTINUE;
}

static __sum16 update_csum_6to4(__sum16 csum16,
		struct ipv6hdr *in_ip6, __be16 in_src_port, __be16 in_dst_port,
		struct iphdr *out_ip4, __be16 out_src_port, __be16 out_dst_port)
{
	__wsum csum;
	int i;
	union {
		__be32 as32;
		__be16 as16[2];
	} addr4;

	csum = ~csum_unfold(csum16);

	/* Remove the IPv6 crap */
	for (i = 0; i < 8; i++)
		csum = csum_sub(csum, in_ip6->saddr.s6_addr16[i]);
	for (i = 0; i < 8; i++)
		csum = csum_sub(csum, in_ip6->daddr.s6_addr16[i]);
	csum = csum_sub(csum, in_src_port);
	csum = csum_sub(csum, in_dst_port);
	csum = csum_sub(csum, cpu_to_be16(in_ip6->nexthdr));

	/* Add the IPv4 crap */
	addr4.as32 = out_ip4->saddr;
	for (i = 0; i < 2; i++)
		csum = csum_add(csum, addr4.as16[i]);
	addr4.as32 = out_ip4->daddr;
	for (i = 0; i < 2; i++)
		csum = csum_add(csum, addr4.as16[i]);
	csum = csum_add(csum, out_src_port);
	csum = csum_add(csum, out_dst_port);
	csum = csum_add(csum, cpu_to_be16(out_ip4->protocol));

	return csum_fold(csum);
}

/**
 * Sets the Checksum field from out's TCP header.
 */
static verdict post_tcp_ipv4(struct tuple *tuple, struct packet *pkt_in, struct packet *pkt_out)
{
	struct ipv6hdr *in_ip6 = frag_get_ipv6_hdr(pkt_in->first_fragment);
	struct tcphdr *in_tcp = frag_get_tcp_hdr(pkt_in->first_fragment);
	struct iphdr *out_ip4 = frag_get_ipv4_hdr(pkt_out->first_fragment);
	struct tcphdr *out_tcp = frag_get_tcp_hdr(pkt_out->first_fragment);

	out_tcp->source = cpu_to_be16(tuple->src.l4_id);
	out_tcp->dest = cpu_to_be16(tuple->dst.l4_id);
	out_tcp->check = update_csum_6to4(in_tcp->check,
			in_ip6, in_tcp->source, in_tcp->dest,
			out_ip4, out_tcp->source, out_tcp->dest);

	return VER_CONTINUE;
}

/**
 * Sets the ports and checksum of out's UDP header.
 */
static verdict post_udp_ipv4(struct tuple *tuple, struct packet *pkt_in, struct packet *pkt_out)
{
	struct fragment *in = pkt_in->first_fragment;
	struct fragment *out = pkt_out->first_fragment;
	struct ipv6hdr *in_ip6 = frag_get_ipv6_hdr(in);
	struct udphdr *in_udp = frag_get_udp_hdr(in);
	struct iphdr *out_ip4 = frag_get_ipv4_hdr(out);
	struct udphdr *out_udp = frag_get_udp_hdr(out);

	out_udp->source = cpu_to_be16(tuple->src.l4_id);
	out_udp->dest = cpu_to_be16(tuple->dst.l4_id);
	out_udp->check = update_csum_6to4(in_udp->check,
			in_ip6, in_udp->source, in_udp->dest,
			out_ip4, out_udp->source, out_udp->dest);
	if (out_udp->check == 0)
		out_udp->check = 0xFFFF;

	return VER_CONTINUE;
}

/*************************************************************************************************
 * -- Inner packet --
 *************************************************************************************************/

static int l4_hdr_len(void *hdr, l3_protocol l3_proto, l4_protocol l4_proto)
{
	switch (l4_proto) {
	case L4PROTO_TCP:
		return 4 * ((struct tcphdr *) hdr)->doff;

	case L4PROTO_UDP:
		return sizeof(struct udphdr);

	case L4PROTO_ICMP:
		switch (l3_proto) {
		case L3PROTO_IPV6:
			return sizeof(struct icmp6hdr);
		case L3PROTO_IPV4:
			return sizeof(struct icmphdr);
		}
		return -1;
	case L4PROTO_NONE:
		return 0;
	}

	return -1;
}

verdict translate_inner_packet_6to4(struct tuple *tuple, struct fragment *in_outer,
		struct fragment *out_outer)
{
	struct packet dummy_pkt_in, dummy_pkt_out;
	struct fragment in_inner;
	struct fragment *out_inner;
	struct ipv6hdr *hdr6;
	struct hdr_iterator iterator;
	struct translation_steps *step;
	verdict result;
	enum hdr_iterator_result iterator_result;

	log_debug("Translating the inner packet (6->4)...");

	in_inner.skb = NULL;

	in_inner.l3_hdr.proto = L3PROTO_IPV6;
	in_inner.l3_hdr.ptr = in_outer->payload.ptr;
	in_inner.l3_hdr.ptr_needs_kfree = false;
	hdr6 = frag_get_ipv6_hdr(&in_inner);
	hdr_iterator_init(&iterator, hdr6);
	iterator_result = hdr_iterator_last(&iterator); /* TODO validar esto. */
	in_inner.l3_hdr.len = iterator.data - (void *) hdr6;

	in_inner.l4_hdr.proto = nexthdr_to_l4proto(iterator.hdr_type);
	if (in_inner.l4_hdr.proto == -1)
		return VER_DROP;
	in_inner.l4_hdr.ptr = iterator.data;
	in_inner.l4_hdr.ptr_needs_kfree = false;
	in_inner.l4_hdr.len = l4_hdr_len(in_inner.l4_hdr.ptr, in_inner.l3_hdr.proto, in_inner.l4_hdr.proto);

	if (in_inner.l4_hdr.proto == L4PROTO_ICMP) {
		struct icmp6hdr *hdr_icmp = frag_get_icmp6_hdr(&in_inner);
		if (icmpv6_has_inner_packet(hdr_icmp->icmp6_type))
			return VER_DROP; /* packet inside packet inside packet. */
	}

	/* TODO mandar a llamar a la función de validación. */

	in_inner.payload.ptr = in_inner.l4_hdr.ptr + in_inner.l4_hdr.len;
	in_inner.payload.ptr_needs_kfree = false;
	in_inner.payload.len = in_outer->payload.len - in_inner.l3_hdr.len - in_inner.l4_hdr.len;

	step = &steps[in_inner.l3_hdr.proto][in_inner.l4_hdr.proto];
	result = translate(tuple, &in_inner, &out_inner, step);
	if (result != VER_CONTINUE)
		return result;
	pkt_init(&dummy_pkt_in, &in_inner);
	pkt_init(&dummy_pkt_out, out_inner);
	result = step->l4_post_function(tuple, &dummy_pkt_in, &dummy_pkt_out);
	if (result != VER_CONTINUE) {
		frag_kfree(out_inner);
		return result;
	}

	out_outer->payload.len = out_inner->skb->len;
	out_outer->payload.ptr = kmalloc(out_outer->payload.len, GFP_ATOMIC);
	out_outer->payload.ptr_needs_kfree = true;
	if (!out_outer->payload.ptr) {
		frag_kfree(out_inner);
		return VER_DROP;
	}
	memcpy(out_outer->payload.ptr, skb_network_header(out_inner->skb), out_outer->payload.len);
	frag_kfree(out_inner);

	return VER_CONTINUE;
}
