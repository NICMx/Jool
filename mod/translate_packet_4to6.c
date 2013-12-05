/**
 * @file
 * Functions from Translate the Packet which specifically target the IPv4 -> IPv6 direction.
 * Would normally be part of translate_packet.c; the constant scrolling was killing me.
 */

/*************************************************************************************************
 * -- Layer 3 --
 * (This is RFC 6145 section 4.1. Translates IPv4 headers to IPv6)
 *************************************************************************************************/

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
 * This is RFC 6145 section 4.1, except Payload Length (See post_ipv6()).
 *
 * Aside from the main call (to translate a normal IPv4 packet's layer 3 header), this function can
 * also be called to translate a packet's inner packet, which severely constraints the information
 * from "in" it can use; see translate_inner_packet() and its callers.
 */
static verdict create_ipv6_hdr(struct tuple *tuple, struct fragment *in, struct fragment *out)
{
	struct iphdr *ip4_hdr = frag_get_ipv4_hdr(in);
	struct ipv6hdr *ip6_hdr;
	bool reset_traffic_class;

	bool has_frag_hdr = !is_dont_fragment_set(ip4_hdr);

	out->l3_hdr.proto = L3PROTO_IPV6;
	out->l3_hdr.len = sizeof(struct ipv6hdr) + (has_frag_hdr ? sizeof(struct frag_hdr) : 0);
	out->l3_hdr.ptr_needs_kfree = true;
	out->l3_hdr.ptr = kmalloc(out->l3_hdr.len, GFP_ATOMIC);
	if (!out->l3_hdr.ptr) {
		log_err(ERR_ALLOC_FAILED, "Allocation of the IPv6 header failed.");
		return VER_DROP;
	}

	spin_lock_bh(&config_lock);
	reset_traffic_class = config.reset_traffic_class;
	spin_unlock_bh(&config_lock);

	ip6_hdr = frag_get_ipv6_hdr(out);
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
	/* ip6_hdr->payload_len is set during post-processing. */
	ip6_hdr->nexthdr = (ip4_hdr->protocol == IPPROTO_ICMP) ? NEXTHDR_ICMP : ip4_hdr->protocol;
	/* The TTL is decremented by the kernel. TODO (warning) please confirm this. */
	ip6_hdr->hop_limit = ip4_hdr->ttl;
	ip6_hdr->saddr = tuple->src.addr.ipv6;
	ip6_hdr->daddr = tuple->dst.addr.ipv6;

	/*
	 * This is already covered by the kernel, by logging martians
	 * (see the installation instructions).
	 */
	/*
	if (!is_address_legal(&ip6_hdr->saddr))
		return false;
	*/

	if (has_unexpired_src_route(ip4_hdr) && in->skb != NULL) {
		log_info("Packet has an unexpired source route.");
		icmp_send(in->skb, ICMP_DEST_UNREACH, ICMP_SR_FAILED, 0);
		return VER_DROP;
	}

	if (has_frag_hdr) {
		struct frag_hdr *frag_header = (struct frag_hdr *) (ip6_hdr + 1);

		/*
		 * Override some fixed header fields...
		 * ip6_hdr->payload_len is set during post-processing.
		 */
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
 * Sets the Payload Length field from out's IPv6 header.
 */
static verdict post_ipv6(struct fragment *out)
{
	struct ipv6hdr *ip6_hdr = frag_get_ipv6_hdr(out);
	__u16 l3_hdr_len = out->l3_hdr.len - sizeof(struct ipv6hdr);

	ip6_hdr->payload_len = cpu_to_be16(l3_hdr_len + out->l4_hdr.len + out->payload.len);

	return VER_CONTINUE;
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

	/* Core comparison to find the minimum value. */
	if (nexthop6_mtu < packet_mtu)
		result = (nexthop6_mtu < nexthop4_mtu) ? nexthop6_mtu : nexthop4_mtu;
	else
		result = (packet_mtu < nexthop4_mtu) ? packet_mtu : nexthop4_mtu;

	spin_lock_bh(&config_lock);
	if (config.lower_mtu_fail && result < 1280) {
		/*
		 * Probably some router does not implement RFC 4890, section 4.3.1.
		 * Gotta override and hope for the best.
		 * See RFC 6145 section 6, second approach, to understand the logic here.
		 */
		result = 1280;
	}
	spin_unlock_bh(&config_lock);

	return cpu_to_be32(result);
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
static verdict icmp4_to_icmp6_dest_unreach(struct fragment *in, struct fragment *out,
		__u16 tot_len_field)
{
	struct icmphdr *icmpv4_hdr = frag_get_icmp4_hdr(in);
	struct icmp6hdr *icmpv6_hdr = frag_get_icmp6_hdr(out);

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
		icmpv6_hdr->icmp6_type = ICMPV6_PKT_TOOBIG;
		icmpv6_hdr->icmp6_code = 0;

#ifndef UNIT_TESTING
		out->dst = route_ipv6(frag_get_ipv6_hdr(out), icmpv6_hdr, L4PROTO_ICMP, in->skb->mark);
		if (!out->dst)
			return VER_DROP;

		icmpv6_hdr->icmp6_mtu = icmp6_minimum_mtu(be16_to_cpu(icmpv4_hdr->un.frag.mtu) + 20,
				out->dst->dev->mtu,
				in->skb->dev->mtu + 20,
				tot_len_field);

#else
		icmpv6_hdr->icmp6_mtu = 1500;
#endif
		break;

	case ICMP_NET_ANO:
	case ICMP_HOST_ANO:
	case ICMP_PKT_FILTERED:
	case ICMP_PREC_CUTOFF:
		icmpv6_hdr->icmp6_code = ICMPV6_ADM_PROHIBITED;
		break;

	default: /* hostPrecedenceViolation (14) is known to fall through here. */
		log_info("ICMPv4 messages type %u code %u do not exist in ICMPv6.", icmpv4_hdr->type,
				icmpv4_hdr->code);
		return VER_DROP; /* No ICMP error. */
	}

	return VER_CONTINUE;
}

/**
 * One-liner for translating "Parameter Problem" messages from ICMPv4 to ICMPv6.
 */
static verdict icmp4_to_icmp6_param_prob(struct icmphdr *icmpv4_hdr, struct icmp6hdr *icmpv6_hdr)
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
			return VER_DROP;
		}

		icmpv6_hdr->icmp6_code = ICMPV6_HDR_FIELD;
		icmpv6_hdr->icmp6_pointer = cpu_to_be32(pointers[icmp4_pointer]);
		break;
	}
	default: /* missingARequiredOption (1) is known to fall through here. */
		log_info("ICMPv4 messages type %u code %u do not exist in ICMPv6.", icmpv4_hdr->type,
				icmpv4_hdr->code);
		return VER_DROP; /* No ICMP error. */
	}

	return VER_CONTINUE;
}

/**
 * Sets out_outer.payload.*.
 */
static verdict translate_inner_packet_4to6(struct tuple *tuple, struct fragment *in_outer,
		struct fragment *out_outer)
{
	struct fragment *in_inner = NULL;
	verdict result = VER_DROP;

	log_debug("Translating the inner packet (4->6)...");

	/* Prepare the translate function's requirements. */
	if (is_error(frag_create_from_buffer_ipv4(in_outer->payload.ptr, in_outer->payload.len, true,
			&in_inner, NULL)))
		goto end;

	if (in_inner->l4_hdr.proto == L4PROTO_ICMP) {
		struct icmphdr *hdr_icmp = frag_get_icmp4_hdr(in_inner);
		if (icmp4_has_inner_packet(hdr_icmp->type))
			goto end; /* packet inside packet inside packet. */
	}

	result = translate_inner_packet(tuple, in_inner, out_outer);

end:
	frag_kfree(in_inner);
	return result;
}

/**
 * Translates in's icmp4 header and payload into out's icmp6 header and payload.
 * This is the RFC 6145 sections 4.2 and 4.3, except checksum (See post_icmp6()).
 */
static verdict create_icmp6_hdr_and_payload(struct tuple* tuple, struct fragment *in,
		struct fragment *out)
{
	verdict result;
	struct icmphdr *icmpv4_hdr;
	struct icmp6hdr *icmpv6_hdr;

	icmpv4_hdr = frag_get_icmp4_hdr(in);
	icmpv6_hdr = kmalloc(sizeof(struct icmp6hdr), GFP_ATOMIC);
	if (!icmpv6_hdr) {
		log_err(ERR_ALLOC_FAILED, "Allocation of the ICMPv6 header failed.");
		return VER_DROP;
	}

	out->l4_hdr.proto = L4PROTO_ICMP;
	out->l4_hdr.len = sizeof(*icmpv6_hdr);
	out->l4_hdr.ptr = icmpv6_hdr;
	out->l4_hdr.ptr_needs_kfree = true;

	/* -- First the ICMP header. -- */
	switch (icmpv4_hdr->type) {
	case ICMP_ECHO:
		icmpv6_hdr->icmp6_type = ICMPV6_ECHO_REQUEST;
		icmpv6_hdr->icmp6_code = 0;
		icmpv6_hdr->icmp6_dataun.u_echo.identifier = cpu_to_be16(tuple->icmp_id);
		icmpv6_hdr->icmp6_dataun.u_echo.sequence = icmpv4_hdr->un.echo.sequence;
		break;

	case ICMP_ECHOREPLY:
		icmpv6_hdr->icmp6_type = ICMPV6_ECHO_REPLY;
		icmpv6_hdr->icmp6_code = 0;
		icmpv6_hdr->icmp6_dataun.u_echo.identifier = cpu_to_be16(tuple->icmp_id);
		icmpv6_hdr->icmp6_dataun.u_echo.sequence = icmpv4_hdr->un.echo.sequence;
		break;

	case ICMP_DEST_UNREACH: {
		__u16 tot_len = be16_to_cpu(ip_hdr(in->skb)->tot_len);
		result = icmp4_to_icmp6_dest_unreach(in, out, tot_len);

		if (result != VER_CONTINUE)
			return result;
		break;
	}

	case ICMP_TIME_EXCEEDED:
		icmpv6_hdr->icmp6_type = ICMPV6_TIME_EXCEED;
		icmpv6_hdr->icmp6_code = icmpv4_hdr->code;
		icmpv6_hdr->icmp6_unused = 0;
		break;

	case ICMP_PARAMETERPROB:
		result = icmp4_to_icmp6_param_prob(icmpv4_hdr, icmpv6_hdr);
		if (result != VER_CONTINUE)
			return result;
		break;

	default:
		/*
		 * The following codes are known to fall through here:
		 * Information Request/Reply (15, 16), Timestamp and Timestamp Reply (13, 14),
		 * Address Mask Request/Reply (17, 18), Router Advertisement (9),
		 * Router Solicitation (10), Source Quench (4),
		 * Redirect (5), Alternative Host Address (6).
		 * This time there's no ICMP error.
		 */
		log_info("ICMPv4 messages type %u do not exist in ICMPv6.", icmpv4_hdr->type);
		return VER_DROP;
	}

	/* -- Then the payload. -- */
	if (icmp4_has_inner_packet(icmpv4_hdr->type)) {
		result = translate_inner_packet_4to6(tuple, in, out);
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
 * Sets the Checksum field from out's ICMPv6 header.
 */
static verdict post_icmp6(struct tuple *tuple, struct packet *pkt_in, struct packet *pkt_out)
{
	struct fragment *in = pkt_in->first_fragment;
	struct fragment *out = pkt_out->first_fragment;
	struct ipv6hdr *out_ip6 = frag_get_ipv6_hdr(out);
	struct icmphdr *in_icmp = frag_get_icmp4_hdr(in);
	struct icmp6hdr *out_icmp = frag_get_icmp6_hdr(out);

	if (is_icmp6_error(out_icmp->icmp6_type)) {
		/*
		 * Header and payload both changed completely, so just trash the old checksum
		 * and start anew.
		 */
		unsigned int datagram_len = out->l4_hdr.len + out->payload.len;
		out_icmp->icmp6_cksum = 0;
		out_icmp->icmp6_cksum = csum_ipv6_magic(&out_ip6->saddr, &out_ip6->daddr,
				datagram_len, IPPROTO_ICMPV6, csum_partial(out_icmp, datagram_len, 0));
	} else {
		/*
		 * Only the ICMP header changed, so subtract the old data from the checksum
		 * and add the new one.
		 */
		__wsum csum;
		unsigned int i, len;

		if (is_error(pkt_get_total_len_ipv6(pkt_out, &len)))
			return VER_DROP;

		csum = ~csum_unfold(in_icmp->checksum);

		/* Add the ICMPv6 pseudo-header */
		for (i = 0; i < 8; i++)
			csum = csum_add(csum, out_ip6->saddr.s6_addr16[i]);
		for (i = 0; i < 8; i++)
			csum = csum_add(csum, out_ip6->daddr.s6_addr16[i]);

		csum = csum_add(csum, cpu_to_be16(len));
		csum = csum_add(csum, cpu_to_be16(NEXTHDR_ICMP));

		/* Add the ICMPv6 header */
		csum = csum_add(csum, cpu_to_be16(out_icmp->icmp6_type << 8 | out_icmp->icmp6_code));
		csum = csum_add(csum, out_icmp->icmp6_dataun.u_echo.identifier);
		csum = csum_add(csum, out_icmp->icmp6_dataun.u_echo.sequence);

		/* There's no ICMPv4 pseudo-header. */

		/* Remove the ICMPv4 header */
		csum = csum_sub(csum, cpu_to_be16(in_icmp->type << 8 | in_icmp->code));
		csum = csum_sub(csum, in_icmp->un.echo.id);
		csum = csum_sub(csum, in_icmp->un.echo.sequence);

		out_icmp->icmp6_cksum = csum_fold(csum);
	}

	return VER_CONTINUE;
}

static __sum16 update_csum_4to6(__sum16 csum16,
		struct iphdr *in_ip4, __be16 in_src_port, __be16 in_dst_port,
		struct ipv6hdr *out_ip6, __be16 out_src_port, __be16 out_dst_port)
{
	__wsum csum;
	int i;
	union {
		__be32 as32;
		__be16 as16[2];
	} addr4;

	csum = ~csum_unfold(csum16);

	/* Remove the IPv4 crap */
	addr4.as32 = in_ip4->saddr;
	for (i = 0; i < 2; i++)
		csum = csum_sub(csum, addr4.as16[i]);
	addr4.as32 = in_ip4->daddr;
	for (i = 0; i < 2; i++)
		csum = csum_sub(csum, addr4.as16[i]);
	csum = csum_sub(csum, in_src_port);
	csum = csum_sub(csum, in_dst_port);

	/* Add the Ipv6 crap */
	for (i = 0; i < 8; i++)
		csum = csum_add(csum, out_ip6->saddr.s6_addr16[i]);
	for (i = 0; i < 8; i++)
		csum = csum_add(csum, out_ip6->daddr.s6_addr16[i]);
	csum = csum_add(csum, out_src_port);
	csum = csum_add(csum, out_dst_port);

	/* "Next Header" and "length" remain equal. */

	return csum_fold(csum);
}

/**
 * Sets the Checksum field from out's TCP header.
 */
static verdict post_tcp_ipv6(struct tuple *tuple, struct packet *pkt_in, struct packet *pkt_out)
{
	struct iphdr *in_ip4 = frag_get_ipv4_hdr(pkt_in->first_fragment);
	struct tcphdr *in_tcp = frag_get_tcp_hdr(pkt_in->first_fragment);
	struct ipv6hdr *out_ip6 = frag_get_ipv6_hdr(pkt_out->first_fragment);
	struct tcphdr *out_tcp = frag_get_tcp_hdr(pkt_out->first_fragment);

	out_tcp->source = cpu_to_be16(tuple->src.l4_id);
	out_tcp->dest = cpu_to_be16(tuple->dst.l4_id);
	out_tcp->check = update_csum_4to6(in_tcp->check,
			in_ip4, in_tcp->source, in_tcp->dest,
			out_ip6, out_tcp->source, out_tcp->dest);

	return VER_CONTINUE;
}

/**
 * Sets the ports and checksum fields of out's UDP header.
 */
static verdict post_udp_ipv6(struct tuple *tuple, struct packet *pkt_in, struct packet *pkt_out)
{
	struct fragment *in = pkt_in->first_fragment;
	struct fragment *out = pkt_out->first_fragment;
	struct iphdr *in_ip4 = frag_get_ipv4_hdr(in);
	struct udphdr *in_udp = frag_get_udp_hdr(in);
	struct ipv6hdr *out_ip6 = frag_get_ipv6_hdr(out);
	struct udphdr *out_udp = frag_get_udp_hdr(out);

	out_udp->source = cpu_to_be16(tuple->src.l4_id);
	out_udp->dest = cpu_to_be16(tuple->dst.l4_id);
	out_udp->check = update_csum_4to6(in_udp->check,
			in_ip4, in_udp->source, in_udp->dest,
			out_ip6, out_udp->source, out_udp->dest);

	return VER_CONTINUE;
}
