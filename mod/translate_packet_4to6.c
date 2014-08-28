/*-----------------------------------------------------------------------------------------------
 * -- IPv4 to IPv6, Layer 3 --
 * (This is RFC 6145 section 4.1. Translates IPv4 headers to IPv6)
 *-----------------------------------------------------------------------------------------------*/

static int has_frag_hdr(struct iphdr *in_hdr)
{
	return !is_dont_fragment_set(in_hdr);
}

static int ttp46_create_out_skb(struct pkt_parts *in, struct sk_buff **out)
{
	int l3_hdr_len;
	int total_len;
	struct sk_buff *new_skb;

	/**
	 * These are my assumptions to compute total_len:
	 *
	 * The IPv4 header will be replaced by a IPv6 header and possibly a fragment header.
	 * The L4 header will never change in size (in particular, ICMPv4 hdr len == ICMPv6 hdr len).
	 * The payload will not change in TCP, UDP and ICMP infos.
	 *
	 * As for ICMP errors:
	 * The IPv4 header will be replaced by a IPv6 header and possibly a fragment header.
	 * The sub-L4 header will never change in size.
	 * The subpayload will never change in size (unless it gets truncated later, but I don't care).
	 */
	l3_hdr_len = sizeof(struct ipv6hdr);
	if (has_frag_hdr(in->l3_hdr.ptr))
		l3_hdr_len += sizeof(struct frag_hdr);

	total_len = l3_hdr_len + in->l4_hdr.len + in->payload.len;
	if (in->l4_hdr.proto == L4PROTO_ICMP && is_icmp4_error(icmp_hdr(in->skb)->type)) {
		total_len += sizeof(struct ipv6hdr) - sizeof(struct iphdr);
		if (has_frag_hdr(in->payload.ptr))
			total_len += sizeof(struct frag_hdr);
	}

	new_skb = alloc_skb(LL_MAX_HEADER + total_len, GFP_ATOMIC);
	if (!new_skb)
		return -ENOMEM;

	skb_reserve(new_skb, LL_MAX_HEADER);
	skb_put(new_skb, total_len);
	skb_reset_mac_header(new_skb);
	skb_reset_network_header(new_skb);
	skb_set_transport_header(new_skb, l3_hdr_len);

	skb_set_jcb(new_skb, L3PROTO_IPV6, in->l4_hdr.proto,
			skb_transport_header(new_skb) + in->l4_hdr.len,
			skb_original_skb(in->skb));

	new_skb->mark = in->skb->mark;
	new_skb->protocol = htons(ETH_P_IPV6);
	new_skb->next = NULL;
	new_skb->prev = NULL;

	*out = new_skb;
	return 0;
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
static int create_ipv6_hdr(struct tuple *tuple, struct pkt_parts *in, struct pkt_parts *out)
{
	struct iphdr *ip4_hdr = in->l3_hdr.ptr;
	struct ipv6hdr *ip6_hdr;
	bool reset_traffic_class;

	rcu_read_lock_bh();
	reset_traffic_class = rcu_dereference_bh(config)->reset_traffic_class;
	rcu_read_unlock_bh();

	ip6_hdr = out->l3_hdr.ptr;
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
	/* This is just a temporary filler value. The real one will be set during post-processing. */
	ip6_hdr->payload_len = ip4_hdr->tot_len;
	ip6_hdr->nexthdr = (ip4_hdr->protocol == IPPROTO_ICMP) ? NEXTHDR_ICMP : ip4_hdr->protocol;
	if (!is_inner_pkt(in)) {
		if (ip4_hdr->ttl <= 1) {
			icmp64_send(in->skb, ICMPERR_HOP_LIMIT, 0);
			return -EINVAL;
		}
		ip6_hdr->hop_limit = ip4_hdr->ttl - 1;
	} else {
		ip6_hdr->hop_limit = ip4_hdr->ttl;
	}
	ip6_hdr->saddr = tuple->src.addr.ipv6;
	ip6_hdr->daddr = tuple->dst.addr.ipv6;

	/*
	 * This is already covered by the kernel, by logging martians
	 * (see the installation instructions).
	 */
	/*
	if (!is_address_legal(&ip6_hdr->saddr))
		return -EINVAL;
	*/

	if (!is_inner_pkt(in) && has_unexpired_src_route(ip4_hdr)) {
		log_debug("Packet has an unexpired source route.");
		icmp64_send(in->skb, ICMPERR_SRC_ROUTE, 0);
		return -EINVAL;
	}

	if (has_frag_hdr(in->l3_hdr.ptr)) {
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

	return 0;
}

/**
 * Sets the Payload Length field from out's IPv6 header.
 */
static int post_ipv6(struct pkt_parts *out)
{
	struct ipv6hdr *ip6_hdr = out->l3_hdr.ptr;
	__u16 l3_hdr_len = out->l3_hdr.len - sizeof(struct ipv6hdr);

	ip6_hdr->payload_len = cpu_to_be16(l3_hdr_len + out->l4_hdr.len + out->payload.len);

	return 0;
}


/*-----------------------------------------------------------------------------------------------
 * -- IPv4 to IPv6, Layer 4 --
 * (Because UDP and TCP almost require no translation, you'll find that this is mostly RFC 6145
 * sections 4.2 and 4.3 (ICMP).)
 *-----------------------------------------------------------------------------------------------*/

/**
 * One liner for creating the ICMPv6 header's MTU field.
 * Returns the smallest out of the three first parameters. It also handles some quirks. See comments
 * inside for more info.
 */
static __be32 icmp6_minimum_mtu(__u16 packet_mtu, __u16 nexthop6_mtu, __u16 nexthop4_mtu,
		__u16 tot_len_field)
{
	__u32 result;

	if (packet_mtu == 20) {
		/*
		 * Some router does not implement RFC 1191.
		 * Got to determine a likely path MTU.
		 * See RFC 1191 sections 5, 7 and 7.1 to understand the logic here.
		 */
		struct translate_config *config_safe;
		int plateau;

		rcu_read_lock_bh();
		config_safe = rcu_dereference_bh(config);

		for (plateau = 0; plateau < config_safe->mtu_plateau_count; plateau++) {
			if (config_safe->mtu_plateaus[plateau] < tot_len_field) {
				packet_mtu = config_safe->mtu_plateaus[plateau];
				break;
			}
		}

		rcu_read_unlock_bh();
	}

	/* Core comparison to find the minimum value. */
	if (nexthop6_mtu < packet_mtu)
		result = (nexthop6_mtu < nexthop4_mtu) ? nexthop6_mtu : nexthop4_mtu;
	else
		result = (packet_mtu < nexthop4_mtu) ? packet_mtu : nexthop4_mtu;

	rcu_read_lock_bh();
	if (rcu_dereference_bh(config)->lower_mtu_fail && result < IPV6_MIN_MTU) {
		/*
		 * Probably some router does not implement RFC 4890, section 4.3.1.
		 * Gotta override and hope for the best.
		 * See RFC 6145 section 6, second approach, to understand the logic here.
		 */
		result = IPV6_MIN_MTU;
	}
	rcu_read_unlock_bh();

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
static int icmp4_to_icmp6_dest_unreach(struct pkt_parts *in, struct pkt_parts *out)
{
	struct icmphdr *icmpv4_hdr = in->l4_hdr.ptr;
	struct icmp6hdr *icmpv6_hdr = out->l4_hdr.ptr;

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
		/* TODO test this. */
		icmpv6_hdr->icmp6_pointer = cpu_to_be32(offsetof(struct ipv6hdr, nexthdr));
		break;

	case ICMP_PORT_UNREACH:
		icmpv6_hdr->icmp6_code = ICMPV6_PORT_UNREACH;
		break;

	case ICMP_FRAG_NEEDED:
		icmpv6_hdr->icmp6_type = ICMPV6_PKT_TOOBIG;
		icmpv6_hdr->icmp6_code = 0;
		/* I moved this to post_icmp6() because it needs the skb already created. */
		icmpv6_hdr->icmp6_mtu = htonl(0);
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

static int buffer4_to_parts(struct iphdr *hdr4, int len, struct pkt_parts *parts)
{
	struct icmphdr *hdr_icmp;
	int error;

	error = validate_ipv4_integrity(hdr4, len, true);
	if (error)
		return error;

	parts->l3_hdr.proto = L3PROTO_IPV4;
	parts->l3_hdr.len = 4 * hdr4->ihl;
	parts->l3_hdr.ptr = hdr4;
	parts->l4_hdr.ptr = parts->l3_hdr.ptr + parts->l3_hdr.len;

	switch (hdr4->protocol) {
	case IPPROTO_TCP:
		error = validate_lengths_tcp(len, parts->l3_hdr.len, parts->l4_hdr.ptr);
		if (error)
			return error;

		parts->l4_hdr.proto = L4PROTO_TCP;
		parts->l4_hdr.len = tcp_hdr_len(parts->l4_hdr.ptr);
		break;
	case IPPROTO_UDP:
		error = validate_lengths_udp(len, parts->l3_hdr.len);
		if (error)
			return error;

		parts->l4_hdr.proto = L4PROTO_UDP;
		parts->l4_hdr.len = sizeof(struct udphdr);
		break;
	case IPPROTO_ICMP:
		error = validate_lengths_icmp4(len, parts->l3_hdr.len);
		if (error)
			return error;
		hdr_icmp = parts->l4_hdr.ptr;
		if (icmp4_has_inner_packet(hdr_icmp->type))
			return -EINVAL; /* packet inside packet inside packet. */

		parts->l4_hdr.proto = L4PROTO_ICMP;
		parts->l4_hdr.len = sizeof(struct icmphdr);
		break;
	default:
		/*
		 * Why are we translating a error packet of a packet we couldn't have translated?
		 * Either an attack or shouldn't happen, so drop silently.
		 */
		return -EINVAL;
	}

	parts->payload.len = len - parts->l3_hdr.len - parts->l4_hdr.len;
	parts->payload.ptr = parts->l4_hdr.ptr + parts->l4_hdr.len;
	parts->skb = NULL;

	return 0;
}

/**
 * Sets out_outer.payload.*.
 */
static int translate_inner_packet_4to6(struct tuple *tuple, struct pkt_parts *in_outer,
		struct pkt_parts *out_outer)
{
	struct pkt_parts in_inner;
	int error;

	log_debug("Translating the inner packet (4->6)...");

	memset(&in_inner, 0, sizeof(in_inner));
	error = buffer4_to_parts(in_outer->payload.ptr, in_outer->payload.len, &in_inner);
	if (error)
		return error;

	return translate_inner_packet(tuple, &in_inner, out_outer);
}

/**
 * Translates in's icmp4 header and payload into out's icmp6 header and payload.
 * This is the RFC 6145 sections 4.2 and 4.3, except checksum (See post_icmp6()).
 */
static int create_icmp6_hdr_and_payload(struct tuple* tuple, struct pkt_parts *in,
		struct pkt_parts *out)
{
	int error;
	struct icmphdr *icmpv4_hdr = in->l4_hdr.ptr;
	struct icmp6hdr *icmpv6_hdr = out->l4_hdr.ptr;

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

	case ICMP_DEST_UNREACH:
		error = icmp4_to_icmp6_dest_unreach(in, out);
		if (error)
			return error;
		break;

	case ICMP_TIME_EXCEEDED:
		icmpv6_hdr->icmp6_type = ICMPV6_TIME_EXCEED;
		icmpv6_hdr->icmp6_code = icmpv4_hdr->code;
		icmpv6_hdr->icmp6_unused = 0;
		break;

	case ICMP_PARAMETERPROB:
		error = icmp4_to_icmp6_param_prob(icmpv4_hdr, icmpv6_hdr);
		if (error)
			return error;
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
		log_debug("ICMPv4 messages type %u do not exist in ICMPv6.", icmpv4_hdr->type);
		return -EINVAL;
	}

	/* -- Then the payload. -- */
	if (icmp4_has_inner_packet(icmpv4_hdr->type)) {
		error = translate_inner_packet_4to6(tuple, in, out);
		if (error)
			return error;
	} else {
		memcpy(out->payload.ptr, in->payload.ptr, in->payload.len);
	}

	return 0;
}

static int post_mtu6(struct pkt_parts *in, struct pkt_parts *out)
{
	struct icmp6hdr *out_icmp = out->l4_hdr.ptr;
#ifndef UNIT_TESTING
	struct dst_entry *out_dst;
	struct iphdr *hdr4;
	struct icmphdr *in_icmp = in->l4_hdr.ptr;

	log_debug("Packet MTU: %u", be16_to_cpu(in_icmp->un.frag.mtu));

	if (!in->skb || !in->skb->dev)
		return -EINVAL;
	log_debug("In dev MTU: %u", in->skb->dev->mtu);

	out_dst = skb_dst(out->skb);
	log_debug("Out dev MTU: %u", out_dst->dev->mtu);

	/* We want the length of the packet that couldn't get through, not the truncated one. */
	hdr4 = in->payload.ptr;

	out_icmp->icmp6_mtu = icmp6_minimum_mtu(be16_to_cpu(in_icmp->un.frag.mtu) + 20,
			out_dst->dev->mtu,
			in->skb->dev->mtu + 20,
			be16_to_cpu(hdr4->tot_len));
	log_debug("Resulting MTU: %u", be32_to_cpu(out_icmp->icmp6_mtu));

#else
	out_icmp->icmp6_mtu = cpu_to_be32(1500);
#endif

	return 0;
}

/**
 * Sets the Checksum field from out's ICMPv6 header.
 */
static int post_icmp6(struct tuple *tuple, struct pkt_parts *in, struct pkt_parts *out)
{
	struct ipv6hdr *out_ip6 = out->l3_hdr.ptr;
	struct icmphdr *in_icmp = in->l4_hdr.ptr;
	struct icmp6hdr *out_icmp = out->l4_hdr.ptr;
	__wsum csum;

	if (out_icmp->icmp6_type == ICMPV6_PKT_TOOBIG && out_icmp->icmp6_code == 0) {
		int error = post_mtu6(in, out);
		if (error)
			return error;
	}

	if (is_icmp6_error(out_icmp->icmp6_type)) {
		/*
		 * Header and payload both changed completely, so just trash the old checksum
		 * and start anew.
		 */
		out_icmp->icmp6_cksum = 0;
		csum = csum_partial(out_icmp, out->l4_hdr.len, 0);
		csum = csum_partial(out->payload.ptr, out->payload.len, csum);
		out_icmp->icmp6_cksum = csum_ipv6_magic(&out_ip6->saddr, &out_ip6->daddr,
				out->l4_hdr.len + out->payload.len, IPPROTO_ICMPV6, csum);
	} else {
		/*
		 * Only the ICMP header changed, so subtract the old data from the checksum
		 * and add the new one.
		 */
		unsigned int i;

		csum = ~csum_unfold(in_icmp->checksum);

		/* Add the ICMPv6 pseudo-header */
		for (i = 0; i < 8; i++)
			csum = csum_add(csum, out_ip6->saddr.s6_addr16[i]);
		for (i = 0; i < 8; i++)
			csum = csum_add(csum, out_ip6->daddr.s6_addr16[i]);

		csum = csum_add(csum, cpu_to_be16(out->l4_hdr.len + out->payload.len));
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

	return 0;
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
static int post_tcp_ipv6(struct tuple *tuple, struct pkt_parts *in, struct pkt_parts *out)
{
	struct tcphdr *in_tcp = in->l4_hdr.ptr;
	struct tcphdr *out_tcp = out->l4_hdr.ptr;

	out_tcp->check = update_csum_4to6(in_tcp->check,
			in->l3_hdr.ptr, in_tcp->source, in_tcp->dest,
			out->l3_hdr.ptr, out_tcp->source, out_tcp->dest);

	return 0;
}

/**
 * Sets the ports and checksum fields of out's UDP header.
 */
static int post_udp_ipv6(struct tuple *tuple, struct pkt_parts *in, struct pkt_parts *out)
{
	struct udphdr *in_udp = in->l4_hdr.ptr;
	struct udphdr *out_udp = out->l4_hdr.ptr;

	out_udp->check = update_csum_4to6(in_udp->check,
			in->l3_hdr.ptr, in_udp->source, in_udp->dest,
			out->l3_hdr.ptr, out_udp->source, out_udp->dest);

	return 0;
}
