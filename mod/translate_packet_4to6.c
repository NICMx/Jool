/*-----------------------------------------------------------------------------------------------
 * -- IPv4 to IPv6, Layer 3 --
 * (This is RFC 6145 section 4.1. Translates IPv4 headers to IPv6)
 *-----------------------------------------------------------------------------------------------*/

static int has_frag_hdr(struct iphdr *in_hdr)
{
	return !is_dont_fragment_set(in_hdr) ||
			(is_more_fragments_set_ipv4(in_hdr) || get_fragment_offset_ipv4(in_hdr));
}

static int ttp46_create_out_skb(struct pkt_parts *in, struct sk_buff **out)
{
	int l3_hdr_len;
	int total_len;
	struct sk_buff *new_skb;
	bool is_first;

	is_first = is_first_fragment_ipv4(in->l3_hdr.ptr);

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
	if (is_first && in->l4_hdr.proto == L4PROTO_ICMP && is_icmp4_error(icmp_hdr(in->skb)->type)) {
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
			has_frag_hdr(in->l3_hdr.ptr) ? ((struct frag_hdr *) (ipv6_hdr(new_skb) + 1)) : NULL,
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
	ip6_hdr->payload_len = cpu_to_be16(out->l3_hdr.len - sizeof(struct ipv6hdr)
			+ out->l4_hdr.len + out->payload.len);;
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

	if (packet_mtu == 0) {
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

	packet_mtu += 20;
	nexthop4_mtu += 20;

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

static int compute_mtu6(struct sk_buff *in, struct sk_buff *out)
{
	struct icmp6hdr *out_icmp = icmp6_hdr(out);
#ifndef UNIT_TESTING
	struct dst_entry *out_dst;
	struct iphdr *hdr4;
	struct icmphdr *in_icmp = icmp_hdr(in);

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
static int icmp4_to_icmp6_dest_unreach(struct pkt_parts *in, struct pkt_parts *out)
{
	struct icmphdr *icmpv4_hdr = in->l4_hdr.ptr;
	struct icmp6hdr *icmpv6_hdr = out->l4_hdr.ptr;
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
		error = compute_mtu6(in->skb, out->skb);
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

static bool is_truncated_ipv6(struct pkt_parts *parts)
{
	struct ipv6hdr *hdr6;
	struct udphdr *hdr_udp;
	uint16_t l3_payload_len;

	switch (parts->l4_hdr.proto) {
	case L4PROTO_TCP:
	case L4PROTO_ICMP:
		/* Calculating the checksum doesn't hurt. Not calculating it might. */
		return false;
	case L4PROTO_UDP:
		hdr6 = parts->l3_hdr.ptr;
		hdr_udp = parts->l4_hdr.ptr;
		l3_payload_len = ntohs(hdr6->payload_len) - (parts->l4_hdr.ptr - parts->l3_hdr.ptr);
		return l3_payload_len == ntohs(hdr_udp->len);
	}

	return true; /* whatever. */
}

static bool is_csum6_computable(struct pkt_parts *parts)
{
	struct ipv6hdr *hdr6 = parts->l3_hdr.ptr;
	struct frag_hdr *hdr_frag = (hdr6->nexthdr == NEXTHDR_FRAGMENT)
			? ((struct frag_hdr *) (hdr6 + 1))
			: NULL;

	if (!is_first_fragment_ipv6(hdr_frag))
		return false;

	if (!is_inner_pkt(parts))
		return true;

	if (is_truncated_ipv6(parts))
		return false;

	if (is_fragmented_ipv6(hdr_frag))
		return false;

	return true;
}

static int update_icmp6_csum(struct pkt_parts *in, struct pkt_parts *out)
{
	struct ipv6hdr *out_ip6 = out->l3_hdr.ptr;
	struct icmphdr *in_icmp = in->l4_hdr.ptr;
	struct icmp6hdr *out_icmp = out->l4_hdr.ptr;
	struct icmphdr copy_hdr;
	unsigned int len;
	__wsum csum;
	int error;

	out_icmp->icmp6_cksum = 0;

	if (is_inner_pkt(out)) {
		len = out->l4_hdr.len + out->payload.len;
	} else {
		error = skb_aggregate_ipv6_payload_len(out->skb, &len);
		if (error)
			return error;
	}

	csum = ~csum_unfold(in_icmp->checksum);

	memcpy(&copy_hdr, in_icmp, sizeof(*in_icmp));
	copy_hdr.checksum = 0;
	csum = csum_sub(csum, csum_partial(&copy_hdr, sizeof(copy_hdr), 0));

	csum = csum_add(csum, csum_partial(out_icmp, sizeof(*out_icmp), 0));

	out_icmp->icmp6_cksum = csum_ipv6_magic(&out_ip6->saddr, &out_ip6->daddr, len,
			IPPROTO_ICMPV6, csum);

	return 0;
}

static int compute_icmp6_csum(struct pkt_parts *out)
{
	struct ipv6hdr *out_ip6 = out->l3_hdr.ptr;
	struct icmp6hdr *out_icmp = out->l4_hdr.ptr;
	__wsum csum;

	out_icmp->icmp6_cksum = 0;
	csum = csum_partial(out_icmp, out->l4_hdr.len, 0);
	csum = csum_partial(out->payload.ptr, out->payload.len, csum);
	out_icmp->icmp6_cksum = csum_ipv6_magic(&out_ip6->saddr, &out_ip6->daddr,
			out->l4_hdr.len + out->payload.len, IPPROTO_ICMPV6, csum);

	return 0;
}

static int post_icmp6info(struct tuple *tuple, struct pkt_parts *in, struct pkt_parts *out)
{
	int error;

	error = copy_payload(tuple, in, out);
	if (error)
		return error;
	if (is_csum6_computable(out))
		error = update_icmp6_csum(in, out);

	return error;
}

static int post_icmp6error(struct tuple *tuple, struct pkt_parts *in_outer,
		struct pkt_parts *out_outer)
{
	struct pkt_parts in_inner;
	int error;

	log_debug("Translating the inner packet (4->6)...");

	memset(&in_inner, 0, sizeof(in_inner));
	error = buffer4_to_parts(in_outer->payload.ptr, in_outer->payload.len, &in_inner);
	if (error)
		return error;

	error = translate_inner_packet(tuple, &in_inner, out_outer);
	if (error)
		return error;

	if (is_csum6_computable(out_outer))
		error = compute_icmp6_csum(out_outer);

	return error;
}

/**
 * Translates in's icmp4 header and payload into out's icmp6 header and payload.
 * This is the RFC 6145 sections 4.2 and 4.3, except checksum (See post_icmp6()).
 */
static int icmp_4to6(struct tuple* tuple, struct pkt_parts *in, struct pkt_parts *out)
{
	struct icmphdr *icmpv4_hdr = in->l4_hdr.ptr;
	struct icmp6hdr *icmpv6_hdr = out->l4_hdr.ptr;
	int error = 0;

	switch (icmpv4_hdr->type) {
	case ICMP_ECHO:
		icmpv6_hdr->icmp6_type = ICMPV6_ECHO_REQUEST;
		icmpv6_hdr->icmp6_code = 0;
		icmpv6_hdr->icmp6_dataun.u_echo.identifier = cpu_to_be16(tuple->icmp_id);
		icmpv6_hdr->icmp6_dataun.u_echo.sequence = icmpv4_hdr->un.echo.sequence;
		error = post_icmp6info(tuple, in, out);
		break;

	case ICMP_ECHOREPLY:
		icmpv6_hdr->icmp6_type = ICMPV6_ECHO_REPLY;
		icmpv6_hdr->icmp6_code = 0;
		icmpv6_hdr->icmp6_dataun.u_echo.identifier = cpu_to_be16(tuple->icmp_id);
		icmpv6_hdr->icmp6_dataun.u_echo.sequence = icmpv4_hdr->un.echo.sequence;
		error = post_icmp6info(tuple, in, out);
		break;

	case ICMP_DEST_UNREACH:
		error = icmp4_to_icmp6_dest_unreach(in, out);
		if (error)
			return error;
		error = post_icmp6error(tuple, in, out);
		break;

	case ICMP_TIME_EXCEEDED:
		icmpv6_hdr->icmp6_type = ICMPV6_TIME_EXCEED;
		icmpv6_hdr->icmp6_code = icmpv4_hdr->code;
		icmpv6_hdr->icmp6_unused = 0;
		error = post_icmp6error(tuple, in, out);
		break;

	case ICMP_PARAMETERPROB:
		error = icmp4_to_icmp6_param_prob(icmpv4_hdr, icmpv6_hdr);
		if (error)
			return error;
		error = post_icmp6error(tuple, in, out);
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

	return error;
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
static void handle_zero_csum(struct pkt_parts *in, struct pkt_parts *out)
{
	struct sk_buff *skb_in;
	struct ipv6hdr *hdr6 = out->l3_hdr.ptr;
	struct udphdr *hdr_udp = out->l4_hdr.ptr;
	unsigned int datagram_len;
	__wsum csum;

	if (is_inner_pkt(in) && is_fragmented_ipv4(in->l3_hdr.ptr)) {
		/*
		 * There's no way to compute the checksum.
		 * Also, this should never happen because we're supposed to have translated this inner
		 * packet, and we never assign zero UDP checksums in theory.
		 * But just in case, don't drop the packet.
		 */
		hdr_udp->check = (__force __sum16) 0x1234;
		return;
	}

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
	 * That's the second reason why we needed in as an argument.
	 */

	csum = csum_partial(hdr_udp, sizeof(*hdr_udp), 0);

	skb_in = in->skb;
	datagram_len = sizeof(*hdr_udp);
	do {
		unsigned int current_len = skb_payload_len(skb_in);
		csum = csum_partial(skb_payload(skb_in), current_len, csum);
		datagram_len += current_len;

		skb_in = skb_in->next;
	} while (skb_in);

	hdr_udp->check = csum_ipv6_magic(&hdr6->saddr, &hdr6->daddr, datagram_len, IPPROTO_UDP, csum);
}

static int tcp_4to6(struct tuple *tuple, struct pkt_parts *in, struct pkt_parts *out)
{
	struct tcphdr *tcp_in = in->l4_hdr.ptr;
	struct tcphdr *tcp_out = out->l4_hdr.ptr;
	struct tcphdr tcp_copy;

	/* Header */
	memcpy(tcp_out, tcp_in, in->l4_hdr.len);

	tcp_out->source = cpu_to_be16(tuple->src.l4_id);
	tcp_out->dest = cpu_to_be16(tuple->dst.l4_id);

	memcpy(&tcp_copy, tcp_in, sizeof(*tcp_in));
	tcp_copy.check = 0;

	tcp_out->check = 0;
	tcp_out->check = update_csum_4to6(tcp_in->check,
			in->l3_hdr.ptr, &tcp_copy, sizeof(tcp_copy),
			out->l3_hdr.ptr, tcp_out, sizeof(*tcp_out));

	/* Payload */
	memcpy(out->payload.ptr, in->payload.ptr, in->payload.len);

	return 0;
}

static int udp_4to6(struct tuple *tuple, struct pkt_parts *in, struct pkt_parts *out)
{
	struct udphdr *udp_in = in->l4_hdr.ptr;
	struct udphdr *udp_out = out->l4_hdr.ptr;
	struct udphdr udp_copy;

	/* Header */
	udp_out->source = cpu_to_be16(tuple->src.l4_id);
	udp_out->dest = cpu_to_be16(tuple->dst.l4_id);
	udp_out->len = udp_in->len;
	if (udp_in->check != 0) {
		memcpy(&udp_copy, udp_in, sizeof(*udp_in));
		udp_copy.check = 0;

		udp_out->check = 0;
		udp_out->check = update_csum_4to6(udp_in->check,
				in->l3_hdr.ptr, &udp_copy, sizeof(udp_copy),
				out->l3_hdr.ptr, udp_out, sizeof(*udp_out));
	} else {
		handle_zero_csum(in, out);
	}

	/* Payload */
	memcpy(out->payload.ptr, in->payload.ptr, in->payload.len);

	return 0;
}
