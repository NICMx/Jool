#include "packet-init.h"

struct pkt_metadata {
	bool has_frag_hdr;
	/*
	 * Atomic fragments have a fragment header but aren't fragmented.
	 * They are deprecated, but we shouldn't make assumptions.
	 */
	bool is_fragmented;
	bool is_first_fragment;
	/*
	 * This is the memory offset from skb->data, not the fragment header
	 * field called "fragment offset".
	 * Do not use if has_frag_hdr is false.
	 */
	unsigned int frag_offset;
	enum l4_protocol l4_proto;
	/* Offset is from skb->data. */
	unsigned int l4_offset;
	/* Offset is from skb->data. */
	unsigned int payload_offset;
};

#define skb_hdr_ptr(skb, offset, buffer) \
	skb_header_pointer(skb, offset, sizeof(buffer), &buffer)

static bool has_inner_pkt4(__u8 icmp_type)
{
	return is_icmp4_error(icmp_type);
}

static bool has_inner_pkt6(__u8 icmp6_type)
{
	return is_icmp6_error(icmp6_type);
}

static int truncated(struct xlation *state, const char *what)
{
	/*
	 * No ICMP error; "If it is not possible to determine the incoming
	 * #-tuple (perhaps because not enough of the embedded packet is
	 * reproduced inside the # message), then the incoming IP packet MUST be
	 * silently discarded." - RFC 6146
	 */
	log_debug("The %s seems truncated.", what);
	return einval(state, JOOL_MIB_TRUNCATED);
}

static void *offset_to_ptr(struct sk_buff *skb, unsigned int offset)
{
	return ((void *)skb->data) + offset;
}

/**
 * Apparently, as of 2007, Netfilter modules can assume they are the sole owners
 * of their skbs (http://lists.openwall.net/netdev/2007/10/14/13).
 * I can sort of confirm it by noticing that if it's not the case, editing the
 * sk_buff structs themselves would be overly cumbersome (since they'd have to
 * operate on a clone, and bouncing the clone back to Netfilter is kind of
 * outside Netfilter's design).
 * This is relevant because we need to call pskb_may_pull(), which might
 * eventually call pskb_expand_head(), and that panics if the packet is shared.
 * Therefore, I think this validation (with messy WARN included) is fair.
 *
 * TODO this no longer applies and drivers can receive shared packets.
 * Copy the headers to a temporal buffer I guess.
 */
static int fail_if_shared(struct sk_buff *skb)
{
	if (WARN(skb_shared(skb), "The packet is shared!"))
		return -EINVAL;

	/*
	 * Keep in mind... "shared" and "cloned" are different concepts.
	 * We know the sk_buff struct is unique, but somebody else might have an
	 * active pointer towards the data area.
	 */
	return 0;
}

/**
 * Walks through @skb's headers, collecting data and adding it to @meta.
 *
 * @hdr6_offset number of bytes between skb_network_header(skb) and the v6 hdr.
 *
 * BTW: You might want to read summarize_skb4() first, since it's a lot simpler.
 */
static int summarize_skb6(struct xlation *state, unsigned int hdr6_offset,
		struct pkt_metadata *meta)
{
	union {
		struct ipv6_opt_hdr opt;
		struct frag_hdr frag;
		struct tcphdr tcp;
	} buffer;
	union {
		struct ipv6_opt_hdr *opt;
		struct frag_hdr *frag;
		struct tcphdr *tcp;
	} ptr;

	struct sk_buff *skb;
	u8 nexthdr;
	unsigned int offset;

	skb = state->in.skb;
	nexthdr = ((struct ipv6hdr *)(skb_network_header(skb) + hdr6_offset))->nexthdr;
	offset = hdr6_offset + sizeof(struct ipv6hdr);
	meta->has_frag_hdr = false;
	meta->is_fragmented = false;
	meta->is_first_fragment = true;

	do {
		switch (nexthdr) {
		case NEXTHDR_TCP:
			meta->l4_proto = L4PROTO_TCP;
			meta->l4_offset = offset;
			meta->payload_offset = offset;

			if (meta->is_first_fragment) {
				ptr.tcp = skb_hdr_ptr(skb, offset, buffer.tcp);
				if (!ptr.tcp)
					return truncated(state, "TCP header");
				meta->payload_offset += tcp_hdr_len(ptr.tcp);
			}

			return 0;

		case NEXTHDR_UDP:
			meta->l4_proto = L4PROTO_UDP;
			meta->l4_offset = offset;
			meta->payload_offset = meta->is_first_fragment
					? (offset + sizeof(struct udphdr))
					: offset;
			return 0;

		case NEXTHDR_ICMP:
			meta->l4_proto = L4PROTO_ICMP;
			meta->l4_offset = offset;
			meta->payload_offset = meta->is_first_fragment
					? (offset + sizeof(struct icmp6hdr))
					: offset;
			return 0;

		case NEXTHDR_FRAGMENT:
			ptr.frag = skb_hdr_ptr(skb, offset, buffer.frag);
			if (!ptr.frag)
				return truncated(state, "fragment header");

			meta->has_frag_hdr = true;
			meta->is_fragmented = is_fragmented_ipv6(ptr.frag);
			meta->frag_offset = offset;
			meta->is_first_fragment = is_first_frag6(ptr.frag);

			offset += sizeof(struct frag_hdr);
			nexthdr = ptr.frag->nexthdr;
			break;

		case NEXTHDR_HOP:
		case NEXTHDR_ROUTING:
		case NEXTHDR_DEST:
			ptr.opt = skb_hdr_ptr(skb, offset, buffer.opt);
			if (!ptr.opt)
				return truncated(state, "extension header");

			offset += 8 + 8 * ptr.opt->hdrlen;
			nexthdr = ptr.opt->nexthdr;
			break;

		default:
			meta->l4_proto = L4PROTO_OTHER;
			meta->l4_offset = offset;
			meta->payload_offset = offset;
			return 0;
		}
	} while (true);

	return 0; /* whatever. */
}

/* No ICMP errors here; ICMP errors should not trigger ICMP errors. */
static int validate_inner6(struct xlation *state,
		struct pkt_metadata *outer_meta)
{
	union {
		struct ipv6hdr ip6;
		struct icmp6hdr icmp;
	} buffer;
	union {
		struct ipv6hdr *ip6;
		struct icmp6hdr *icmp;
	} ptr;

	struct sk_buff *skb = state->in.skb;
	struct pkt_metadata meta;
	int error;

	ptr.ip6 = skb_hdr_ptr(skb, outer_meta->payload_offset, buffer.ip6);
	if (!ptr.ip6)
		return truncated(state, "inner IPv6 header");
	if (unlikely(ptr.ip6->version != 6)) {
		log_debug("Version is not 6.");
		return einval(state, JOOL_MIB_HDR6_VERSION);
	}

	error = summarize_skb6(state, outer_meta->payload_offset, &meta);
	if (error)
		return error;

	if (!meta.is_first_fragment) {
		log_debug("Inner packet is not a first fragment.");
		return einval(state, JOOL_MIB_INNER_FRAG6);
	}

	if (meta.l4_proto == L4PROTO_ICMP) {
		ptr.icmp = skb_hdr_ptr(skb, meta.l4_offset, buffer.icmp);
		if (!ptr.icmp)
			return truncated(state, "inner ICMPv6 header");
		if (has_inner_pkt6(ptr.icmp->icmp6_type)) {
			/*
			 * No ICMP error; "If the incoming IP packet contains a
			 * complete (un-fragmented) ICMP error message
			 * containing an ICMP error message, then the packet is
			 * silently discarded." - RFC 6146
			 */
			log_debug("Packet inside packet inside packet.");
			return einval(state, JOOL_MIB_2X_INNER6);
		}
	}

	if (!pskb_may_pull(skb, meta.payload_offset)) {
		log_debug("Could not 'pull' the headers out of the skb.");
		return einval(state, JOOL_MIB_CANNOT_PULL);
	}

	return 0;
}

static int handle_icmp6(struct xlation *state, struct pkt_metadata *meta)
{
	struct icmp6hdr buffer, *ptr;

	if (meta->is_fragmented) {
		/*
		 * There is no ICMP error for this kind of problem.
		 * (Also ICMP errors are bogus and should not trigger ICMP
		 * errors.)
		 */
		log_debug("Fragmented ICMPv6 packets cannot be translated.");
		return einval(state, JOOL_MIB_FRAGMENTED_ICMP6);
	}

	ptr = skb_hdr_ptr(state->in.skb, meta->l4_offset, buffer);
	if (!ptr)
		return truncated(state, "ICMPv6 header");

	return has_inner_pkt6(ptr->icmp6_type)
			? validate_inner6(state, meta)
			: 0;
}

int pkt_init_ipv6(struct xlation *state, struct sk_buff *skb)
{
	struct pkt_metadata meta;
	int error;

	/*
	 * Careful in this function and subfunctions. pskb_may_pull() might
	 * change header pointers, so you generally don't want to store them.
	 */

	state->in.skb = skb; /* Prepare prematurely for breakdown(). */

	error = fail_if_shared(skb);
	if (error)
		return breakdown(state, JOOL_MIB_SHARED6, error);

	if (skb->len != get_tot_len_ipv6(skb)) {
		log_debug("Packet size doesn't match the IPv6 header's payload length field.");
		return einval(state, JOOL_MIB_HDR6_PAYLOAD_LEN);
	}

	error = summarize_skb6(state, skb_network_offset(skb), &meta);
	if (error)
		return error;

	if (meta.l4_proto == L4PROTO_ICMP) {
		/*
		 * Do not move this to summarize_skb6(),
		 * because it risks infinite recursion.
		 */
		error = handle_icmp6(state, &meta);
		if (error)
			return error;
	}

	if (!pskb_may_pull(skb, meta.payload_offset)) {
		log_debug("Could not 'pull' the headers out of the skb.");
		return einval(state, JOOL_MIB_CANNOT_PULL);
	}

	state->in.l3_proto = L3PROTO_IPV6;
	state->in.l4_proto = meta.l4_proto;
	state->in.is_inner = 0;
	state->in.is_hairpin = false;
	state->in.hdr_frag = meta.has_frag_hdr
			? offset_to_ptr(skb, meta.frag_offset)
			: NULL;
	skb_set_transport_header(skb, meta.l4_offset);
	state->in.payload = offset_to_ptr(skb, meta.payload_offset);
	state->in.original_pkt = &state->in;

	return 0;
}

/**
 * Collects a bunch of useful information from @state's incoming packet and
 * stores it in @meta.
 */
static int summarize_skb4(struct xlation *state, unsigned int hdr4_offset,
		struct pkt_metadata *meta)
{
	struct sk_buff *skb;
	struct iphdr *hdr4;
	unsigned int offset;

	skb = state->in.skb;
	hdr4 = (struct iphdr *)(skb_network_header(skb) + hdr4_offset);
	offset = hdr4_offset + (hdr4->ihl << 2);

	meta->has_frag_hdr = false;
	meta->is_fragmented = is_fragmented_ipv4(hdr4);
	meta->is_first_fragment = is_first_frag4(hdr4);
	meta->l4_offset = offset;
	meta->payload_offset = offset;

	switch (hdr4->protocol) {
	case IPPROTO_TCP:
		meta->l4_proto = L4PROTO_TCP;
		if (meta->is_first_fragment) {
			struct tcphdr buffer, *ptr;
			ptr = skb_hdr_ptr(skb, offset, buffer);
			if (!ptr)
				return truncated(state, "TCP header");
			meta->payload_offset += tcp_hdr_len(ptr);
		}
		return 0;

	case IPPROTO_UDP:
		meta->l4_proto = L4PROTO_UDP;
		if (meta->is_first_fragment)
			meta->payload_offset += sizeof(struct udphdr);
		return 0;

	case IPPROTO_ICMP:
		meta->l4_proto = L4PROTO_ICMP;
		if (meta->is_first_fragment)
			meta->payload_offset += sizeof(struct icmphdr);
		return 0;
	}

	meta->l4_proto = L4PROTO_OTHER;
	return 0;
}

/* No ICMP errors here; ICMP errors should not trigger ICMP errors. */
static int validate_inner4(struct xlation *state,
		struct pkt_metadata *outer_meta)
{
	union {
		struct iphdr hdr4;
		struct icmphdr icmp;
	} buffer;
	union {
		struct iphdr *hdr4;
		struct icmphdr *icmp;
	} ptr;
	struct sk_buff *skb = state->in.skb;
	struct pkt_metadata meta;
	unsigned int ihl;
	int error;

	ptr.hdr4 = skb_hdr_ptr(skb, outer_meta->payload_offset, buffer.hdr4);
	if (!ptr.hdr4)
		return truncated(state, "inner IPv4 header");

	ihl = ptr.hdr4->ihl << 2;
	if (ptr.hdr4->version != 4) {
		log_debug("Inner packet is not IPv4.");
		return einval(state, JOOL_MIB_HDR4_VERSION);
	}
	if (ihl < 20) {
		log_debug("Inner packet's IHL is bogus.");
		return einval(state, JOOL_MIB_HDR4_IHL);
	}
	if (ntohs(ptr.hdr4->tot_len) < ihl) {
		log_debug("Inner packet's total length is bogus.");
		return einval(state, JOOL_MIB_HDR4_TOTAL_LEN);
	}
	if (!is_first_frag4(ptr.hdr4)) {
		log_debug("Inner packet is not first fragment.");
		return einval(state, JOOL_MIB_INNER_FRAG4);
	}

	error = summarize_skb4(state, outer_meta->payload_offset, &meta);
	if (error)
		return error;

	if (meta.l4_proto == L4PROTO_ICMP) {
		ptr.icmp = skb_hdr_ptr(skb, meta.l4_offset, buffer.icmp);
		if (!ptr.icmp)
			return truncated(state, "inner ICMPv4 header");
		if (has_inner_pkt4(ptr.icmp->type)) {
			log_debug("Packet inside packet inside packet.");
			return einval(state, JOOL_MIB_2X_INNER4);
		}
	}

	if (!pskb_may_pull(skb, meta.payload_offset)) {
		log_debug("Could not 'pull' the headers out of the skb.");
		return einval(state, JOOL_MIB_CANNOT_PULL);
	}

	return 0;
}

static int handle_icmp4(struct xlation *state, struct pkt_metadata *meta)
{
	struct icmphdr buffer, *ptr;

	if (meta->is_fragmented) {
		/*
		 * "Fragmented ICMP/ICMPv6 packets will not be translated by
		 * IP/ICMP translators." - RFC 7915
		 * Technically, stateful translators *can* deal with fragmented
		 * ICMP infos, and in fact the rest of Jool can handle this
		 * perfecly well, but we're going with standards compliance.
		 */
		log_debug("Fragmented ICMPv4 packets cannot be translated.");
		return einval(state, JOOL_MIB_FRAGMENTED_ICMP4);
	}

	ptr = skb_hdr_ptr(state->in.skb, meta->l4_offset, buffer);
	if (!ptr)
		return truncated(state, "ICMP header");

	return has_inner_pkt4(ptr->type) ? validate_inner4(state, meta) : 0;
}

int pkt_init_ipv4(struct xlation *state, struct sk_buff *skb)
{
	struct pkt_metadata meta;
	int error;

	/*
	 * Careful in this function and subfunctions. pskb_may_pull() might
	 * change header pointers, so you generally don't want to store them.
	 */

	state->in.skb = skb; /* Prepare prematurely for breakdown(). */

	error = fail_if_shared(skb);
	if (error)
		return breakdown(state, JOOL_MIB_SHARED4, error);

	error = summarize_skb4(state, skb_network_offset(skb), &meta);
	if (error)
		return error;

	if (meta.l4_proto == L4PROTO_ICMP) {
		/*
		 * Do not move this to summarize_skb4(),
		 * because it risks infinite recursion.
		 */
		error = handle_icmp4(state, &meta);
		if (error)
			return error;
	}

	if (!pskb_may_pull(skb, meta.payload_offset)) {
		log_debug("Could not 'pull' the headers out of the skb.");
		return einval(state, JOOL_MIB_CANNOT_PULL);
	}

	state->in.l3_proto = L3PROTO_IPV4;
	state->in.l4_proto = meta.l4_proto;
	state->in.is_inner = false;
	state->in.is_hairpin = false;
	state->in.hdr_frag = NULL;
	skb_set_transport_header(skb, meta.l4_offset);
	state->in.payload = offset_to_ptr(skb, meta.payload_offset);
	state->in.original_pkt = &state->in;

	return 0;
}
