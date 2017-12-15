#include "packet.h"

#include <linux/version.h>
#include <linux/icmp.h>
#include <net/route.h>

#include "types.h"
#include "constants.h"
#include "str-utils.h"
#include "config.h"
#include "xlation.h"

struct pkt_metadata {
	bool has_frag_hdr;
	/* Offset is from skb->data. Do not use if has_frag_hdr is false. */
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
	log_debug("The %s seems truncated.", what);
	return breakdown(state, JOOL_MIB_TRUNCATED, -EINVAL);
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
	bool is_first = true;

	skb = state->in.skb;
	nexthdr = ((struct ipv6hdr *)(skb_network_header(skb) + hdr6_offset))->nexthdr;
	offset = hdr6_offset + sizeof(struct ipv6hdr);
	meta->has_frag_hdr = false;

	do {
		switch (nexthdr) {
		case NEXTHDR_TCP:
			meta->l4_proto = L4PROTO_TCP;
			meta->l4_offset = offset;
			meta->payload_offset = offset;

			if (is_first) {
				ptr.tcp = skb_hdr_ptr(skb, offset, buffer.tcp);
				if (!ptr.tcp)
					return truncated(state, "TCP header");
				meta->payload_offset += tcp_hdr_len(ptr.tcp);
			}

			return 0;

		case NEXTHDR_UDP:
			meta->l4_proto = L4PROTO_UDP;
			meta->l4_offset = offset;
			meta->payload_offset = is_first
					? (offset + sizeof(struct udphdr))
					: offset;
			return 0;

		case NEXTHDR_ICMP:
			meta->l4_proto = L4PROTO_ICMP;
			meta->l4_offset = offset;
			meta->payload_offset = is_first
					? (offset + sizeof(struct icmp6hdr))
					: offset;
			return 0;

		case NEXTHDR_FRAGMENT:
			ptr.frag = skb_hdr_ptr(skb, offset, buffer.frag);
			if (!ptr.frag)
				return truncated(state, "fragment header");

			meta->has_frag_hdr = true;
			meta->frag_offset = offset;
			is_first = is_first_frag6(ptr.frag);

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

static int validate_inner6(struct xlation *state, struct pkt_metadata *outer_meta)
{
	union {
		struct ipv6hdr ip6;
		struct frag_hdr frag;
		struct icmp6hdr icmp;
	} buffer;
	union {
		struct ipv6hdr *ip6;
		struct frag_hdr *frag;
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
		return breakdown(state, JOOL_MIB_HDR6_VERSION, -EINVAL);
	}

	error = summarize_skb6(state, outer_meta->payload_offset, &meta);
	if (error)
		return error;

	if (meta.has_frag_hdr) {
		ptr.frag = skb_hdr_ptr(skb, meta.frag_offset, buffer.frag);
		if (!ptr.frag)
			return truncated(state, "inner fragment header");
		if (!is_first_frag6(ptr.frag)) {
			log_debug("Inner packet is not a first fragment.");
			return breakdown(state, JOOL_MIB_INNER_FRAG6, -EINVAL);
		}
	}

	if (meta.l4_proto == L4PROTO_ICMP) {
		ptr.icmp = skb_hdr_ptr(skb, meta.l4_offset, buffer.icmp);
		if (!ptr.icmp)
			return truncated(state, "inner ICMPv6 header");
		if (has_inner_pkt6(ptr.icmp->icmp6_type)) {
			log_debug("Packet inside packet inside packet.");
			return breakdown(state, JOOL_MIB_2X_INNER6, -EINVAL);
		}
	}

	if (!pskb_may_pull(skb, meta.payload_offset)) {
		log_debug("Could not 'pull' the headers out of the skb.");
		return breakdown(state, JOOL_MIB_CANNOT_PULL, -EINVAL);
	}

	return 0;
}

static int handle_icmp6(struct xlation *state, struct pkt_metadata *meta)
{
	union {
		struct icmp6hdr icmp;
		struct frag_hdr frag;
	} buffer;
	union {
		struct icmp6hdr *icmp;
		struct frag_hdr *frag;
	} ptr;
	int error;

	ptr.icmp = skb_hdr_ptr(state->in.skb, meta->l4_offset, buffer.icmp);
	if (!ptr.icmp)
		return truncated(state, "ICMPv6 header");

	if (has_inner_pkt6(ptr.icmp->icmp6_type)) {
		error = validate_inner6(state, meta);
		if (error)
			return error;
	}

	if (state->jool.type == XLATOR_SIIT && meta->has_frag_hdr
			&& is_icmp6_info(ptr.icmp->icmp6_type)) {
		ptr.frag = skb_hdr_ptr(state->in.skb, meta->frag_offset, buffer.frag);
		if (!ptr.frag)
			return truncated(state, "fragment header");
		if (is_fragmented_ipv6(ptr.frag)) {
			log_debug("Packet is a fragmented ping; its checksum cannot be translated.");
			return breakdown(state, JOOL_MIB_CANNOT_CSUM6, -EINVAL);
		}
	}

	return 0;
}

/**
 * As a contract, pkt_destroy() doesn't need to be called if this fails.
 * (Just like other init functions.)
 */
int pkt_init_ipv6(struct xlation *state, struct sk_buff *skb)
{
	struct pkt_metadata meta;
	int error;

	/*
	 * Careful in this function and subfunctions. pskb_may_pull() might
	 * change pointers, so you generally don't want to store them.
	 */

	state->in.skb = skb; /* Prepare prematurely for breakdown(). */

	error = fail_if_shared(skb);
	if (error)
		return breakdown(state, JOOL_MIB_SHARED6, error);

	if (skb->len != get_tot_len_ipv6(skb)) {
		log_debug("Packet size doesn't match the IPv6 header's payload length field.");
		return breakdown(state, JOOL_MIB_HDR6_PAYLOAD_LEN, -EINVAL);
	}

	error = summarize_skb6(state, skb_network_offset(skb), &meta);
	if (error)
		return error;

	if (meta.l4_proto == L4PROTO_ICMP) {
		/* Do not move this to summarize_skb6(), because it risks infinite recursion. */
		error = handle_icmp6(state, &meta);
		if (error)
			return error;
	}

	if (!pskb_may_pull(skb, meta.payload_offset)) {
		log_debug("Could not 'pull' the headers out of the skb.");
		return breakdown(state, JOOL_MIB_CANNOT_PULL, -EINVAL);
	}

	state->in.l3_proto = L3PROTO_IPV6;
	state->in.l4_proto = meta.l4_proto;
	state->in.is_inner = 0;
	state->in.is_hairpin = false;
	state->in.hdr_frag = meta.has_frag_hdr ? offset_to_ptr(skb, meta.frag_offset) : NULL;
	skb_set_transport_header(skb, meta.l4_offset);
	state->in.payload = offset_to_ptr(skb, meta.payload_offset);
	state->in.original_pkt = &state->in;

	return 0;
}

static int validate_inner4(struct xlation *state, struct pkt_metadata *meta)
{
	union {
		struct iphdr ip4;
		struct tcphdr tcp;
	} buffer;
	union {
		struct iphdr *ip4;
		struct tcphdr *tcp;
	} ptr;
	struct sk_buff *skb = state->in.skb;
	unsigned int ihl;
	unsigned int offset = meta->payload_offset;

	ptr.ip4 = skb_hdr_ptr(skb, offset, buffer.ip4);
	if (!ptr.ip4)
		return truncated(state, "inner IPv4 header");

	ihl = ptr.ip4->ihl << 2;
	if (ptr.ip4->version != 4) {
		log_debug("Inner packet is not IPv4.");
		return breakdown(state, JOOL_MIB_HDR4_VERSION, -EINVAL);
	}
	if (ihl < 20) {
		log_debug("Inner packet's IHL is bogus.");
		return breakdown(state, JOOL_MIB_HDR4_IHL, -EINVAL);
	}
	if (ntohs(ptr.ip4->tot_len) < ihl) {
		log_debug("Inner packet's total length is bogus.");
		return breakdown(state, JOOL_MIB_HDR4_TOTAL_LEN, -EINVAL);
	}
	if (!is_first_frag4(ptr.ip4)) {
		log_debug("Inner packet is not first fragment.");
		return breakdown(state, JOOL_MIB_INNER_FRAG4, -EINVAL);
	}

	offset += ihl;

	switch (ptr.ip4->protocol) {
	case IPPROTO_TCP:
		ptr.tcp = skb_hdr_ptr(skb, offset, buffer.tcp);
		if (!ptr.tcp)
			return truncated(state, "inner TCP header");
		offset += tcp_hdr_len(ptr.tcp);
		break;
	case IPPROTO_UDP:
		offset += sizeof(struct udphdr);
		break;
	case IPPROTO_ICMP:
		offset += sizeof(struct icmphdr);
		break;
	}

	if (!pskb_may_pull(skb, offset)) {
		log_debug("Could not 'pull' the headers out of the skb.");
		return breakdown(state, JOOL_MIB_CANNOT_PULL, -EINVAL);
	}

	return 0;
}

static int handle_icmp4(struct xlation *state, struct pkt_metadata *meta)
{
	struct icmphdr buffer, *ptr;
	int error;

	ptr = skb_hdr_ptr(state->in.skb, meta->l4_offset, buffer);
	if (!ptr)
		return truncated(state, "ICMP header");

	if (has_inner_pkt4(ptr->type)) {
		error = validate_inner4(state, meta);
		if (error)
			return error;
	}

	if (state->jool.type == XLATOR_SIIT && is_icmp4_info(ptr->type)
			&& is_fragmented_ipv4(ip_hdr(state->in.skb))) {
		log_debug("Packet is a fragmented ping; its checksum cannot be translated.");
		return breakdown(state, JOOL_MIB_CANNOT_CSUM4, -EINVAL);
	}

	return 0;
}

static int summarize_skb4(struct xlation *state, struct pkt_metadata *meta)
{
	struct sk_buff *skb = state->in.skb;
	struct iphdr *hdr4 = ip_hdr(skb);
	unsigned int offset = skb_network_offset(skb) + (hdr4->ihl << 2);

	meta->has_frag_hdr = false;
	meta->l4_offset = offset;
	meta->payload_offset = offset;

	switch (hdr4->protocol) {
	case IPPROTO_TCP:
		meta->l4_proto = L4PROTO_TCP;
		if (is_first_frag4(hdr4)) {
			struct tcphdr buffer, *ptr;
			ptr = skb_hdr_ptr(skb, offset, buffer);
			if (!ptr)
				return truncated(state, "TCP header");
			meta->payload_offset += tcp_hdr_len(ptr);
		}
		return 0;

	case IPPROTO_UDP:
		meta->l4_proto = L4PROTO_UDP;
		if (is_first_frag4(hdr4))
			meta->payload_offset += sizeof(struct udphdr);
		return 0;

	case IPPROTO_ICMP:
		meta->l4_proto = L4PROTO_ICMP;
		if (is_first_frag4(hdr4))
			meta->payload_offset += sizeof(struct icmphdr);
		return handle_icmp4(state, meta);
	}

	meta->l4_proto = L4PROTO_OTHER;
	return 0;
}

/**
 * As a contract, pkt_destroy() doesn't need to be called if this fails.
 * (Just like other init functions.)
 */
int pkt_init_ipv4(struct xlation *state, struct sk_buff *skb)
{
	struct pkt_metadata meta;
	int error;

	/*
	 * Careful in this function and subfunctions. pskb_may_pull() might
	 * change pointers, so you generally don't want to store them.
	 */

	state->in.skb = skb; /* Prepare prematurely for breakdown(). */

	error = fail_if_shared(skb);
	if (error)
		return breakdown(state, JOOL_MIB_SHARED4, error);

	error = summarize_skb4(state, &meta);
	if (error)
		return error;

	if (!pskb_may_pull(skb, meta.payload_offset)) {
		log_debug("Could not 'pull' the headers out of the skb.");
		return breakdown(state, JOOL_MIB_CANNOT_PULL, -EINVAL);
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

#define SIMPLE_MIN(a, b) ((a < b) ? a : b)

void snapshot_record(struct pkt_snapshot *shot, struct sk_buff *skb)
{
	struct skb_shared_info *shinfo = skb_shinfo(skb);
	unsigned int limit;
	unsigned int i;

	shot->len = skb->len;
	shot->data_len = skb->data_len;
	shot->nr_frags = shinfo->nr_frags;

	limit = SIMPLE_MIN(SNAPSHOT_FRAGS_SIZE, shot->nr_frags);
	for (i = 0; i < limit; i++)
		shot->frags[i] = skb_frag_size(&shinfo->frags[i]);

	/*
	 * Ok so I only have room for SNAPSHOT_FRAGS_SIZE page sizes, unless I
	 * allocate. I don't want to allocate because that's an additional fail
	 * opportunity and I want this to be as unintrusive as possible.
	 *
	 * First of all, since PAGE_SIZE is 4k in my VM, and the typical
	 * Internet MTU is 1500 max, I don't think the packet is going
	 * to have more than one page.
	 *
	 * (Unless IP fragments are being treated as pages, but I don't think
	 * that's the case here because the crashing packet was an ICMP error,
	 * and defrag discards fragmented ICMP errors on reception because they
	 * are BS.)
	 *
	 * Second, even if we get multiple pages, I don't see why would they
	 * have different sizes. Except for the last one, that is.
	 *
	 * (Unless the crashing pages were IP fragments. Again, I don't think
	 * this is the case.)
	 *
	 * Therefore, if the packet has more than SNAPSHOT_FRAGS_SIZE pages,
	 * I'm going to risk it and override the last slottable page size with
	 * the most interesting one. (The last one.)
	 *
	 * Consider that when you're reading the output.
	 */
	if (shot->nr_frags > SNAPSHOT_FRAGS_SIZE) {
		shot->frags[SNAPSHOT_FRAGS_SIZE - 1]
			    = skb_frag_size(&shinfo->frags[shot->nr_frags - 1]);
	}
}

void snapshot_report(struct pkt_snapshot *shot, char *prefix)
{
	unsigned int limit;
	unsigned int i;

	pr_err("%s len: %u\n", prefix, shot->len);
	pr_err("%s data_len: %u\n", prefix, shot->data_len);
	pr_err("%s nr_frags: %u\n", prefix, shot->nr_frags);

	limit = SIMPLE_MIN(SNAPSHOT_FRAGS_SIZE, shot->nr_frags);
	for (i = 0; i < limit; i++)
		pr_err("    %s frag %u: %u\n", prefix, i, shot->frags[i]);
}
