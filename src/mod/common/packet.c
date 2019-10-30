#include "mod/common/packet.h"

#include <linux/version.h>
#include <linux/icmp.h>
#include <net/route.h>
#include "common/types.h"
#include "common/config.h"
#include "common/constants.h"
#include "mod/common/icmp_wrapper.h"
#include "mod/common/log.h"
#include "mod/common/stats.h"
#include "mod/common/translation_state.h"

/*
 * Note: Offsets need to be relative to skb->data because that's how
 * skb_header_pointer() works.
 */
struct pkt_metadata {
	/*
	 * Note: The fact that a packet has a fragment header does not imply
	 * that it is fragmented.
	 */
	bool has_frag_hdr;
	/* Offset is from skb->data. Do not use if has_frag_hdr is false. */
	unsigned int frag_offset;
	/* Actual packet protocol; not tuple protocol. */
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

/* It seems that this should never trigger ICMP errors. */
static verdict truncated(struct xlation *state, const char *what)
{
	log_debug("The %s seems truncated.", what);
	return drop(state, JSTAT_SKB_TRUNCATED);
}

static verdict inhdr6(struct xlation *state, const char *msg)
{
	log_debug("%s", msg);
	return drop(state, JSTAT_HDR6);
}

static verdict inhdr4(struct xlation *state, const char *msg)
{
	log_debug("%s", msg);
	return drop(state, JSTAT_HDR4);
}

static void *skb_offset_to_ptr(struct sk_buff *skb, unsigned int offset)
{
	return ((void *) skb->data) + offset;
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
 */
static verdict fail_if_shared(struct xlation *state)
{
	if (WARN(skb_shared(state->in.skb), "The packet is shared!"))
		return drop(state, JSTAT_SKB_SHARED);

	/*
	 * Keep in mind... "shared" and "cloned" are different concepts.
	 * We know the sk_buff struct is unique, but somebody else might have an
	 * active pointer towards the data area.
	 */
	return VERDICT_CONTINUE;
}

/*
 * Jool doesn't like making assumptions, but it certainly needs to make a few.
 * One of them is that the skb_network_offset() offset is meant to be relative
 * to skb->data. Thing is, this should be part of the contract of the function,
 * but I don't see it set in stone anywhere. (Not even in the "How skbs work"
 * guide.)
 *
 * Now, it's pretty obvious that this is the case for all such skbuff.h
 * non-paged offsets at present, but I'm keeping my buttcheeks tight in case
 * they are meant to be relative to a common pivot rather than a specific one.
 */
static verdict fail_if_broken_offset(struct xlation *state)
{
	struct sk_buff *skb = state->in.skb;

	if (WARN(skb_network_offset(skb) != (skb_network_header(skb) - skb->data),
			"The packet's network header offset is not relative to skb->data.\n"
			"Translating this packet would break Jool, so dropping."))
		return drop(state, JSTAT_L3HDR_OFFSET);

	return VERDICT_CONTINUE;
}

static verdict paranoid_validations(struct xlation *state, size_t min_hdr_size)
{
	verdict result;

	result = fail_if_shared(state);
	if (result != VERDICT_CONTINUE)
		return result;
	result = fail_if_broken_offset(state);
	if (result != VERDICT_CONTINUE)
		return result;
	if (!pskb_may_pull(state->in.skb, min_hdr_size))
		return truncated(state, "basic IP header");

	return VERDICT_CONTINUE;
}

/**
 * Walks through @skb's headers, collecting data and adding it to @meta.
 *
 * @hdr6_offset number of bytes between skb->data and the IPv6 header.
 *
 * BTW: You might want to read summarize_skb4() first, since it's a lot simpler.
 */
static verdict summarize_skb6(struct xlation *state,
		unsigned int hdr6_offset,
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
		u8 *nexthdr;
	} ptr;

	struct sk_buff *skb = state->in.skb;
	u8 nexthdr;
	unsigned int offset;
	bool is_first = true;

	ptr.nexthdr = skb_hdr_ptr(skb,
			hdr6_offset + offsetof(struct ipv6hdr, nexthdr),
			nexthdr);
	if (!ptr.nexthdr)
		return truncated(state, "IPv6 header");
	nexthdr = *ptr.nexthdr;
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

			return VERDICT_CONTINUE;

		case NEXTHDR_UDP:
			meta->l4_proto = L4PROTO_UDP;
			meta->l4_offset = offset;
			meta->payload_offset = is_first
					? (offset + sizeof(struct udphdr))
					: offset;
			return VERDICT_CONTINUE;

		case NEXTHDR_ICMP:
			meta->l4_proto = L4PROTO_ICMP;
			meta->l4_offset = offset;
			meta->payload_offset = is_first
					? (offset + sizeof(struct icmp6hdr))
					: offset;
			return VERDICT_CONTINUE;

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
			if (ptr.frag) {
				log_debug("There's a known extension header (%u) after Fragment.",
						nexthdr);
				return drop(state, JSTAT64_FRAG_THEN_EXT);
			}

			ptr.opt = skb_hdr_ptr(skb, offset, buffer.opt);
			if (!ptr.opt)
				return truncated(state, "extension header");

			offset += ipv6_optlen(ptr.opt);
			nexthdr = ptr.opt->nexthdr;
			break;

		default:
			meta->l4_proto = L4PROTO_OTHER;
			meta->l4_offset = offset;
			meta->payload_offset = offset;
			return VERDICT_CONTINUE;
		}
	} while (true);

	return VERDICT_CONTINUE; /* whatever. */
}

static verdict validate_inner6(struct xlation *state,
		struct pkt_metadata const *outer_meta)
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

	struct pkt_metadata meta;
	verdict result;

	ptr.ip6 = skb_hdr_ptr(state->in.skb, outer_meta->payload_offset,
			buffer.ip6);
	if (!ptr.ip6)
		return truncated(state, "inner IPv6 header");
	if (unlikely(ptr.ip6->version != 6))
		return inhdr6(state, "Version is not 6.");

	result = summarize_skb6(state, outer_meta->payload_offset, &meta);
	if (result != VERDICT_CONTINUE)
		return result;

	if (meta.has_frag_hdr) {
		ptr.frag = skb_hdr_ptr(state->in.skb, meta.frag_offset,
				buffer.frag);
		if (!ptr.frag)
			return truncated(state, "inner fragment header");
		if (!is_first_frag6(ptr.frag))
			return inhdr6(state, "Inner packet is not a first fragment.");
	}

	if (meta.l4_proto == L4PROTO_ICMP) {
		ptr.icmp = skb_hdr_ptr(state->in.skb, meta.l4_offset,
				buffer.icmp);
		if (!ptr.icmp)
			return truncated(state, "inner ICMPv6 header");
		if (has_inner_pkt6(ptr.icmp->icmp6_type))
			return inhdr6(state, "Packet inside packet inside packet.");
	}

	if (!pskb_may_pull(state->in.skb, meta.payload_offset)) {
		log_debug("Could not 'pull' the headers out of the skb.");
		return truncated(state, "inner headers");
	}

	return VERDICT_CONTINUE;
}

static verdict handle_icmp6(struct xlation *state, struct pkt_metadata const *meta)
{
	union {
		struct icmp6hdr icmp;
		struct frag_hdr frag;
	} buffer;
	union {
		struct icmp6hdr *icmp;
		struct frag_hdr *frag;
	} ptr;
	verdict result;

	ptr.icmp = skb_hdr_ptr(state->in.skb, meta->l4_offset, buffer.icmp);
	if (!ptr.icmp)
		return truncated(state, "ICMPv6 header");

	if (has_inner_pkt6(ptr.icmp->icmp6_type)) {
		result = validate_inner6(state, meta);
		if (result != VERDICT_CONTINUE)
			return result;
	}

	if (xlation_is_siit(state)
			&& meta->has_frag_hdr
			&& is_icmp6_info(ptr.icmp->icmp6_type)) {
		ptr.frag = skb_hdr_ptr(state->in.skb, meta->frag_offset, buffer.frag);
		if (!ptr.frag)
			return truncated(state, "fragment header");
		if (is_fragmented_ipv6(ptr.frag)) {
			log_debug("Packet is a fragmented ping; its checksum cannot be translated.");
			return drop(state, JSTAT_FRAGMENTED_PING);
		}
	}

	return VERDICT_CONTINUE;
}

verdict pkt_init_ipv6(struct xlation *state, struct sk_buff *skb)
{
	struct pkt_metadata meta;
	verdict result;

	state->in.skb = skb;

	/*
	 * DO NOT, UNDER ANY CIRCUMSTANCES, EXTRACT ANY BYTES FROM THE SKB'S
	 * DATA AREA DIRECTLY (ie. without using skb_hdr_ptr()) UNTIL YOU KNOW
	 * IT HAS ALREADY BEEN pskb_may_pull()ED. ASSUME THAT EVEN THE MAIN
	 * LAYER 3 HEADER CAN BE PAGED.
	 *
	 * Also, careful in this function and subfunctions. pskb_may_pull()
	 * might change pointers, so you generally don't want to store them.
	 */

	result = paranoid_validations(state, sizeof(struct ipv6hdr));
	if (result != VERDICT_CONTINUE)
		return result;

	log_debug("Packet addresses: %pI6c->%pI6c",
			&ipv6_hdr(skb)->saddr,
			&ipv6_hdr(skb)->daddr);

	if (skb->len != get_tot_len_ipv6(skb))
		return inhdr6(state, "Packet size doesn't match the IPv6 header's payload length field.");

	result = summarize_skb6(state, skb_network_offset(skb), &meta);
	if (result != VERDICT_CONTINUE)
		return result;

	if (meta.l4_proto == L4PROTO_ICMP) {
		/* Do not move this to summarize_skb6(), because it risks infinite recursion. */
		result = handle_icmp6(state, &meta);
		if (result != VERDICT_CONTINUE)
			return result;
	}

	if (!pskb_may_pull(skb, meta.payload_offset))
		return truncated(state, "headers");

	state->in.l3_proto = L3PROTO_IPV6;
	state->in.l4_proto = meta.l4_proto;
	state->in.is_inner = 0;
	state->in.is_hairpin = false;
	state->in.hdr_frag = meta.has_frag_hdr
			? skb_offset_to_ptr(skb, meta.frag_offset)
			: NULL;
	skb_set_transport_header(skb, meta.l4_offset);
	state->in.payload = skb_offset_to_ptr(skb, meta.payload_offset);
	state->in.original_pkt = &state->in;

	return VERDICT_CONTINUE;
}

static verdict validate_inner4(struct xlation *state, struct pkt_metadata *meta)
{
	union {
		struct iphdr ip4;
		struct tcphdr tcp;
	} buffer;
	union {
		struct iphdr *ip4;
		struct tcphdr *tcp;
	} ptr;
	unsigned int ihl;
	unsigned int offset = meta->payload_offset;

	ptr.ip4 = skb_hdr_ptr(state->in.skb, offset, buffer.ip4);
	if (!ptr.ip4)
		return truncated(state, "inner IPv4 header");

	ihl = ptr.ip4->ihl << 2;
	if (ptr.ip4->version != 4)
		return inhdr4(state, "Inner packet is not IPv4.");
	if (ihl < 20)
		return inhdr4(state, "Inner packet's IHL is bogus.");
	if (ntohs(ptr.ip4->tot_len) < ihl)
		return inhdr4(state, "Inner packet's total length is bogus.");
	if (!is_first_frag4(ptr.ip4))
		return inhdr4(state, "Inner packet is not first fragment.");

	offset += ihl;

	switch (ptr.ip4->protocol) {
	case IPPROTO_TCP:
		ptr.tcp = skb_hdr_ptr(state->in.skb, offset, buffer.tcp);
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

	if (!pskb_may_pull(state->in.skb, offset))
		return truncated(state, "inner headers");

	return VERDICT_CONTINUE;
}

static verdict handle_icmp4(struct xlation *state, struct pkt_metadata *meta)
{
	struct icmphdr buffer, *ptr;
	verdict result;

	ptr = skb_hdr_ptr(state->in.skb, meta->l4_offset, buffer);
	if (!ptr)
		return truncated(state, "ICMP header");

	if (has_inner_pkt4(ptr->type)) {
		result = validate_inner4(state, meta);
		if (result != VERDICT_CONTINUE)
			return result;
	}

	if (xlation_is_siit(state)
			&& is_icmp4_info(ptr->type)
			&& is_fragmented_ipv4(ip_hdr(state->in.skb))) {
		log_debug("Packet is a fragmented ping; its checksum cannot be translated.");
		return drop(state, JSTAT_FRAGMENTED_PING);
	}

	return VERDICT_CONTINUE;
}

static verdict summarize_skb4(struct xlation *state, struct pkt_metadata *meta)
{
	struct iphdr *hdr4 = ip_hdr(state->in.skb);
	unsigned int offset;

	hdr4 = ip_hdr(state->in.skb);
	offset = skb_network_offset(state->in.skb) + (hdr4->ihl << 2);

	meta->has_frag_hdr = false;
	meta->l4_offset = offset;
	meta->payload_offset = offset;

	switch (hdr4->protocol) {
	case IPPROTO_TCP:
		meta->l4_proto = L4PROTO_TCP;
		if (is_first_frag4(hdr4)) {
			struct tcphdr buffer, *ptr;
			ptr = skb_hdr_ptr(state->in.skb, offset, buffer);
			if (!ptr)
				return truncated(state, "TCP header");
			meta->payload_offset += tcp_hdr_len(ptr);
		}
		return VERDICT_CONTINUE;

	case IPPROTO_UDP:
		meta->l4_proto = L4PROTO_UDP;
		if (is_first_frag4(hdr4))
			meta->payload_offset += sizeof(struct udphdr);
		return VERDICT_CONTINUE;

	case IPPROTO_ICMP:
		meta->l4_proto = L4PROTO_ICMP;
		if (is_first_frag4(hdr4))
			meta->payload_offset += sizeof(struct icmphdr);
		return handle_icmp4(state, meta);
	}

	meta->l4_proto = L4PROTO_OTHER;
	return VERDICT_CONTINUE;
}

verdict pkt_init_ipv4(struct xlation *state, struct sk_buff *skb)
{
	struct pkt_metadata meta;
	verdict result;

	state->in.skb = skb;

	/*
	 * DO NOT, UNDER ANY CIRCUMSTANCES, EXTRACT ANY BYTES FROM THE SKB'S
	 * DATA AREA DIRECTLY (ie. without using skb_hdr_ptr()) UNTIL YOU KNOW
	 * IT HAS ALREADY BEEN pskb_may_pull()ED. ASSUME THAT EVEN THE MAIN
	 * LAYER 3 HEADER CAN BE PAGED.
	 *
	 * Also, careful in this function and subfunctions. pskb_may_pull()
	 * might change pointers, so you generally don't want to store them.
	 */

	result = paranoid_validations(state, sizeof(struct iphdr));
	if (result != VERDICT_CONTINUE)
		return result;

	log_debug("Packet addresses: %pI4->%pI4",
			&ip_hdr(skb)->saddr,
			&ip_hdr(skb)->daddr);

	result = summarize_skb4(state, &meta);
	if (result != VERDICT_CONTINUE)
		return result;

	if (!pskb_may_pull(skb, meta.payload_offset)) {
		log_debug("Could not 'pull' the headers out of the skb.");
		return truncated(state, "headers");
	}

	state->in.l3_proto = L3PROTO_IPV4;
	state->in.l4_proto = meta.l4_proto;
	state->in.is_inner = false;
	state->in.is_hairpin = false;
	state->in.hdr_frag = NULL;
	skb_set_transport_header(skb, meta.l4_offset);
	state->in.payload = skb_offset_to_ptr(skb, meta.payload_offset);
	state->in.original_pkt = &state->in;

	return VERDICT_CONTINUE;
}

/**
 * skb_pull() is oddly special in that it can return NULL in a situation where
 * most skb functions would just panic. Which is actually great for skb_pull();
 * the kernel good practices thingy rightfully states that we should always
 * respond to such situations gracefully instead of BUG()ging out like a bunch
 * of wusses.
 *
 * These situations should not arise, however, so we should treat them as
 * programming errors. (WARN, cancel the packet's translation and then continue
 * normally.)
 *
 * This function takes care of the WARN clutter. "j" stands for "Jool", as
 * usual.
 *
 * Never use skb_pull() directly.
 */
unsigned char *jskb_pull(struct sk_buff *skb, unsigned int len)
{
	unsigned char *result = skb_pull(skb, len);
	WARN(!result, "Bug: We tried to pull %u bytes out of a %u-length skb.",
			len, skb->len);
	return result;
}

/**
 * skb_push() cannot return NULL at present, but maybe someday will.
 */
unsigned char *jskb_push(struct sk_buff *skb, unsigned int len)
{
	unsigned char *result = skb_push(skb, len);
	WARN(!result, "Bug: skb_push() returned NULL (skblen:%u len:%u).",
			skb->len, len);
	return result;
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
