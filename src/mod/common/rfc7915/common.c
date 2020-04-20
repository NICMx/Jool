#include "mod/common/rfc7915/common.h"

#include <linux/icmp.h>

#include "common/config.h"
#include "mod/common/ipv6_hdr_iterator.h"
#include "mod/common/log.h"
#include "mod/common/packet.h"
#include "mod/common/stats.h"
#include "mod/common/rfc7915/4to6.h"
#include "mod/common/rfc7915/6to4.h"
#include "mod/common/db/blacklist4.h"
#include "mod/common/steps/compute_outgoing_tuple.h"

struct backup_skb {
	unsigned int pulled;
	struct {
		int l3;
		int l4;
	} offset;
	unsigned int payload;
	l4_protocol l4_proto;
	struct tuple tuple;
};

static verdict handle_unknown_l4(struct xlation *state)
{
	return VERDICT_CONTINUE;
}

static struct translation_steps steps[][L4_PROTO_COUNT] = {
	{ /* IPv6 */
		{
			.skb_alloc_fn = ttp64_alloc_skb,
			.l3_hdr_fn = ttp64_ipv4,
			.l4_hdr_fn = ttp64_tcp,
		}, {
			.skb_alloc_fn = ttp64_alloc_skb,
			.l3_hdr_fn = ttp64_ipv4,
			.l4_hdr_fn = ttp64_udp,
		}, {
			.skb_alloc_fn = ttp64_alloc_skb,
			.l3_hdr_fn = ttp64_ipv4,
			.l4_hdr_fn = ttp64_icmp,
		}, {
			.skb_alloc_fn = ttp64_alloc_skb,
			.l3_hdr_fn = ttp64_ipv4,
			.l4_hdr_fn = handle_unknown_l4,
		}
	},
	{ /* IPv4 */
		{
			.skb_alloc_fn = ttp46_alloc_skb,
			.l3_hdr_fn = ttp46_ipv6,
			.l4_hdr_fn = ttp46_tcp,
		}, {
			.skb_alloc_fn = ttp46_alloc_skb,
			.l3_hdr_fn = ttp46_ipv6,
			.l4_hdr_fn = ttp46_udp,
		}, {
			.skb_alloc_fn = ttp46_alloc_skb,
			.l3_hdr_fn = ttp46_ipv6,
			.l4_hdr_fn = ttp46_icmp,
		}, {
			.skb_alloc_fn = ttp46_alloc_skb,
			.l3_hdr_fn = ttp46_ipv6,
			.l4_hdr_fn = handle_unknown_l4,
		}
	}
};

/**
 * RFC 7915:
 * "When the IPv4 sender does not set the DF bit, the translator MUST NOT
 * include the Fragment Header for the non-fragmented IPv6 packets."
 *
 * Very strange wording. I believe that DF enabled also implies no fragmentation
 * (as everyone seems to assume no one generates DF-enabled fragments), which,
 * stacked with the general direction of the atomic fragments deprecation
 * effort, I think what it actually means is
 *
 * The translator MUST NOT include the Fragment Header for non-fragmented IPv6
 * packets. (Obviously, if the packet is fragmented, the fragment header MUST
 * be included.)
 *
 * (i.e. The translator must include the Fragment header if, and only if, the
 * packet is fragmented.)
 *
 * The following quote also supports this logic:
 * "If there is a need to add a Fragment Header (the packet is a fragment
 * or the DF bit is not set and the packet size is greater than the
 * minimum IPv6 MTU (...)),"
 *
 * So that's why I implemented it this way.
 */
bool will_need_frag_hdr(const struct iphdr *hdr)
{
	return is_fragmented_ipv4(hdr);
}

static int report_bug247(struct packet *pkt, __u8 proto)
{
	struct sk_buff *skb = pkt->skb;
	struct skb_shared_info *shinfo = skb_shinfo(skb);
	unsigned int i;
	unsigned char *pos;

	pr_err("----- JOOL OUTPUT -----\n");
	pr_err("Bug #247 happened!\n");

	pr_err("xlator: " JOOL_VERSION_STR);
	pr_err("Page size: %lu\n", PAGE_SIZE);
	pr_err("Page shift: %u\n", PAGE_SHIFT);
	pr_err("protocols: %u %u %u\n", pkt->l3_proto, pkt->l4_proto, proto);

	snapshot_report(&pkt->debug.shot1, "initial");
	snapshot_report(&pkt->debug.shot2, "mid");

	pr_err("current len: %u\n", skb->len);
	pr_err("current data_len: %u\n", skb->data_len);
	pr_err("current nr_frags: %u\n", shinfo->nr_frags);
	for (i = 0; i < shinfo->nr_frags; i++) {
		pr_err("    current frag %u: %u\n", i,
				skb_frag_size(&shinfo->frags[i]));
	}

	pr_err("skb head:%p data:%p tail:%p end:%p\n",
			skb->head, skb->data,
			skb_tail_pointer(skb),
			skb_end_pointer(skb));
	pr_err("skb l3-hdr:%p l4-hdr:%p payload:%p\n",
			skb_network_header(skb),
			skb_transport_header(skb),
			pkt_payload(pkt));

	pr_err("packet content: ");
	for (pos = skb->head; pos < skb_end_pointer(skb); pos++)
		pr_cont("%x ", *pos);
	pr_cont("\n");

	pr_err("Dropping packet.\n");
	pr_err("-----------------------\n");
	return -EINVAL;
}

static int move_pointers_in(struct packet *pkt, __u8 protocol,
		unsigned int l3hdr_len)
{
	unsigned int l4hdr_len;

	if (unlikely(pkt->skb->len - pkt_hdrs_len(pkt) < pkt->skb->data_len))
		return report_bug247(pkt, protocol);

	if (!jskb_pull(pkt->skb, pkt_hdrs_len(pkt)))
		return -EINVAL;
	skb_reset_network_header(pkt->skb);
	skb_set_transport_header(pkt->skb, l3hdr_len);

	switch (protocol) {
	case IPPROTO_TCP:
		pkt->l4_proto = L4PROTO_TCP;
		l4hdr_len = tcp_hdr_len(pkt_tcp_hdr(pkt));
		break;
	case IPPROTO_UDP:
		pkt->l4_proto = L4PROTO_UDP;
		l4hdr_len = sizeof(struct udphdr);
		break;
	case IPPROTO_ICMP:
	case NEXTHDR_ICMP:
		pkt->l4_proto = L4PROTO_ICMP;
		l4hdr_len = sizeof(struct icmphdr);
		break;
	default:
		pkt->l4_proto = L4PROTO_OTHER;
		l4hdr_len = 0;
		break;
	}
	pkt->is_inner = true;
	pkt->payload_offset = skb_transport_offset(pkt->skb) + l4hdr_len;

	return 0;
}

static int move_pointers_out(struct packet *in, struct packet *out,
		unsigned int l3hdr_len)
{
	if (!jskb_pull(out->skb, pkt_hdrs_len(out)))
		return -EINVAL;
	skb_reset_network_header(out->skb);
	skb_set_transport_header(out->skb, l3hdr_len);

	out->l4_proto = pkt_l4_proto(in);
	out->is_inner = true;
	out->payload_offset = skb_transport_offset(out->skb)
			+ pkt_l4hdr_len(in);

	return 0;
}

static int move_pointers4(struct xlation *state)
{
	struct iphdr *hdr4;
	unsigned int l3hdr_len;
	int error;

	hdr4 = pkt_payload(&state->in);
	error = move_pointers_in(&state->in, hdr4->protocol, 4 * hdr4->ihl);
	if (error)
		return error;

	l3hdr_len = sizeof(struct ipv6hdr);
	if (will_need_frag_hdr(hdr4))
		l3hdr_len += sizeof(struct frag_hdr);
	return move_pointers_out(&state->in, &state->out, l3hdr_len);
}

static int move_pointers6(struct packet *in, struct packet *out)
{
	struct ipv6hdr *hdr6 = pkt_payload(in);
	struct hdr_iterator iterator = HDR_ITERATOR_INIT(hdr6);
	int error;

	hdr_iterator_last(&iterator);

	error = move_pointers_in(in, iterator.hdr_type,
			iterator.data - (void *)hdr6);
	if (error)
		return error;

	return move_pointers_out(in, out, sizeof(struct iphdr));
}

static void backup(struct xlation *state, struct packet *pkt,
		struct backup_skb *bkp)
{
	bkp->pulled = pkt_hdrs_len(pkt);
	bkp->offset.l3 = skb_network_offset(pkt->skb);
	bkp->offset.l4 = skb_transport_offset(pkt->skb);
	bkp->payload = pkt->payload_offset;
	bkp->l4_proto = pkt_l4_proto(pkt);
	if (xlation_is_nat64(state))
		bkp->tuple = pkt->tuple;
}

static int restore(struct xlation *state, struct packet *pkt,
		struct backup_skb *bkp)
{
	if (!jskb_push(pkt->skb, bkp->pulled))
		return -EINVAL;
	skb_set_network_header(pkt->skb, bkp->offset.l3);
	skb_set_transport_header(pkt->skb, bkp->offset.l4);
	pkt->payload_offset = bkp->payload;
	pkt->l4_proto = bkp->l4_proto;
	pkt->is_inner = 0;
	if (xlation_is_nat64(state))
		pkt->tuple = bkp->tuple;
	return 0;
}

static verdict xlat_inner_addresses(struct xlation *state)
{
	union {
		struct ipv6hdr *v6;
		struct iphdr *v4;
	} hdr;
	verdict result;

	switch (pkt_l3_proto(&state->in)) {
	case L3PROTO_IPV4: /* 4 -> 6 */
		if (xlation_is_siit(state)) {
			result = translate_addrs46_siit(state);
			if (result != VERDICT_CONTINUE)
				return result;
		}

		hdr.v6 = pkt_ip6_hdr(&state->out);
		hdr.v6->saddr = state->out.tuple.src.addr6.l3;
		hdr.v6->daddr = state->out.tuple.dst.addr6.l3;
		break;

	case L3PROTO_IPV6: /* 6 -> 4 */
		if (xlation_is_siit(state)) {
			result = translate_addrs64_siit(state);
			if (result != VERDICT_CONTINUE)
				return result;
		}

		hdr.v4 = pkt_ip4_hdr(&state->out);
		hdr.v4->saddr = state->out.tuple.src.addr4.l3.s_addr;
		hdr.v4->daddr = state->out.tuple.dst.addr4.l3.s_addr;
		break;

	}

	return VERDICT_CONTINUE;
}

verdict ttpcomm_translate_inner_packet(struct xlation *state)
{
	struct packet *in = &state->in;
	struct packet *out = &state->out;
	struct backup_skb bkp_in, bkp_out;
	struct translation_steps *current_steps;
	verdict result;

	backup(state, in, &bkp_in);
	backup(state, out, &bkp_out);

	switch (pkt_l3_proto(in)) {
	case L3PROTO_IPV4:
		if (move_pointers4(state))
			return drop(state, JSTAT_UNKNOWN);
		break;
	case L3PROTO_IPV6:
		if (move_pointers6(in, out))
			return drop(state, JSTAT_UNKNOWN);
		break;
	}

	if (xlation_is_nat64(state)) {
		in->tuple.src = bkp_in.tuple.dst;
		in->tuple.dst = bkp_in.tuple.src;
		out->tuple.src = bkp_out.tuple.dst;
		out->tuple.dst = bkp_out.tuple.src;
	}

	result = xlat_inner_addresses(state);
	if (result != VERDICT_CONTINUE)
		return result;

	current_steps = &steps[pkt_l3_proto(in)][pkt_l4_proto(in)];

	result = current_steps->l3_hdr_fn(state);
	if (result == VERDICT_UNTRANSLATABLE) {
		/*
		 * Accepting because of an inner packet doesn't make sense.
		 * Also we couldn't have translated this inner packet.
		 */
		return VERDICT_DROP;
	}
	if (result != VERDICT_CONTINUE)
		return result;

	result = current_steps->l4_hdr_fn(state);
	if (result == VERDICT_UNTRANSLATABLE)
		return VERDICT_DROP;
	if (result != VERDICT_CONTINUE)
		return result;

	if (restore(state, in, &bkp_in))
		return drop(state, JSTAT_UNKNOWN);
	if (restore(state, out, &bkp_out))
		return drop(state, JSTAT_UNKNOWN);

	return VERDICT_CONTINUE;
}

struct translation_steps *ttpcomm_get_steps(struct packet *in)
{
	return &steps[pkt_l3_proto(in)][pkt_l4_proto(in)];
}

/**
 * partialize_skb - set up @out_skb so the layer 4 checksum will be computed
 * from almost-scratch by the OS or by the NIC later.
 * @csum_offset: The checksum field's offset within its header.
 *
 * When the incoming skb's ip_summed field is NONE, UNNECESSARY or COMPLETE,
 * the checksum is defined, in the sense that its correctness consistently
 * dictates whether the packet is corrupted or not. In these cases, Jool is
 * supposed to update the checksum with the translation changes (pseudoheader
 * and transport header) and forget about it. The incoming packet's corruption
 * will still be reflected in the outgoing packet's checksum.
 *
 * On the other hand, when the incoming skb's ip_summed field is PARTIAL,
 * the existing checksum only covers the pseudoheader (which Jool replaces).
 * In these cases, fully updating the checksum is wrong because it doesn't
 * already cover the transport header, and fully computing it again is wasted
 * time because this work can be deferred to the NIC (which'll likely do it
 * faster).
 *
 * The correct thing to do is convert the partial (pseudoheader-only) checksum
 * into a translated-partial (pseudoheader-only) checksum, and set up some skb
 * fields so the NIC can do its thing.
 *
 * This function handles the skb fields setting part.
 */
void partialize_skb(struct sk_buff *out_skb, unsigned int csum_offset)
{
	out_skb->ip_summed = CHECKSUM_PARTIAL;
	out_skb->csum_start = skb_transport_header(out_skb) - out_skb->head;
	out_skb->csum_offset = csum_offset;
}

static verdict fix_ie(struct xlation *state, size_t in_ie_offset,
		size_t ipl, size_t pad, size_t iel)
{
	struct sk_buff *skb_old;
	struct sk_buff *skb_new;
	unsigned int ohl; /* Outer Headers Length */
	void *beginning;
	void *to;
	int offset;
	int len;
	int error;

	skb_old = state->out.skb;
	ohl = pkt_hdrs_len(&state->out);
	len = ohl + ipl + pad + iel;
	skb_new = alloc_skb(LL_MAX_HEADER + len, GFP_ATOMIC);
	if (!skb_new)
		return drop(state, JSTAT_ENOMEM);

	skb_reserve(skb_new, LL_MAX_HEADER);
	beginning = skb_put(skb_new, len);
	skb_reset_mac_header(skb_new);
	skb_reset_network_header(skb_new);
	skb_set_transport_header(skb_new, skb_transport_offset(skb_old));

	offset = skb_network_offset(skb_old);
	to = beginning;
	len = ohl;
	error = skb_copy_bits(skb_old, offset, to, len);
	if (error)
		goto copy_fail;

	offset += len;
	to += len; /* alloc_skb() always creates linear packets. */
	len = ipl;
	error = skb_copy_bits(skb_old, offset, to, len);
	if (error)
		goto copy_fail;

	if (iel) {
		to += len;
		len = pad;
		memset(to, 0, len);

		offset = in_ie_offset;
		to += len;
		len = iel;
		error = skb_copy_bits(state->in.skb, offset, to, len);
		if (error)
			goto copy_fail;
	}

	skb_dst_set(skb_new, dst_clone(skb_dst(skb_old)));
	kfree_skb(skb_old);
	state->out.skb = skb_new;
	return VERDICT_CONTINUE;

copy_fail:
	log_debug("skb_copy_bits(skb, %d, %zd, %d) threw error %d.", offset,
			to - beginning, len, error);
	return drop(state, JSTAT_UNKNOWN);
}

/**
 * "Handle the ICMP Extension" in this context means
 *
 * - Make sure it aligns in accordance with the target protocol's ICMP length
 *   field. (32 bits in IPv4, 64 bits in IPv6)
 * - Make sure it fits in the packet in accordance with the target protocol's
 *   official maximum ICMP error size. (576 for IPv4, 1280 for IPv6)
 * 	- If it doesn't fit, remove it completely.
 * 	- If it does fit, trim the Optional Part if needed.
 * - Add padding to the internal packet if necessary.
 *
 * Again, see /test/graybox/test-suite/rfc/7915.md#ic.
 *
 * "Handle the ICMP Extension" does NOT mean:
 *
 * - Translate the contents. (Jool treats extensions like opaque bit strings.)
 * - Update outer packet's L3 checksums and lengths. (Too difficult to do here;
 *   caller's responsibility.) This includes the ICMP header length.
 *
 * If this function succeeds, it will return the value of the ICMP header length
 * in args->ipl.
 */
verdict handle_icmp_extension(struct xlation *state,
		struct icmpext_args *args)
{
	struct packet *in;
	struct packet *out;
	size_t payload_len; /* Incoming packet's payload length */
	size_t in_iel; /* Incoming packet's IE length */
	size_t max_iel; /* Maximum outgoing packet's allowable IE length */
	size_t in_ieo; /* Incoming packet's IE offset */
	size_t out_ipl; /* Outgoing packet's internal packet length */
	size_t out_pad; /* Outgoing packet's padding length */
	size_t out_iel; /* Outgoing packet's IE length */

	in = &state->in;
	out = &state->out;

	/* Validate input */
	if (args->ipl == 0)
		return VERDICT_CONTINUE;
	if (args->ipl < 128) {
		log_debug("Illegal internal packet length (%zu < 128)",
				args->ipl);
		return drop(state, JSTAT_ICMPEXT_SMALL);
	}

	payload_len = in->skb->len - pkt_hdrs_len(in);
	if (args->ipl == payload_len) {
		args->ipl = 0;
		return VERDICT_CONTINUE; /* Whatever, I guess */
	}
	if (args->ipl > payload_len) {
		log_debug("ICMP Length %zu > L3 payload %zu", args->ipl,
				payload_len);
		return drop(state, JSTAT_ICMPEXT_BIG);
	}

	/* Compute helpers */
	in_ieo = pkt_hdrs_len(in) + args->ipl;
	in_iel = in->skb->len - in_ieo;
	max_iel = args->max_pkt_len - (pkt_hdrs_len(out) + 128);

	/* Figure out what we want to do */
	/* (Assumption: In packet's iel equals current out packet's iel) */
	if (args->force_remove_ie || (in_iel > max_iel)) {
		out_ipl = min(out->skb->len - in_iel, args->max_pkt_len)
				- pkt_hdrs_len(out);
		out_pad = (out_ipl < 128) ? (128 - out_ipl) : 0;
		out_iel = 0;
		args->ipl = 0;
	} else {
		out_ipl = min((size_t)out->skb->len, args->max_pkt_len) - in_iel
				- pkt_hdrs_len(out);
		out_ipl &= (~(size_t)0) << args->out_bits;
		out_pad = (out_ipl < 128) ? (128 - out_ipl) : 0;
		out_iel = in_iel;
		args->ipl = (out_ipl + out_pad) >> args->out_bits;
	}

	/* Move everything around */
	return fix_ie(state, skb_network_offset(in->skb) + in_ieo, out_ipl,
			out_pad, out_iel);
}
