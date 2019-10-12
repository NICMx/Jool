#include "mod/common/rfc7915/common.h"

#include <linux/icmp.h>

#include "common/config.h"
#include "mod/common/ipv6_hdr_iterator.h"
#include "mod/common/packet.h"
#include "mod/common/stats.h"
#include "mod/common/rfc7915/4to6.h"
#include "mod/common/rfc7915/6to4.h"
#include "mod/common/db/blacklist4.h"

struct backup_skb {
	unsigned int pulled;
	struct {
		int l3;
		int l4;
	} offset;
	void *payload;
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
		},
		{
			.skb_alloc_fn = ttp64_alloc_skb,
			.l3_hdr_fn = ttp64_ipv4,
			.l4_hdr_fn = ttp64_udp,
		},
		{
			.skb_alloc_fn = ttp64_alloc_skb,
			.l3_hdr_fn = ttp64_ipv4,
			.l4_hdr_fn = ttp64_icmp,
		},
		{
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
		},
		{
			.skb_alloc_fn = ttp46_alloc_skb,
			.l3_hdr_fn = ttp46_ipv6,
			.l4_hdr_fn = ttp46_udp,
		},
		{
			.skb_alloc_fn = ttp46_alloc_skb,
			.l3_hdr_fn = ttp46_ipv6,
			.l4_hdr_fn = ttp46_icmp,
		},
		{
			.skb_alloc_fn = ttp46_alloc_skb,
			.l3_hdr_fn = ttp46_ipv6,
			.l4_hdr_fn = handle_unknown_l4,
		}
	}
};

bool will_need_frag_hdr(const struct iphdr *hdr)
{
	return is_mf_set_ipv4(hdr) || get_fragment_offset_ipv4(hdr);
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
	pkt->payload = skb_transport_header(pkt->skb) + l4hdr_len;

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
	out->payload = skb_transport_header(out->skb) + pkt_l4hdr_len(in);

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
	bkp->payload = pkt_payload(pkt);
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
	pkt->payload = bkp->payload;
	pkt->l4_proto = bkp->l4_proto;
	pkt->is_inner = 0;
	if (xlation_is_nat64(state))
		pkt->tuple = bkp->tuple;
	return 0;
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
