#include "nat64/mod/common/rfc6145/common.h"
#include "nat64/mod/common/config.h"
#include "nat64/mod/common/ipv6_hdr_iterator.h"
#include "nat64/mod/common/packet.h"
#include "nat64/mod/common/stats.h"
#include "nat64/mod/common/rfc6145/4to6.h"
#include "nat64/mod/common/rfc6145/6to4.h"
#include "nat64/mod/stateless/blacklist4.h"
#include <linux/icmp.h>

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
	return copy_payload(state) ? VERDICT_DROP : VERDICT_CONTINUE;
}

static struct translation_steps steps[][L4_PROTO_COUNT] = {
	{ /* IPv6 */
		{
			.skb_create_fn = ttp64_create_skb,
			.l3_hdr_fn = ttp64_ipv4,
			.l3_payload_fn = ttp64_tcp,
		},
		{
			.skb_create_fn = ttp64_create_skb,
			.l3_hdr_fn = ttp64_ipv4,
			.l3_payload_fn = ttp64_udp,
		},
		{
			.skb_create_fn = ttp64_create_skb,
			.l3_hdr_fn = ttp64_ipv4,
			.l3_payload_fn = ttp64_icmp,
		},
		{
			.skb_create_fn = ttp64_create_skb,
			.l3_hdr_fn = ttp64_ipv4,
			.l3_payload_fn = handle_unknown_l4,
		}
	},
	{ /* IPv4 */
		{
			.skb_create_fn = ttp46_create_skb,
			.l3_hdr_fn = ttp46_ipv6,
			.l3_payload_fn = ttp46_tcp,
		},
		{
			.skb_create_fn = ttp46_create_skb,
			.l3_hdr_fn = ttp46_ipv6,
			.l3_payload_fn = ttp46_udp,
		},
		{
			.skb_create_fn = ttp46_create_skb,
			.l3_hdr_fn = ttp46_ipv6,
			.l3_payload_fn = ttp46_icmp,
		},
		{
			.skb_create_fn = ttp46_create_skb,
			.l3_hdr_fn = ttp46_ipv6,
			.l3_payload_fn = handle_unknown_l4,
		}
	}
};

int copy_payload(struct xlation *state)
{
	int error;

	error = skb_copy_bits(state->in.skb, pkt_payload_offset(&state->in),
			pkt_payload(&state->out),
			/*
			 * Note: There's an important reason why the payload
			 * length must be extracted from the outgoing packet:
			 * the outgoing packet might be truncated. See
			 * ttp46_create_skb() and ttp64_create_skb().
			 */
			pkt_payload_len_frag(&state->out));
	if (error)
		log_debug("The payload copy threw errcode %d.", error);

	return error;
}

bool will_need_frag_hdr(const struct iphdr *hdr)
{
	return is_mf_set_ipv4(hdr) || get_fragment_offset_ipv4(hdr);
}

static int move_pointers_in(struct packet *pkt, __u8 protocol,
		unsigned int l3hdr_len)
{
	unsigned int l4hdr_len;

	skb_pull(pkt->skb, pkt_hdrs_len(pkt));
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
	skb_pull(out->skb, pkt_hdrs_len(out));
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

static void backup(struct packet *pkt, struct backup_skb *bkp)
{
	bkp->pulled = pkt_hdrs_len(pkt);
	bkp->offset.l3 = skb_network_offset(pkt->skb);
	bkp->offset.l4 = skb_transport_offset(pkt->skb);
	bkp->payload = pkt_payload(pkt);
	bkp->l4_proto = pkt_l4_proto(pkt);
	if (xlat_is_nat64())
		bkp->tuple = pkt->tuple;
}

static void restore(struct packet *pkt, struct backup_skb *bkp)
{
	skb_push(pkt->skb, bkp->pulled);
	skb_set_network_header(pkt->skb, bkp->offset.l3);
	skb_set_transport_header(pkt->skb, bkp->offset.l4);
	pkt->payload = bkp->payload;
	pkt->l4_proto = bkp->l4_proto;
	pkt->is_inner = 0;
	if (xlat_is_nat64())
		pkt->tuple = bkp->tuple;
}

verdict ttpcomm_translate_inner_packet(struct xlation *state)
{
	struct packet *in = &state->in;
	struct packet *out = &state->out;
	struct backup_skb bkp_in, bkp_out;
	struct translation_steps *current_steps;
	verdict result;

	backup(in, &bkp_in);
	backup(out, &bkp_out);

	switch (pkt_l3_proto(in)) {
	case L3PROTO_IPV4:
		if (move_pointers4(state))
			return VERDICT_DROP;
		break;
	case L3PROTO_IPV6:
		if (move_pointers6(in, out))
			return VERDICT_DROP;
		break;
	default:
		inc_stats(in, IPSTATS_MIB_INUNKNOWNPROTOS);
		return VERDICT_DROP;
	}

	if (xlat_is_nat64()) {
		in->tuple.src = bkp_in.tuple.dst;
		in->tuple.dst = bkp_in.tuple.src;
		out->tuple.src = bkp_out.tuple.dst;
		out->tuple.dst = bkp_out.tuple.src;
	}

	current_steps = &steps[pkt_l3_proto(in)][pkt_l4_proto(in)];

	result = current_steps->l3_hdr_fn(state);
	if (result == VERDICT_ACCEPT) {
		/*
		 * Accepting because of an inner packet doesn't make sense.
		 * Also we couldn't have translated this inner packet.
		 */
		return VERDICT_DROP;
	}
	if (result != VERDICT_CONTINUE)
		return result;

	result = current_steps->l3_payload_fn(state);
	if (result == VERDICT_ACCEPT)
		return VERDICT_DROP;
	if (result != VERDICT_CONTINUE)
		return result;

	restore(in, &bkp_in);
	restore(out, &bkp_out);

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

bool must_not_translate(struct in_addr *addr, struct net *ns)
{
	return addr4_is_scope_subnet(addr->s_addr)
			|| interface_contains(ns, addr);
}
