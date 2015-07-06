#include "nat64/mod/common/rfc6145/common.h"
#include "nat64/mod/common/config.h"
#include "nat64/mod/common/ipv6_hdr_iterator.h"
#include "nat64/mod/common/packet.h"
#include "nat64/mod/common/stats.h"
#include "nat64/mod/common/rfc6145/4to6.h"
#include "nat64/mod/common/rfc6145/6to4.h"
#include <linux/icmp.h>

struct backup_skb {
	unsigned int pulled;
	struct {
		int l3;
		int l4;
	} offset;
	void *payload;
	l4_protocol l4_proto;
};

static verdict handle_unknown_l4(struct tuple *out_tuple, struct packet *in, struct packet *out)
{
	return copy_payload(in, out) ? VERDICT_DROP : VERDICT_CONTINUE;
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

int copy_payload(struct packet *in, struct packet *out)
{
	int error;

	error = skb_copy_bits(in->skb, pkt_payload_offset(in), pkt_payload(out),
			pkt_payload_len_frag(out));
	if (error)
		log_debug("The payload copy threw errcode %d.", error);

	return error;
}

static bool build_ipv6_frag_hdr(struct iphdr *in_hdr)
{
	if (is_dont_fragment_set(in_hdr))
		return false;

	return config_get_build_ipv6_fh();
}

bool will_need_frag_hdr(struct iphdr *in_hdr)
{
	/*
	 * Note, build_ipv6_frag_hdr(in_hdr) should remain disabled.
	 * See www.jool.mx/usr-flags-atomic.html.
	 * (if that's down, try doc/usr/usr-flags-atomic.md in Jool's source.)
	 */
	return build_ipv6_frag_hdr(in_hdr) || is_more_fragments_set_ipv4(in_hdr)
			|| get_fragment_offset_ipv4(in_hdr);
}

static int move_pointers_in(struct packet *pkt, __u8 protocol, unsigned int l3hdr_len)
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
	pkt->is_inner = 1;
	pkt->payload = skb_transport_header(pkt->skb) + l4hdr_len;

	return 0;
}

static int move_pointers_out(struct packet *in, struct packet *out, unsigned int l3hdr_len)
{
	skb_pull(out->skb, pkt_hdrs_len(out));
	skb_reset_network_header(out->skb);
	skb_set_transport_header(out->skb, l3hdr_len);

	out->l4_proto = pkt_l4_proto(in);
	out->is_inner = 1;
	out->payload = skb_transport_header(out->skb) + pkt_l4hdr_len(in);

	return 0;
}

static int move_pointers4(struct packet *in, struct packet *out)
{
	struct iphdr *hdr4;
	unsigned int l3hdr_len;
	int error;

	hdr4 = pkt_payload(in);
	error = move_pointers_in(in, hdr4->protocol, 4 * hdr4->ihl);
	if (error)
		return error;

	l3hdr_len = sizeof(struct ipv6hdr);
	if (will_need_frag_hdr(hdr4))
		l3hdr_len += sizeof(struct frag_hdr);
	return move_pointers_out(in, out, l3hdr_len);
}

static int move_pointers6(struct packet *in, struct packet *out)
{
	struct ipv6hdr *hdr6 = pkt_payload(in);
	struct hdr_iterator iterator = HDR_ITERATOR_INIT(hdr6);
	int error;

	hdr_iterator_last(&iterator);

	error = move_pointers_in(in, iterator.hdr_type, iterator.data - (void *) hdr6);
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
}

static void restore(struct packet *pkt, struct backup_skb *bkp)
{
	skb_push(pkt->skb, bkp->pulled);
	skb_set_network_header(pkt->skb, bkp->offset.l3);
	skb_set_transport_header(pkt->skb, bkp->offset.l4);
	pkt->payload = bkp->payload;
	pkt->l4_proto = bkp->l4_proto;
	pkt->is_inner = 0;
}

verdict ttpcomm_translate_inner_packet(struct tuple *outer_tuple, struct packet *in,
		struct packet *out)
{
	struct backup_skb bkp_in, bkp_out;
	struct tuple inner_tuple;
	struct tuple *inner_tuple_ptr = NULL;
	struct translation_steps *current_steps;
	verdict result;

	backup(in, &bkp_in);
	backup(out, &bkp_out);

	switch (pkt_l3_proto(in)) {
	case L3PROTO_IPV4:
		if (move_pointers4(in, out))
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

	if (nat64_is_stateful()) {
		inner_tuple.src = outer_tuple->dst;
		inner_tuple.dst = outer_tuple->src;
		inner_tuple.l3_proto = outer_tuple->l3_proto;
		inner_tuple.l4_proto = outer_tuple->l4_proto;
		inner_tuple_ptr = &inner_tuple;
	}

	current_steps = &steps[pkt_l3_proto(in)][pkt_l4_proto(in)];

	result = current_steps->l3_hdr_fn(inner_tuple_ptr, in, out);
	if (result == VERDICT_ACCEPT) {
		/*
		 * Accepting because of an inner packet doesn't make sense.
		 * Also we couldn't have translated this inner packet.
		 */
		return VERDICT_DROP;
	}
	if (result != VERDICT_CONTINUE)
		return result;

	result = current_steps->l3_payload_fn(inner_tuple_ptr, in, out);
	if (result == VERDICT_ACCEPT)
		return VERDICT_DROP;
	if (result != VERDICT_CONTINUE)
		return result;

	restore(in, &bkp_in);
	restore(out, &bkp_out);

	return VERDICT_CONTINUE;
}

struct translation_steps *ttpcomm_get_steps(enum l3_protocol l3_proto, enum l4_protocol l4_proto)
{
	return &steps[l3_proto][l4_proto];
}

/**
 * handle_partial_csum - set up @out_skb so the layer 4 checksum will be
 * computed from scratch by the OS or by the NIC.
 * @csum_offset: The checksum field's offset within its header.
 *
 * When the incoming skb's ip_summed field is NONE, UNNECESSARY or COMPLETE,
 * the checksum is defined, in the sense that its correctness consistently
 * dictates whether the packet is corrupted or not. In these cases, Jool is
 * supposed to update the checksum with the translation changes and forget
 * about it. The incoming packet's corruption will still be reflected in the
 * outgoing packet's checksum.
 *
 * On the other hand, when the incoming skb's ip_summed field is PARTIAL,
 * the existing checksum is pretty much guaranteed garbage. Jool can't update
 * it, and there's no reason to recompute it since the hardware or the OS are
 * supposed to do it later (and likely faster) anyway. Jool still has to fill
 * in a handful of fields for them to be able to do this, however.
 *
 * The latter situation (PARTIAL) is the one this function handles.
 */
void handle_partial_csum(struct sk_buff *out_skb, unsigned int csum_offset)
{
	out_skb->ip_summed = CHECKSUM_PARTIAL;
	out_skb->csum_start = skb_transport_offset(out_skb);
	out_skb->csum_offset = out_skb->csum_start + csum_offset;
}
