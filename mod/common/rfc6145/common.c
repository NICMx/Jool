#include "nat64/mod/common/rfc6145/common.h"
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

bool will_need_frag_hdr(struct iphdr *in_hdr)
{
	/*
	 * Starting from Jool 3.3, we largely defer fragmentation to the kernel.
	 * Jool no longer fragments packets because that implied a ridiculous amount of really
	 * troublesome code. It not only received strange input, but also had very hard-to-explain
	 * output requirements, and it also had to handle the RFCs' quirks.
	 *
	 * Unfortunately, this has an important consequence: Jool must never send atomic fragments.
	 * This is because the kernel doesn't know them. If I send an atomic fragment and the kernel
	 * has to fragment it, it appends another fragment header. This confuses everything.
	 * On the other hand, RFC 6145 *wants* atomic fragments.
	 * Read below to find out how we handle this.
	 */

	/*
	 * We completely ignore the fragment header during stateful operation
	 * because the kernel really wants to handle it on its own.
	 * This introduces an unimportant mismatch with the RFC.
	 * TODO (doc) document what it is and why it doesn't matter.
	 */
	if (nat64_is_stateful())
		return false;

	/*
	 * TODO (fine) RFC 6145 wants a flag here.
	 * If the flag is false and DF is also false, the NAT64 should include a fragmentation header
	 * regardless of fragmentation status (page 7).
	 * I removed it on Jool 3.3 because it lead to atomic fragments.
	 * The reason why this is not considered a problem is because experience has given the flag
	 * a bad reputation (draft-gont-6man-deprecate-atomfrag-generation).
	 * I've decided removing all that fragmentation code is worth not supporting that flag.
	 */
	return is_more_fragments_set_ipv4(in_hdr) || get_fragment_offset_ipv4(in_hdr);
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
		/* TODO what abour OTHER? */
		log_debug("Unknown l4 protocol: %u", protocol);
		inc_stats(pkt, IPSTATS_MIB_INUNKNOWNPROTOS);
		return -EINVAL;
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
