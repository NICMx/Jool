#include "nat64/mod/common/packet.h"
#include "nat64/mod/common/stats.h"
#include "nat64/mod/common/rfc6145/common.h"
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

static struct translation_steps steps[L3_PROTO_COUNT][L4_PROTO_COUNT] = {
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
		}
	}
};

int copy_payload(struct sk_buff *in, struct sk_buff *out)
{
	int error;

	error = skb_copy_bits(in, skb_payload_offset(in), skb_payload(out), skb_payload_len_frag(out));
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

static int move_pointers_in(struct sk_buff *skb, __u8 protocol, unsigned int l3hdr_len)
{
	struct jool_cb *cb = skb_jcb(skb);
	unsigned int l4hdr_len;

	skb_pull(skb, skb_hdrs_len(skb));
	skb_reset_network_header(skb);
	skb_set_transport_header(skb, l3hdr_len);

	switch (protocol) {
	case IPPROTO_TCP:
		cb->l4_proto = L4PROTO_TCP;
		l4hdr_len = tcp_hdr_len(tcp_hdr(skb));
		break;
	case IPPROTO_UDP:
		cb->l4_proto = L4PROTO_UDP;
		l4hdr_len = sizeof(struct udphdr);
		break;
	case IPPROTO_ICMP:
	case NEXTHDR_ICMP:
		cb->l4_proto = L4PROTO_ICMP;
		l4hdr_len = sizeof(struct icmphdr);
		break;
	default:
		/* TODO what abour OTHER? */
		log_debug("Unknown l4 protocol: %u", protocol);
		inc_stats(skb, IPSTATS_MIB_INUNKNOWNPROTOS);
		return -EINVAL;
	}
	cb->is_inner = 1;
	cb->payload = skb_transport_header(skb) + l4hdr_len;

	return 0;
}

static int move_pointers_out(struct sk_buff *skb_in, struct sk_buff *skb_out,
		unsigned int l3hdr_len)
{
	struct jool_cb *cb = skb_jcb(skb_out);

	skb_pull(skb_out, skb_hdrs_len(skb_out));
	skb_reset_network_header(skb_out);
	skb_set_transport_header(skb_out, l3hdr_len);

	cb->l4_proto = skb_l4_proto(skb_in);
	cb->is_inner = 1;
	cb->payload = skb_transport_header(skb_out) + skb_l4hdr_len(skb_in);

	return 0;
}

static int move_pointers4(struct sk_buff *skb_in, struct sk_buff *skb_out)
{
	struct iphdr *hdr4;
	unsigned int l3hdr_len;
	int error;

	hdr4 = skb_payload(skb_in);
	error = move_pointers_in(skb_in, hdr4->protocol, 4 * hdr4->ihl);
	if (error)
		return error;

	l3hdr_len = sizeof(struct ipv6hdr);
	if (will_need_frag_hdr(hdr4))
		l3hdr_len += sizeof(struct frag_hdr);
	return move_pointers_out(skb_in, skb_out, l3hdr_len);
}

static int move_pointers6(struct sk_buff *skb_in, struct sk_buff *skb_out)
{
	struct ipv6hdr *hdr6;
	struct hdr_iterator iterator;
	int error;

	hdr6 = skb_payload(skb_in);
	hdr_iterator_init(&iterator, hdr6);
	hdr_iterator_last(&iterator);

	error = move_pointers_in(skb_in, iterator.hdr_type, iterator.data - (void *) hdr6);
	if (error)
		return error;

	return move_pointers_out(skb_in, skb_out, sizeof(struct iphdr));
}

static void backup(struct sk_buff *skb, struct backup_skb *bkp)
{
	bkp->pulled = skb_hdrs_len(skb);
	bkp->offset.l3 = skb_network_offset(skb);
	bkp->offset.l4 = skb_transport_offset(skb);
	bkp->payload = skb_payload(skb);
	bkp->l4_proto = skb_l4_proto(skb);
}

static void restore(struct sk_buff *skb, struct backup_skb *bkp)
{
	struct jool_cb *cb = skb_jcb(skb);

	skb_push(skb, bkp->pulled);
	skb_set_network_header(skb, bkp->offset.l3);
	skb_set_transport_header(skb, bkp->offset.l4);
	cb->payload = bkp->payload;
	cb->l4_proto = bkp->l4_proto;
	cb->is_inner = 0;
}

verdict ttpcomm_translate_inner_packet(struct tuple *outer_tuple, struct sk_buff *in,
		struct sk_buff *out)
{
	struct backup_skb bkp_in, bkp_out;
	struct tuple inner_tuple;
	struct tuple *inner_tuple_ptr = NULL;
	struct translation_steps *current_steps;
	verdict result;

	backup(in, &bkp_in);
	backup(out, &bkp_out);

	switch (skb_l3_proto(in)) {
	case L3PROTO_IPV4:
		if (move_pointers4(in, out))
			return VER_DROP;
		break;
	case L3PROTO_IPV6:
		if (move_pointers6(in, out))
			return VER_DROP;
		break;
	default:
		inc_stats(in, IPSTATS_MIB_INUNKNOWNPROTOS);
		return VER_DROP;
	}

	if (nat64_is_stateful()) {
		inner_tuple.src = outer_tuple->dst;
		inner_tuple.dst = outer_tuple->src;
		inner_tuple.l3_proto = outer_tuple->l3_proto;
		inner_tuple.l4_proto = outer_tuple->l4_proto;
		inner_tuple_ptr = &inner_tuple;
	}

	current_steps = &steps[skb_l3_proto(in)][skb_l4_proto(in)];

	result = current_steps->l3_hdr_fn(inner_tuple_ptr, in, out);
	if (result == VER_ACCEPT) {
		/*
		 * Accepting because of an inner packet doesn't make sense.
		 * Also we couldn't have translated this inner packet.
		 */
		return VER_DROP;
	}
	if (result != VER_CONTINUE)
		return result;

	result = current_steps->l3_payload_fn(inner_tuple_ptr, in, out);
	if (result == VER_ACCEPT)
		return VER_DROP;
	if (result != VER_CONTINUE)
		return result;

	restore(in, &bkp_in);
	restore(out, &bkp_out);

	return VER_CONTINUE;
}

struct translation_steps *ttpcomm_get_steps(enum l3_protocol l3_proto, enum l4_protocol l4_proto)
{
	return &steps[l3_proto][l4_proto];
}
