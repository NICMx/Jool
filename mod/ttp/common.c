#include "nat64/mod/ttp/common.h"
#include "nat64/mod/ttp/config.h"
#include "nat64/mod/ttp/4to6.h"
#include "nat64/mod/ttp/6to4.h"
#include "nat64/mod/send_packet.h"
#include "nat64/mod/stats.h"
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

static struct translation_steps steps[L3_PROTO_COUNT][L4_PROTO_COUNT];

int copy_payload(struct sk_buff *in, struct sk_buff *out)
{
	int error;

	error = skb_copy_bits(in, skb_payload_offset(in), skb_payload(out), skb_payload_len_frag(in));
	if (error)
		log_debug("The payload copy threw errcode %d.", error);

	return error;
}

static bool build_ipv6_frag_hdr(struct iphdr *in_hdr)
{
	struct translate_config *config;
	bool build_ipv6_fh = 0;

	if (is_dont_fragment_set(in_hdr))
		return false;

	rcu_read_lock_bh();
	config = ttpconfig_get();
	build_ipv6_fh = config->build_ipv6_fh;
	rcu_read_unlock_bh();

	return build_ipv6_fh;
}

bool will_need_frag_hdr(struct iphdr *in_hdr)
{
	/*
	 * We completely ignore the fragment header during stateful operation
	 * because the kernel really wants to handle it on its own.
	 */
	if (nat64_is_stateful())
		return false;

	return build_ipv6_frag_hdr(in_hdr)
			|| is_more_fragments_set_ipv4(in_hdr)
			|| get_fragment_offset_ipv4(in_hdr);
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

int ttpcomm_translate_inner_packet(struct tuple *outer_tuple, struct sk_buff *in,
		struct sk_buff *out)
{
	struct backup_skb bkp_in, bkp_out;
	struct tuple inner_tuple;
	struct translation_steps *current_steps;
	int error;

	backup(in, &bkp_in);
	backup(out, &bkp_out);

	switch (skb_l3_proto(in)) {
	case L3PROTO_IPV4:
		error = move_pointers4(in, out);
		break;
	case L3PROTO_IPV6:
		error = move_pointers6(in, out);
		break;
	default:
		inc_stats(in, IPSTATS_MIB_INUNKNOWNPROTOS);
		return -EINVAL;
	}
	if (error)
		return error;

	inner_tuple.src = outer_tuple->dst;
	inner_tuple.dst = outer_tuple->src;
	inner_tuple.l3_proto = outer_tuple->l3_proto;
	inner_tuple.l4_proto = outer_tuple->l4_proto;

	current_steps = &steps[skb_l3_proto(in)][skb_l4_proto(in)];

	error = current_steps->l3_hdr_fn(&inner_tuple, in, out);
	if (error)
		return error;
	error = current_steps->l3_payload_fn(&inner_tuple, in, out);
	if (error)
		return error;

	restore(in, &bkp_in);
	restore(out, &bkp_out);

	return 0;
}

int ttpcomm_init(void)
{
	steps[L3PROTO_IPV6][L4PROTO_TCP].skb_create_fn = ttp64_create_skb;
	steps[L3PROTO_IPV6][L4PROTO_TCP].l3_hdr_fn = ttp64_ipv4;
	steps[L3PROTO_IPV6][L4PROTO_TCP].l3_payload_fn = ttp64_tcp;
	steps[L3PROTO_IPV6][L4PROTO_TCP].route_fn = sendpkt_route4;

	steps[L3PROTO_IPV6][L4PROTO_UDP].skb_create_fn = ttp64_create_skb;
	steps[L3PROTO_IPV6][L4PROTO_UDP].l3_hdr_fn = ttp64_ipv4;
	steps[L3PROTO_IPV6][L4PROTO_UDP].l3_payload_fn = ttp64_udp;
	steps[L3PROTO_IPV6][L4PROTO_UDP].route_fn = sendpkt_route4;

	steps[L3PROTO_IPV6][L4PROTO_ICMP].skb_create_fn = ttp64_create_skb;
	steps[L3PROTO_IPV6][L4PROTO_ICMP].l3_hdr_fn = ttp64_ipv4;
	steps[L3PROTO_IPV6][L4PROTO_ICMP].l3_payload_fn = ttp64_icmp;
	steps[L3PROTO_IPV6][L4PROTO_ICMP].route_fn = sendpkt_route4;

	steps[L3PROTO_IPV4][L4PROTO_TCP].skb_create_fn = ttp46_create_skb;
	steps[L3PROTO_IPV4][L4PROTO_TCP].l3_hdr_fn = ttp46_ipv6;
	steps[L3PROTO_IPV4][L4PROTO_TCP].l3_payload_fn = ttp46_tcp;
	steps[L3PROTO_IPV4][L4PROTO_TCP].route_fn = sendpkt_route6;

	steps[L3PROTO_IPV4][L4PROTO_UDP].skb_create_fn = ttp46_create_skb;
	steps[L3PROTO_IPV4][L4PROTO_UDP].l3_hdr_fn = ttp46_ipv6;
	steps[L3PROTO_IPV4][L4PROTO_UDP].l3_payload_fn = ttp46_udp;
	steps[L3PROTO_IPV4][L4PROTO_UDP].route_fn = sendpkt_route6;

	steps[L3PROTO_IPV4][L4PROTO_ICMP].skb_create_fn = ttp46_create_skb;
	steps[L3PROTO_IPV4][L4PROTO_ICMP].l3_hdr_fn = ttp46_ipv6;
	steps[L3PROTO_IPV4][L4PROTO_ICMP].l3_payload_fn = ttp46_icmp;
	steps[L3PROTO_IPV4][L4PROTO_ICMP].route_fn = sendpkt_route6;

	return 0;
}

void ttpcomm_destroy(void)
{
	/* Empty. */
}

struct translation_steps *ttpcomm_get_steps(enum l3_protocol l3_proto, enum l4_protocol l4_proto)
{
	return &steps[l3_proto][l4_proto];
}
