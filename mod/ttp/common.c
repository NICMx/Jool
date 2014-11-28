#include "nat64/mod/ttp/common.h"
#include "nat64/mod/ttp/4to6.h"
#include "nat64/mod/ttp/6to4.h"
#include "nat64/mod/send_packet.h"
#include "nat64/mod/stats.h"
#include <linux/icmp.h>

struct backup_skb {
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
	return skb_copy_bits(in, skb_payload_offset(in), skb_payload(out), skb_payload_len_frag(in));
}

static int move_pointers4(struct sk_buff *skb)
{
	struct iphdr *hdr4 = skb_payload(skb);
	struct jool_cb *cb = skb_jcb(skb);

	skb_set_network_header(skb, skb_payload_offset(skb));
	skb_set_transport_header(skb, skb_network_offset(skb) + 4 * hdr4->ihl);
	cb->is_inner = 1;

	switch (hdr4->protocol) {
	case IPPROTO_TCP:
		cb->l4_proto = L4PROTO_TCP;
		/* TODO (issue #41) wrong. The TCP header hasn't been init'd, so this returns garbage. */
		cb->payload = skb_transport_header(skb) + tcp_hdr_len(tcp_hdr(skb));
		break;
	case IPPROTO_UDP:
		cb->l4_proto = L4PROTO_UDP;
		cb->payload = skb_transport_header(skb) + sizeof(struct udphdr);
		break;
	case IPPROTO_ICMP:
		cb->l4_proto = L4PROTO_ICMP;
		cb->payload = skb_transport_header(skb) + sizeof(struct icmphdr);
		break;
	default:
		inc_stats(skb, IPSTATS_MIB_INUNKNOWNPROTOS);
		return -EINVAL;
	}

	return 0;
}

static int move_pointers6(struct sk_buff *skb)
{
	struct ipv6hdr *hdr6 = skb_payload(skb);
	struct jool_cb *cb = skb_jcb(skb);
	struct hdr_iterator iterator = HDR_ITERATOR_INIT(hdr6);

	hdr_iterator_last(&iterator);

	skb_set_network_header(skb, skb_payload_offset(skb));
	skb_set_transport_header(skb, skb_network_offset(skb) + (iterator.data - (void *) hdr6));
	cb->is_inner = 1;

	switch (iterator.hdr_type) {
	case NEXTHDR_TCP:
		cb->l4_proto = L4PROTO_TCP;
		/* TODO (issue #41) wrong. The TCP header hasn't been init'd, so this returns garbage. */
		cb->payload = skb_transport_header(skb) + tcp_hdr_len(tcp_hdr(skb));
		break;
	case NEXTHDR_UDP:
		cb->l4_proto = L4PROTO_UDP;
		cb->payload = skb_transport_header(skb) + sizeof(struct udphdr);
		break;
	case NEXTHDR_ICMP:
		cb->l4_proto = L4PROTO_ICMP;
		cb->payload = skb_transport_header(skb) + sizeof(struct icmphdr);
		break;
	default:
		inc_stats(skb, IPSTATS_MIB_INUNKNOWNPROTOS);
		return -EINVAL;
	}

	return 0;
}

static void backup(struct sk_buff *skb, struct backup_skb *bkp)
{
	bkp->offset.l3 = skb_network_offset(skb);
	bkp->offset.l4 = skb_transport_offset(skb);
	bkp->payload = skb_payload(skb);
	bkp->l4_proto = skb_l4_proto(skb);
}

static void restore(struct sk_buff *skb, struct backup_skb *bkp)
{
	struct jool_cb *cb = skb_jcb(skb);

	skb_set_network_header(skb, bkp->offset.l3);
	skb_set_transport_header(skb, bkp->offset.l3);
	cb->payload = bkp->payload;
	cb->l4_proto = bkp->l4_proto;
}

int ttpcomm_translate_inner_packet(struct tuple *outer_tuple,
		struct sk_buff *skb6, struct sk_buff *skb4,
		struct sk_buff *in, struct sk_buff *out)
{
	struct backup_skb bkp_in, bkp_out;
	struct tuple inner_tuple;
	struct translation_steps *current_steps;
	int error;

	backup(in, &bkp_in);
	backup(out, &bkp_out);

	error = move_pointers6(skb6);
	if (error)
		return error;
	error = move_pointers4(skb4);
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
	skb_jcb(in)->is_inner = 0;
	skb_jcb(out)->is_inner = 0;

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
