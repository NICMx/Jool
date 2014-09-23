#include "nat64/mod/ttp/common.h"
#include "nat64/mod/ttp/4to6.h"
#include "nat64/mod/ttp/6to4.h"
#include "nat64/mod/send_packet.h"

static struct translation_steps steps[L3_PROTO_COUNT][L4_PROTO_COUNT];

int ttpcomm_translate_inner_packet(struct tuple *out_tuple, struct pkt_parts *in_inner,
		struct pkt_parts *out_outer)
{
	struct pkt_parts out_inner;
	struct tuple inner_tuple;
	struct translation_steps *current_steps;
	int error;

	inner_tuple.src = out_tuple->dst;
	inner_tuple.dst = out_tuple->src;
	inner_tuple.l3_proto = out_tuple->l3_proto;
	inner_tuple.l4_proto = out_tuple->l4_proto;

	out_inner.l3_hdr.proto = out_outer->l3_hdr.proto;
	out_inner.l3_hdr.len = out_outer->payload.len - in_inner->l4_hdr.len - in_inner->payload.len;
	out_inner.l3_hdr.ptr = out_outer->payload.ptr;
	out_inner.l4_hdr.proto = in_inner->l4_hdr.proto;
	out_inner.l4_hdr.len = in_inner->l4_hdr.len;
	out_inner.l4_hdr.ptr = out_inner.l3_hdr.ptr + out_inner.l3_hdr.len;
	out_inner.payload.len = in_inner->payload.len;
	out_inner.payload.ptr = out_inner.l4_hdr.ptr + out_inner.l4_hdr.len;

	current_steps = &steps[in_inner->l3_hdr.proto][in_inner->l4_hdr.proto];

	error = current_steps->l3_hdr_fn(&inner_tuple, in_inner, &out_inner);
	if (error)
		return error;
	error = current_steps->l3_payload_fn(&inner_tuple, in_inner, &out_inner);
	if (error)
		return error;

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
