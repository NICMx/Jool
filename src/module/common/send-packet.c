#include "send-packet.h"

/* TODO move this. It no longer belongs to send-packet.
static unsigned int get_nexthop_mtu(struct packet *pkt)
{
#ifndef UNIT_TESTING
	return skb_dst(pkt->skb)->dev->mtu;
#else
	return 1500;
#endif
}

static int whine_if_too_big(struct xlation *state)
{
	struct packet *in = &state->in;
	struct packet *out = &state->out;
	unsigned int len;
	unsigned int mtu;

	if (pkt_l3_proto(in) == L3PROTO_IPV4 && !is_df_set(pkt_ip4_hdr(in)))
		return 0;

	len = pkt_len(out);
	mtu = get_nexthop_mtu(out);
	if (len > mtu) {
*/
		/*
		 * We don't have to worry about ICMP errors causing this because
		 * the translate code already truncates them.
		 */
/*
		log_debug("Packet is too big (len: %u, mtu: %u).", len, mtu);

		switch (pkt_l3_proto(out)) {
		case L3PROTO_IPV6:
			mtu -= 20;
			break;
		case L3PROTO_IPV4:
			mtu += 20;
			break;
		}

		icmp64_send(out, ICMPERR_FRAG_NEEDED, mtu);
		return einval(state, JOOL_MIB_FRAG_NEEDED);
	}

	return 0;
}
*/

static void add_ethernet_header(struct packet *pkt)
{
	struct ethhdr *hdr = (struct ethhdr *)skb_push(pkt->skb, ETH_HLEN);
	memset(hdr->h_dest, 0x64, ETH_ALEN);
	memset(hdr->h_source, 0x46, ETH_ALEN);
	hdr->h_proto = pkt->skb->protocol;
}

/**
 * BTW: You @pkt->skb->protocol needs to be set.
 */
int sendpkt_send(struct packet *pkt)
{
	/* TODO maybe missing a whole bunch of locking according to snull. */
	log_debug("Sending skb.");

	add_ethernet_header(pkt);
	netif_rx(pkt->skb);
	pkt->skb = NULL;
	return 0;
}
