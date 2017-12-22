#include "send-packet.h"

#include "icmp-wrapper.h"

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
		/*
		 * We don't have to worry about ICMP errors causing this because
		 * the translate code already truncates them.
		 */
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

static int add_eth_hdr(struct xlation *state)
{
	struct ethhdr *hdr;

	hdr = (struct ethhdr *)skb_push(state->out.skb, ETH_HLEN);
	memset(hdr->h_dest, 0x64, ETH_ALEN);
	memset(hdr->h_source, 0x46, ETH_ALEN);
	switch (pkt_l3_proto(&state->out)) {
	case L3PROTO_IPV6:
		hdr->h_proto = cpu_to_be16(ETH_P_IPV6);
		return 0;
	case L3PROTO_IPV4:
		hdr->h_proto = cpu_to_be16(ETH_P_IP);
		return 0;
	}

	log_debug("Unknown l3 proto: %d", pkt_l3_proto(&state->out));
	return einval(state, JOOL_MIB_UNKNOWN_L3);
}

/* TODO maybe missing a whole bunch of locking according to snull. */
int sendpkt_send(struct xlation *state)
{
	int error;

	log_debug("Sending skb.");

	error = whine_if_too_big(state);
	if (error)
		goto fail;

	error = add_eth_hdr(state);
	if (error)
		goto fail;

	netif_rx(state->out.skb);
	state->out.skb = NULL;
	return 0;

fail:
	kfree_skb(state->out.skb);
	state->out.skb = NULL;
	return error;
}
