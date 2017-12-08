#include "nat64/mod/common/send_packet.h"

#include <linux/version.h>

#include "nat64/mod/common/linux_version.h"
#include "nat64/mod/common/icmp_wrapper.h"
#include "nat64/mod/common/packet.h"
#include "nat64/mod/common/route.h"
#include "nat64/mod/common/log_time.h"

static unsigned int get_nexthop_mtu(struct packet *pkt)
{
#ifndef UNIT_TESTING
	return skb_dst(pkt->skb)->dev->mtu;
#else
	return 1500;
#endif
}

static int whine_if_too_big(struct packet *in, struct packet *out)
{
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

		return -EINVAL;
	}

	return 0;
}

verdict sendpkt_send(struct xlation *state)
{
	struct packet *out = &state->out;
	int error;

	logtime(out);

	if (!route(state->jool.ns, out)) {
		kfree_skb(out->skb);
		return VERDICT_ACCEPT;
	}

	out->skb->dev = skb_dst(out->skb)->dev;
	log_debug("Sending skb.");

	error = whine_if_too_big(&state->in, out);
	if (error) {
		kfree_skb(out->skb);
		return VERDICT_DROP;
	}

#if LINUX_VERSION_AT_LEAST(3, 16, 0, 7, 2)
	out->skb->ignore_df = true; /* FFS, kernel. */
#else
	out->skb->local_df = true; /* FFS, kernel. */
#endif

	/*
	 * Implicit kfree_skb(out->skb) here.
	 *
	 * At time of writing, RHEL hasn't yet upgraded to the messy version of
	 * dst_output().
	 */
#if LINUX_VERSION_AT_LEAST(4, 4, 0, 9999, 0)
	error = dst_output(state->jool.ns, NULL, out->skb);
#else
	error = dst_output(out->skb);
#endif
	if (error) {
		log_debug("dst_output() returned errcode %d.", error);
		return VERDICT_DROP;
	}

	return VERDICT_CONTINUE;
}
