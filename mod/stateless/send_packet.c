#include "nat64/mod/common/send_packet.h"

#include <net/ip.h>
#include <net/ipv6.h>

#include "nat64/mod/common/packet.h"

verdict sendpkt_send(struct sk_buff *in_skb, struct sk_buff *out_skb)
{
	struct sk_buff *skb;
	int error;

	/* TODO (issue #41) remember to re-test this before releasing. */
#ifdef BENCHMARK
	struct timespec end_time;
	getnstimeofday(&end_time);
	logtime(&skb_jcb(out_skb)->start_time, &end_time, skb_l3_proto(out_skb),
			skb_l4_proto(out_skb));
#endif

	log_debug("Sending skb.");

	skb_clear_cb(out_skb);
	skb_walk_frags(out_skb, skb)
		skb_clear_cb(skb);

	/* TODO (issue #41) newer kernels don't have local_df. Review. */
	out_skb->local_df = true; /* FFS, kernel. */
	error = dst_output(out_skb); /* Implicit kfree_skb(out_skb) goes here. */
	if (error) {
		log_debug("dst_output() returned errcode %d.", error);
		return VER_DROP;
	}

	return VER_CONTINUE;
}
