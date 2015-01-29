#include "nat64/mod/common/send_packet.h"

#include <linux/version.h>

#include "nat64/mod/common/icmp_wrapper.h"
#include "nat64/mod/common/packet.h"
#include "nat64/mod/common/route.h"

static unsigned int get_nexthop_mtu(struct sk_buff *skb)
{
#ifndef UNIT_TESTING
	return skb_dst(skb)->dev->mtu;
#else
	return 1500;
#endif
}

static int whine_if_too_big(struct sk_buff *in_skb, struct sk_buff *out_skb)
{
	unsigned int len;
	unsigned int mtu;

	if (skb_l3_proto(in_skb) == L3PROTO_IPV4 && !is_dont_fragment_set(ip_hdr(in_skb)))
		return 0;

	len = skb_len(out_skb);
	mtu = get_nexthop_mtu(out_skb);
	if (len > mtu) {
		/*
		 * We don't have to worry about ICMP errors causing this because the translate code already
		 * truncates them.
		 */
		log_debug("Packet is too big (len: %u, mtu: %u).", len, mtu);
		icmp64_send(out_skb, ICMPERR_FRAG_NEEDED, mtu);
		return -EINVAL;
	}

	return 0;
}

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

	if (!out_skb->dev) {
		error = route(out_skb);
		if (error) {
			kfree_skb(out_skb);
			return VER_DROP;
		}
	}

	log_debug("Sending skb via device '%s'.", out_skb->dev->name);

	error = whine_if_too_big(in_skb, out_skb);
	if (error) {
		kfree_skb(out_skb);
		return VER_DROP;
	}

	skb_clear_cb(out_skb);
	skb_walk_frags(out_skb, skb)
		skb_clear_cb(skb);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 16, 0)
	out_skb->ignore_df = true; /* FFS, kernel. */
#else
	out_skb->local_df = true; /* FFS, kernel. */
#endif

	error = dst_output(out_skb); /* Implicit kfree_skb(out_skb) goes here. */
	if (error) {
		log_debug("dst_output() returned errcode %d.", error);
		return VER_DROP;
	}

	return VER_CONTINUE;
}
