#ifndef SRC_MOD_COMMON_RFC7915_COMMON_H_
#define SRC_MOD_COMMON_RFC7915_COMMON_H_

#include <linux/ip.h>
#include "common/types.h"
#include "mod/common/packet.h"
#include "mod/common/translation_state.h"

/**
 * An accesor for the full unused portion of the ICMP header, which I feel is
 * missing from linux/icmp.h.
 */
#define icmp4_unused un.gateway

struct translation_steps {
	/**
	 * Note: For the purposes of this comment, remember that the reserved
	 * area of a packet (bytes between head and data) is called "headroom"
	 * (example: skb_headroom()), while the non-paged active area (bytes
	 * between data and tail) is called "head" (eg: skb_headlen()). This is
	 * a kernel quirk; don't blame me for it.
	 *
	 * Computes the outer addresses of the outgoing packet, routes it,
	 * allocates it, then copies addresses, destination and layer 4 payload
	 * into it. Ensures there's enough headroom for translated headers.
	 * (In other words, it does everything except for headers, except for
	 * outer addresses.)
	 *
	 * Addresses need to be translated first because of issue #167, and
	 * because they're needed for routing. Routing needs to be done before
	 * allocation because we might need to fragment based on the outgoing
	 * interface's MTU.
	 *
	 * "Why do we need this? Why don't we simply override the headers of the
	 * incoming packet? This would avoid lots of allocation and copying."
	 *
	 * Because we can't afford to completely lose the original headers until
	 * we've fetched the translated packet successfully. Even after the
	 * RFC7915 code ends, there is still stuff we might need the original
	 * packet for, such as replying an ICMP error or NF_ACCEPTing.
	 */
	verdict (*skb_alloc_fn)(struct xlation *state);
	/**
	 * The function that will translate the layer-3 header, except
	 * addresses.
	 */
	verdict (*l3_hdr_fn)(struct xlation *state);
	/**
	 * The function that will translate the layer-4 header.
	 * For ICMP errors, this also translates the inner packet headers.
	 */
	verdict (*l4_hdr_fn)(struct xlation *state);
};

struct translation_steps *ttpcomm_get_steps(struct packet *in);

void partialize_skb(struct sk_buff *skb, unsigned int csum_offset);
bool will_need_frag_hdr(const struct iphdr *hdr);
verdict ttpcomm_translate_inner_packet(struct xlation *state);

bool must_not_translate(struct in_addr *addr, struct net *ns);

/* ICMP Extensions */

#define icmp6_length icmp6_dataun.un_data8[0]
#define icmp4_length un.reserved[1]

/* See /test/graybox/test-suite/rfc/7915.md#ic */
struct icmpext_args {
	size_t max_pkt_len; /* Maximum (allowed outgoing) Packet Length */
	size_t ipl; /* Internal Packet Length */
	size_t out_bits; /* 4->6: Set as 3; 6->4: Set as 2 */
	bool force_remove_ie; /* Force the removal of the IE? */
};

verdict handle_icmp_extension(struct xlation *state,
		struct icmpext_args *args);

#endif /* SRC_MOD_COMMON_RFC7915_COMMON_H_ */
