#ifndef _JOOL_MOD_TTP_COMMON_H
#define _JOOL_MOD_TTP_COMMON_H

#include "nat64/mod/types.h"

/**
 * An accesor for the full unused portion of the ICMP header, which I feel is missing from
 * linux/icmp.h.
 */
#define icmp4_unused un.gateway

/**
 * A bunch of pieces, that will eventually be merged into a sk_buff.
 * We also use it to describe incoming skbs, so we don't have to turn ICMP payloads into skbs when
 * we're translating error messages (since a pkt_parts in the stack is easier on the kernel than
 * a massive temporal sk_buff in the heap, I think).
 */
struct pkt_parts {
	struct {
		l3_protocol proto;
		unsigned int len;
		void *ptr;
	} l3_hdr;
	struct {
		l4_protocol proto;
		unsigned int len;
		void *ptr;
	} l4_hdr;
	struct {
		unsigned int len;
		void *ptr;
	} payload;

	/**
	 * If this parts represents a incoming packet:
	 * - If skb is not NULL, it is the sk_buff these parts were computed from.
	 * - If skb is NULL, it's because there was no sk_buff in the first place (ie. it was generated
	 * from a packet contained inside a packet).
	 *
	 * If this parts represents a outgoing packet, then the result of joining the above parts is
	 * placed here.
	 */
	struct sk_buff *skb;
};

struct translation_steps {
	int (*skb_create_fn)(struct pkt_parts *in, struct sk_buff **out);
	/**
	 * The function that will translate the layer-3 header.
	 * Its purpose is to set the variables "out->l3_hdr.*", based on the packet described by "in".
	 */
	int (*l3_hdr_fn)(struct tuple *tuple, struct pkt_parts *in, struct pkt_parts *out);
	/**
	 * The function that will translate the layer-4 header and the payload.
	 * Layer 4 and payload are combined in a single function due to their strong interdependence.
	 * Its purpose is to set the variables "out->l4_hdr.*" and "out->payload.*", based on the
	 * packet described by "in".
	 */
	int (*l3_payload_fn)(struct tuple *, struct pkt_parts *in, struct pkt_parts *out);
};

int ttpcomm_init(void);
void ttpcomm_destroy(void);

/**
 * This function only makes sense if parts is an incoming packet.
 */
static inline bool is_inner_pkt(struct pkt_parts *parts)
{
	return parts->skb == NULL;
}

struct translation_steps *ttpcomm_get_steps(enum l3_protocol l3_proto, enum l4_protocol l4_proto);

int ttpcomm_translate_inner_packet(struct tuple *tuple, struct pkt_parts *in_inner,
		struct pkt_parts *out_outer);

#endif /* _JOOL_MOD_TTP_COMMON_H */
