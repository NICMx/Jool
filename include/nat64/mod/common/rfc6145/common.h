#ifndef _JOOL_MOD_RFC6145_COMMON_H
#define _JOOL_MOD_RFC6145_COMMON_H

#include <linux/ip.h>
#include "nat64/common/types.h"
#include "nat64/mod/common/packet.h"
#include "nat64/mod/common/translation_state.h"

/**
 * An accesor for the full unused portion of the ICMP header, which I feel is
 * missing from linux/icmp.h.
 */
#define icmp4_unused un.gateway

struct translation_steps {
	verdict (*skb_create_fn)(struct xlation *state);
	/**
	 * The function that will translate the layer-3 header.
	 */
	verdict (*l3_hdr_fn)(struct xlation *state);
	/**
	 * The function that will translate the layer-4 header and the payload.
	 * Layer 4 and payload are combined in a single function due to their
	 * strong interdependence.
	 */
	verdict (*l3_payload_fn)(struct xlation *state);
};

struct translation_steps *ttpcomm_get_steps(struct packet *in);

void partialize_skb(struct sk_buff *skb, unsigned int csum_offset);
int copy_payload(struct xlation *state);
bool will_need_frag_hdr(struct xlation *state);
verdict ttpcomm_translate_inner_packet(struct xlation *state);

#endif /* _JOOL_MOD_TTP_COMMON_H */
