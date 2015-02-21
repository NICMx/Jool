#ifndef _JOOL_MOD_RFC6145_COMMON_H
#define _JOOL_MOD_RFC6145_COMMON_H

#include <linux/ip.h>
#include "nat64/mod/common/types.h"
#include "nat64/mod/common/packet.h"

/**
 * An accesor for the full unused portion of the ICMP header, which I feel is missing from
 * linux/icmp.h.
 */
#define icmp4_unused un.gateway

struct translation_steps {
	verdict (*skb_create_fn)(struct packet *in, struct packet *out);
	/**
	 * The function that will translate the layer-3 header.
	 * Its purpose is to set the variables "out->l3_hdr.*", based on the packet described by "in".
	 */
	verdict (*l3_hdr_fn)(struct tuple *out_tuple, struct packet *in, struct packet *out);
	/**
	 * The function that will translate the layer-4 header and the payload.
	 * Layer 4 and payload are combined in a single function due to their strong interdependence.
	 * Its purpose is to set the variables "out->l4_hdr.*" and "out->payload.*", based on the
	 * packet described by "in".
	 */
	verdict (*l3_payload_fn)(struct tuple *out_tuple, struct packet *in, struct packet *out);
};

struct translation_steps *ttpcomm_get_steps(enum l3_protocol l3_proto, enum l4_protocol l4_proto);

int copy_payload(struct packet *in, struct packet *out);
bool will_need_frag_hdr(struct iphdr *in_hdr);
verdict ttpcomm_translate_inner_packet(struct tuple *outer_tuple, struct packet *in,
		struct packet *out);

#endif /* _JOOL_MOD_TTP_COMMON_H */
