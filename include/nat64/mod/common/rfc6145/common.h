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

/**
 * The reason why I need to create a new enum (as opposed to adding
 * TRY_SOMETHING_ELSE to verdict) is because VERDICT_CONTINUE is the only of its
 * kind that does not interrupt translation, which allows me to simplify most
 * verdict handling in the rest of the project:
 *
 *	verdict = handle_something(...);
 * 	if (verdict != VERDICT_CONTINUE)
 * 		return verdict; // ie. "interrupt"
 *
 * This would simply not be possible if there were other "possibly continue"
 * verdicts.
 */
typedef enum addrxlat_verdict {
	/** "Ok, address translated. Do something else now." */
	ADDRXLAT_CONTINUE = VERDICT_CONTINUE,
	/** "Translation failed but caller might use a fallback method." */
	ADDRXLAT_TRY_SOMETHING_ELSE = 512,
	/** "Translation prohibited. Return VERDICT_ACCEPT and forget it." */
	ADDRXLAT_ACCEPT = VERDICT_ACCEPT,
	/** "Translation prohibited. Return VERDICT_DROP and forget it." */
	ADDRXLAT_DROP = VERDICT_DROP,
} addrxlat_verdict;

struct translation_steps *ttpcomm_get_steps(enum l3_protocol l3_proto, enum l4_protocol l4_proto);

void partialize_skb(struct sk_buff *skb, unsigned int csum_offset);
int copy_payload(struct packet *in, struct packet *out);
bool will_need_frag_hdr(struct iphdr *in_hdr);
verdict ttpcomm_translate_inner_packet(struct tuple *outer_tuple, struct packet *in,
		struct packet *out);

bool must_not_translate(struct in_addr *addr);

#endif /* _JOOL_MOD_TTP_COMMON_H */
