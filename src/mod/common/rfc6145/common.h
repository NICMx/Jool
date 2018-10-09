#ifndef _JOOL_MOD_RFC6145_COMMON_H
#define _JOOL_MOD_RFC6145_COMMON_H

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
	 * Performs a pskb_copy()-style clone (ie. different sk_buff, different
	 * head, same pages) of @state->in.skb and places it in @state->out.skb.
	 * Ensures there's enough headroom for translated headers. Packet
	 * content translation is deferred to the other functions below.
	 *
	 * "Why do we need this? Why don't we simply override the headers of the
	 * incoming packet? This would avoid lots of allocation and copying."
	 *
	 * Because we can't afford to completely lose the original headers until
	 * we've fetched the translated packet successfully. Even after the
	 * RFC6145 code ends, there is still stuff we might need the original
	 * packet for, such as replying an ICMP error or NF_ACCEPTing.
	 */
	verdict (*skb_alloc_fn)(struct xlation *state);
	/**
	 * The function that will translate the layer-3 header.
	 */
	verdict (*l3_hdr_fn)(struct xlation *state);
	/**
	 * The function that will translate the layer-4 header.
	 * For ICMP errors, this also translates the inner packet headers.
	 */
	verdict (*l4_hdr_fn)(struct xlation *state);
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
	ADDRXLAT_CONTINUE,
	/** "Translation failed but caller might use a fallback method." */
	ADDRXLAT_TRY_SOMETHING_ELSE,
	/** "Translation prohibited. Return VERDICT_ACCEPT and forget it." */
	ADDRXLAT_ACCEPT,
	/** "Translation prohibited. Return VERDICT_DROP and forget it." */
	ADDRXLAT_DROP,
} addrxlat_verdict;

struct translation_steps *ttpcomm_get_steps(struct packet *in);

void partialize_skb(struct sk_buff *skb, unsigned int csum_offset);
bool will_need_frag_hdr(const struct iphdr *hdr);
verdict ttpcomm_translate_inner_packet(struct xlation *state);

bool must_not_translate(struct in_addr *addr, struct net *ns);

#endif /* _JOOL_MOD_TTP_COMMON_H */
