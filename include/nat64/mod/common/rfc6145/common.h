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
	/**
	 * Allocates the translated version of the incoming packet. Predicts
	 * packet size, allocates skb and initializes a basic skb fields. Packet
	 * content translation is deferred to other functions.
	 *
	 * "Why do we need this? Why don't we simply override the headers of the
	 * incoming packet? This would avoid lots of allocation and copying."
	 *
	 * Because we can't afford to completely lose the original headers until
	 * we've fetched the translated packet successfully. Even after the
	 * RFC6145 code ends, there is still stuff we might need the original
	 * packet for, such as replying an ICMP error or NF_ACCEPTing.
	 *
	 * -----------------------------
	 *
	 * When translating a fragment chain, this only creates the first
	 * packet. Subsequent fragments are allocated by translate_subsequent().
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
	ADDRXLAT_CONTINUE = VERDICT_CONTINUE,
	/** "Translation failed but caller might use a fallback method." */
	ADDRXLAT_TRY_SOMETHING_ELSE = 512,
	/** "Translation prohibited. Return VERDICT_ACCEPT and forget it." */
	ADDRXLAT_ACCEPT = VERDICT_ACCEPT,
	/** "Translation prohibited. Return VERDICT_DROP and forget it." */
	ADDRXLAT_DROP = VERDICT_DROP,
} addrxlat_verdict;

struct translation_steps *ttpcomm_get_steps(struct packet *in);

void partialize_skb(struct sk_buff *skb, unsigned int csum_offset);
bool will_need_frag_hdr(const struct iphdr *hdr);
verdict ttpcomm_translate_inner_packet(struct xlation *state);

bool must_not_translate(struct in_addr *addr, struct net *ns);

#endif /* _JOOL_MOD_TTP_COMMON_H */
