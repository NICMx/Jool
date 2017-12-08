#ifndef _JOOL_MOD_STATS_H
#define _JOOL_MOD_STATS_H

/**
 * @file
 * A wrapper for the kernel's stat functions.
 *
 * This exists because, based on experience, we can't really afford the assumptions that led to
 * those functions lacking argument validations.
 */

#include "packet.h"

/**
 * Wrapper for both IP6_INC_STATS_BH() and IP_INC_STATS_BH().
 */
void inc_stats(struct packet *pkt, int field);

/**
 * @{
 * These are intended to be used when the struct packet is not yet initialized. For anything else,
 * just use inc_stats().
 */
void inc_stats_skb6(struct sk_buff *skb, int field);
void inc_stats_skb4(struct sk_buff *skb, int field);
/**
 * @}
 */

#endif /* _JOOL_MOD_STATS_H */
