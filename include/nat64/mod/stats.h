#ifndef _JOOL_MOD_STATS_H
#define _JOOL_MOD_STATS_H

/**
 * @file
 * A wrapper for the kernel's stat functions.
 *
 * This exists because, based on experience, we can't really afford the assumptions that led to
 * those functions lacking argument validations.
 *
 * @author Alberto Leiva
 */

#include <linux/skbuff.h>

/**
 * Wrapper for IP6_INC_STATS_BH().
 */
void inc_stats_ipv6(struct sk_buff *skb, int field);

/**
 * Wrapper for IP_INC_STATS_BH().
 */
void inc_stats_ipv4(struct sk_buff *skb, int field);

/**
 * Wrapper for both IP6_INC_STATS_BH() and IP_INC_STATS_BH(), useful from l3-protocol unaware code.
 */
void inc_stats(struct sk_buff *skb, int field);

#endif /* _JOOL_MOD_STATS_H */
