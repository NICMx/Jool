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
 * @author Daniel Hernandez
 */

#include <linux/skbuff.h>

/**
 * Wrapper for both IP6_INC_STATS_BH() and IP_INC_STATS_BH().
 */
void inc_stats(struct sk_buff *skb, int field);

#endif /* _JOOL_MOD_STATS_H */
