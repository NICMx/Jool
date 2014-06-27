#ifndef _JOOL_MOD_STATS_H
#define _JOOL_MOD_STATS_H

#include <linux/skbuff.h>

/**
 * Wrapper for IP6_INC_STATS_BH().
 *
 * This exists because I don't trust the kernel :B. I need to validate the crap out of "skb" before
 * I dereference its pointers.
 */
void inc_stats_ipv6(struct sk_buff *skb, int field);

/**
 * Wrapper for IP_INC_STATS_BH().
 *
 * This exists because I don't trust the kernel :B. I need to validate the crap out of "skb" before
 * I dereference its pointers.
 */
void inc_stats_ipv4(struct sk_buff *skb, int field);

void inc_stats(struct sk_buff *skb, int field);


#endif /* _JOOL_MOD_STATS_H */
