#ifndef _NF_NAT64_ICMP_WRAPPER_H
#define _NF_NAT64_ICMP_WRAPPER_H

#include <linux/types.h>
#include <linux/skbuff.h>


/**
 * @file
 * It is normal for Jool to not want to send ICMP error messages even if the RFC says so, because
 * some packets being translated are originated from the localhost.
 * Other times an error emerges while processing a inner packet (which is part of a ICMP error),
 * and it is well known that ICMP errors should not cause other ICMP errors.
 *
 * In these cases, the incoming socket buffer or its "dst" is NULL. While the kernel's icmp*_send()
 * functions are shielded against NULL skbs, NULL dsts cause kernel panics. And because we have to
 * check the dst, we also have to check the skb.
 * So it is convenient to have one-liners that take care of all of that.
 *
 * Direct use of the kernel's icmp*_send() functions anywhere in Jool is strongly discouraged.
 */

/**
 * Wrapper for the icmp_send() function.
 */
void icmp4_send(struct sk_buff *skb, int type, int code, __be32 info);
/**
 * Wrapper for the icmpv6_send() function.
 */
void icmp6_send(struct sk_buff *skb, u8 type, u8 code, __u32 info);


#endif /* _NF_NAT64_ICMP_WRAPPER_H */
