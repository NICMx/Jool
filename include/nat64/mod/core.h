#ifndef _NF_NAT64_CORE_H
#define _NF_NAT64_CORE_H

/**
 * @file
 * The core is the packet handling's highest layer.
 *
 * @author Miguel Gonzalez
 * @author Ramiro Nava
 * @author Roberto Aceves
 * @author Alberto Leiva
 */

#include <linux/skbuff.h>


unsigned int core_6to4(struct sk_buff *skb);
unsigned int core_4to6(struct sk_buff *skb);


#endif /* _NF_NAT64_CORE_H */
