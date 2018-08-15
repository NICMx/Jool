#ifndef INCLUDE_NAT64_MOD_COMMON_SKBUFF_H_
#define INCLUDE_NAT64_MOD_COMMON_SKBUFF_H_

#include <linux/skbuff.h>

void skb_log(struct sk_buff *skb, char *label);

#endif /* INCLUDE_NAT64_MOD_COMMON_SKBUFF_H_ */
