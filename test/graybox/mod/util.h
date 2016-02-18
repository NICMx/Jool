#ifndef FRAGS_MOD_UTIL_H
#define FRAGS_MOD_UTIL_H

#include <linux/skbuff.h>

int ip6_local_out_wrapped(struct sk_buff *skb);
int ip_local_out_wrapped(struct sk_buff *skb);

#endif
