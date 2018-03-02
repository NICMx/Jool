#ifndef __NL_POOL4_H__
#define __NL_POOL4_H__

#include <linux/skbuff.h>
#include <net/genetlink.h>

int handle_pool4_foreach(struct sk_buff *skb, struct genl_info *info);
int handle_pool4_add(struct sk_buff *skb, struct genl_info *info);
int handle_pool4_rm(struct sk_buff *skb, struct genl_info *info);
int handle_pool4_flush(struct sk_buff *skb, struct genl_info *info);

#endif
