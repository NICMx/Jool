#ifndef __NL_INSTANCE_H__
#define __NL_INSTANCE_H__

#include <linux/skbuff.h>
#include <net/genetlink.h>

int handle_instance_add(struct sk_buff *skb, struct genl_info *info);
int handle_instance_rm(struct sk_buff *skb, struct genl_info *info);

#endif
