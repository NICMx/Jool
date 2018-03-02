#ifndef __NL_GLOBAL_H__
#define __NL_GLOBAL_H__

#include <linux/skbuff.h>
#include <net/genetlink.h>

int handle_global_display(struct sk_buff *skb, struct genl_info *info);
int handle_global_update(struct sk_buff *skb, struct genl_info *info);

#endif
