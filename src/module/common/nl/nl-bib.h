#ifndef __NL_BIB_H__
#define __NL_BIB_H__

#include <linux/skbuff.h>
#include <net/genetlink.h>

int handle_bib_foreach(struct sk_buff *skb, struct genl_info *info);
int handle_bib_add(struct sk_buff *skb, struct genl_info *info);
int handle_bib_rm(struct sk_buff *skb, struct genl_info *info);

#endif
