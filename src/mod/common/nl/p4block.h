#ifndef SRC_MOD_COMMON_NL_P4BLOCK_H_
#define SRC_MOD_COMMON_NL_P4BLOCK_H_

#include <net/genetlink.h>

int handle_p4block_foreach(struct sk_buff *skb, struct genl_info *info);
int handle_p4block_add(struct sk_buff *skb, struct genl_info *info);
int handle_p4block_rm(struct sk_buff *skb, struct genl_info *info);

#endif /* SRC_MOD_COMMON_NL_P4BLOCK_H_ */
