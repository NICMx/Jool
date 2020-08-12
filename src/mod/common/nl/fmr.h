#ifndef SRC_MOD_COMMON_NL_FMR_H_
#define SRC_MOD_COMMON_NL_FMR_H_

#include <net/genetlink.h>

int handle_fmrt_foreach(struct sk_buff *skb, struct genl_info *info);
int handle_fmrt_add(struct sk_buff *skb, struct genl_info *info);

#endif /* SRC_MOD_COMMON_NL_FMR_H_ */
