#ifndef __NL_SESSION_H__
#define __NL_SESSION_H__

#include <linux/skbuff.h>
#include <net/genetlink.h>

int handle_session_foreach(struct sk_buff *skb, struct genl_info *info);

#endif
