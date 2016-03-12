#ifndef _JOOL_MOD_NL_HANDLER_H
#define _JOOL_MOD_NL_HANDLER_H

/**
 * @file
 * The NAT64's layer/bridge towards the user. S/he can control its behavior
 * using this.
 */

#include <linux/skbuff.h>
#include <net/genetlink.h>

int nlhandler_init(void);
void nlhandler_destroy(void);

int handle_jool_message(struct sk_buff *skb, struct genl_info *info);

#endif /* _JOOL_MOD_NL_HANDLER_H */
