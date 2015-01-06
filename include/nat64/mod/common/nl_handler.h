#ifndef _JOOL_MOD_NL_HANDLER_H
#define _JOOL_MOD_NL_HANDLER_H

/**
 * @file
 * The NAT64's layer/bridge towards the user. S/he can control its behavior using this.
 *
 * @author Miguel Gonzalez
 * @author Alberto Leiva
 */

#include <linux/netlink.h>

/**
 * Activates this module. The module will then listen to user requests on its own.
 */
int nlhandler_init(void);
/**
 * Terminates this module. Deletes any memory left on the heap.
 */
void nlhandler_destroy(void);

#endif /* _JOOL_MOD_NL_HANDLER_H */
