#ifndef _JOOL_MOD_NL_HANDLER_H
#define _JOOL_MOD_NL_HANDLER_H

/**
 * @file
 * The NAT64's layer/bridge towards the user. S/he can control its behavior
 * using this.
 */

int nlhandler_init(void);
void nlhandler_destroy(void);

#endif /* _JOOL_MOD_NL_HANDLER_H */
