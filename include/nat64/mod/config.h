#ifndef _JOOL_MOD_CONFIG_H
#define _JOOL_MOD_CONFIG_H

/**
 * @file
 * The NAT64's layer/bridge towards the user. S/he can control its behavior using this.
 *
 * @author Miguel Gonzalez
 * @author Alberto Leiva
 */

/**
 * Activates this module. The module will then listen to user requests on its own.
 */
int config_init(void);
/**
 * Terminates this module. Deletes any memory left on the heap.
 */
void config_destroy(void);

#endif /* _JOOL_MOD_CONFIG_H */
