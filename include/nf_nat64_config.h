#ifndef NF_NAT64_CONFIG_H_
#define NF_NAT64_CONFIG_H_

/**
 * @file
 * The NAT64's layer/bridge towards the user. S/he can control its behavior using this.
 *
 * @author Miguel Gonzalez
 * @author Alberto Leiva  <- maintenance
 */

#include <linux/types.h>


/**
 * Initializes this module. Sets default values for the entire configuration.
 *
 * @return "true" if initialization was successful, "false" otherwise.
 */
bool nat64_config_init(void);
/**
 * Terminates this module. Deletes any memory left on the heap.
 */
void nat64_config_destroy(void);


#endif /* NF_NAT64_CONFIG_H_ */
