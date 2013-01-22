#ifndef NF_NAT64_CONFIG_H_
#define NF_NAT64_CONFIG_H_


#ifdef __KERNEL__
	#include <linux/in.h>
	#include <linux/in6.h>
#else
	#include <netinet/in.h>
	#include <stdbool.h>
	#include <asm/types.h>
#endif
#include "xt_nat64_module_comm.h"


/**
 * Initializes this module. Sets default values for the entire configuration.
 *
 * TODO (info) no deberían ser invisibles desde userspace?
 *
 * @return "true" if initialization was successful, "false" otherwise.
 */
bool nat64_config_init(void);
/**
 * Terminates this module. Deletes any memory left on the heap.
 */
void nat64_config_destroy(void);

bool ipv6_prefix_equals(struct ipv6_prefix *expected, struct ipv6_prefix *actual);


#endif /* NF_NAT64_CONFIG_H_ */
