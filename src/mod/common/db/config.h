#ifndef SRC_MOD_COMMON_CONFIG_H_
#define SRC_MOD_COMMON_CONFIG_H_

#include "common/config.h"

int globals_init(struct globals *config, xlator_type type,
		struct ipv6_prefix *pool6);

#endif /* SRC_MOD_COMMON_CONFIG_H_ */
