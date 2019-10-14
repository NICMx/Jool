#ifndef SRC_MOD_COMMON_CONFIG_H_
#define SRC_MOD_COMMON_CONFIG_H_

#include "common/config.h"

int globals_init(struct globals *config, xlator_type type,
		struct config_prefix6 *pool6);

#endif /* SRC_MOD_COMMON_CONFIG_H_ */
