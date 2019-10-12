#ifndef SRC_MOD_COMMON_ATOMIC_CONFIG_H_
#define SRC_MOD_COMMON_ATOMIC_CONFIG_H_

#include "common/config.h"

int atomconfig_add(char *iname, xlator_type xt, void *config, size_t config_len,
		bool force);

#endif /* SRC_MOD_COMMON_ATOMIC_CONFIG_H_ */
