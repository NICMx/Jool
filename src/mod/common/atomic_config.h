#ifndef SRC_MOD_COMMON_ATOMIC_CONFIG_H_
#define SRC_MOD_COMMON_ATOMIC_CONFIG_H_

#include "mod/common/nl/nl_common.h"

void atomconfig_teardown(void);
int atomconfig_add(struct jnl_state *state, struct genl_info const *info);

#endif /* SRC_MOD_COMMON_ATOMIC_CONFIG_H_ */
