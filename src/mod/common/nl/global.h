#ifndef SRC_MOD_COMMON_NL_GLOBAL_H_
#define SRC_MOD_COMMON_NL_GLOBAL_H_

#include <net/genetlink.h>
#include "mod/common/xlator.h"

int handle_global_config(struct xlator *jool, struct genl_info *info);

/* Helper for atomic configuration. */
int global_update(struct global_config *cfg, bool force,
		struct global_value *request, size_t request_size);

#endif /* SRC_MOD_COMMON_NL_GLOBAL_H_ */
