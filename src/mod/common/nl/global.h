#ifndef __NL_GLOBAL_H__
#define __NL_GLOBAL_H__

#include <net/genetlink.h>
#include "mod/common/xlator.h"

int handle_global_config(struct xlator *jool, struct genl_info *info);

/* Helper for atomic configuration. */
int global_update(struct global_config *cfg, bool force,
		struct global_value *request, size_t request_size);

#endif
