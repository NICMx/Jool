#ifndef SRC_MOD_COMMON_NL_POOL4_H_
#define SRC_MOD_COMMON_NL_POOL4_H_

#include <net/genetlink.h>
#include "mod/common/xlator.h"

int handle_pool4_config(struct xlator *jool, struct genl_info *info);

#endif /* SRC_MOD_COMMON_NL_POOL4_H_ */
