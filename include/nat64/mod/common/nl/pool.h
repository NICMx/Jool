#ifndef __NL_POOL_H__
#define __NL_POOL_H__

#include <net/genetlink.h>
#include "nat64/mod/common/xlator.h"

int handle_blacklist_config(struct xlator *jool, struct genl_info *info);
int handle_pool6791_config(struct xlator *jool, struct genl_info *info);

#endif
