#ifndef __NL_POOL6_H__
#define __NL_POOL6_H__

#include <net/genetlink.h>
#include "nat64/mod/common/xlator.h"

int handle_pool6_config(struct xlator *jool, struct genl_info *info);

#endif
