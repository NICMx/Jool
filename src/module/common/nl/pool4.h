#ifndef __NL_POOL4_H__
#define __NL_POOL4_H__

#include <net/genetlink.h>
#include "nat64/mod/common/xlator.h"

int handle_pool4_config(struct xlator *jool, struct genl_info *info);

#endif
