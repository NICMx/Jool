#ifndef __NL_GLOBAL_H__
#define __NL_GLOBAL_H__

#include <net/genetlink.h>
#include "xlator.h"

int handle_global_config(struct xlator *jool, struct genl_info *info);

#endif
