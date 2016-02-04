#ifndef __NL_SESSION_H__
#define __NL_SESSION_H__

#include <net/genetlink.h>
#include "nat64/mod/common/xlator.h"

int handle_session_config(struct xlator *jool, struct genl_info *info);

#endif
