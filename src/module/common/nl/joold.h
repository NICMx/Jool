#ifndef __NL_JOOLD_H__
#define __NL_JOOLD_H__

#include <net/genetlink.h>
#include "nat64/mod/common/xlator.h"

int handle_joold_request(struct xlator *jool, struct genl_info *info);

#endif
