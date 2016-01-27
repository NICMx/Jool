#ifndef __NL_BIB_H__
#define __NL_BIB_H__

#include <net/genetlink.h>
#include "nat64/mod/common/namespace.h"

int handle_bib_config(struct xlator *jool, struct genl_info *info);

#endif
