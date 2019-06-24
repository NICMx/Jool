#ifndef SRC_MOD_COMMON_NL_BIB_H_
#define SRC_MOD_COMMON_NL_BIB_H_

#include <net/genetlink.h>
#include "mod/common/xlator.h"

int handle_bib_config(struct xlator *jool, struct genl_info *info);

#endif /* SRC_MOD_COMMON_NL */
