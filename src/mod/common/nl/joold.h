#ifndef SRC_MOD_COMMON_NL_JOOLD_H_
#define SRC_MOD_COMMON_NL_JOOLD_H_

#include <net/genetlink.h>
#include "mod/common/xlator.h"

int handle_joold_request(struct xlator *jool, struct genl_info *info);

#endif /* SRC_MOD_COMMON_NL_JOOLD_H_ */
