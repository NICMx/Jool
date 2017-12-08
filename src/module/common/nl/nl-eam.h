#ifndef __NL_EAM_H__
#define __NL_EAM_H__

#include <net/genetlink.h>
#include "xlator.h"

int handle_eamt_config(struct xlator *jool, struct genl_info *info);

#endif
