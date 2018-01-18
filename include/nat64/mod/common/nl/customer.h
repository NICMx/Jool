#ifndef __NL_CUSTOMER_H__
#define __NL_CUSTOMER_H__

#include <net/genetlink.h>
#include "nat64/mod/common/xlator.h"

int handle_customer_config(struct xlator *jool, struct genl_info *info);

#endif
