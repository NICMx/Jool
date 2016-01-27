#ifndef __NL_POOL_H__
#define __NL_POOL_H__

#include <net/genetlink.h>
#include "nat64/common/config.h"
#include "nat64/mod/stateless/pool.h"

int handle_addr4pool_config(struct addr4_pool *pool, enum config_mode command,
		struct genl_info *info);

#endif
