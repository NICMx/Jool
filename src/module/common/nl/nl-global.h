#ifndef __NL_GLOBAL_H__
#define __NL_GLOBAL_H__

#include <net/genetlink.h>
#include "xlator.h"

int handle_global_config(struct xlator *jool, struct genl_info *info);
int config_parse(struct full_config *config, void *payload, size_t payload_len);

#endif
