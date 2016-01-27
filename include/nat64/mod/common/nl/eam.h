#ifndef __NL_EAM_H__
#define __NL_EAM_H__

#include <net/genetlink.h>
#include "nat64/mod/stateless/eam.h"

int handle_eamt_config(struct eam_table *eamt, struct genl_info *info);

#endif
