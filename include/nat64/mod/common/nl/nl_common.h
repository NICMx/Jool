#ifndef __NL_COMMON_H__
#define __NL_COMMON_H__

#include <net/genetlink.h>
#include "nat64/common/config.h"

int verify_superpriv(void);
struct request_hdr *get_jool_hdr(struct genl_info *info);
int validate_request_size(struct genl_info *info, size_t min_expected);

#endif
