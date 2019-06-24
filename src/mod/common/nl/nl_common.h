#ifndef SRC_MOD_COMMON_NL_COMMON_H_
#define SRC_MOD_COMMON_NL_COMMON_H_

#include <net/genetlink.h>
#include "common/config.h"

int verify_superpriv(void);
struct request_hdr *get_jool_hdr(struct genl_info *info);
int validate_request_size(struct genl_info *info, size_t min_expected);
char *get_iname(struct genl_info *info);

#endif /* SRC_MOD_COMMON_NL_COMMON_H_ */
