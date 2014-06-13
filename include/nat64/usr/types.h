#ifndef _NF_NAT64_TYPES_USR_H
#define _NF_NAT64_TYPES_USR_H

#include "nat64/comm/types.h"


#define log_debug(text, ...) printf(text "\n", ##__VA_ARGS__)
#define log_info(text, ...) log_debug(text, ##__VA_ARGS__)
#define log_err(text, ...) log_debug(text, ##__VA_ARGS__)


#endif /* _NF_NAT64_TYPES_USR_H */
