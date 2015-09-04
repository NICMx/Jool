#ifndef _JOOL_USR_TYPES_H
#define _JOOL_USR_TYPES_H

#include "nat64/common/types.h"


#define log_debug(text, ...) printf(text "\n", ##__VA_ARGS__)
#define log_info(text, ...) log_debug(text, ##__VA_ARGS__)
#define log_err(text, ...) fprintf(stderr, text "\n", ##__VA_ARGS__)


#endif /* _JOOL_USR_TYPES_H */
