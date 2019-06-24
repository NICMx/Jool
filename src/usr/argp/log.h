#ifndef SRC_USR_ARGP_LOG_H_
#define SRC_USR_ARGP_LOG_H_

#include <stdio.h>
#include "usr/util/result.h"

#define log_debug(text, ...) printf(text "\n", ##__VA_ARGS__)
#define log_info(text, ...) log_debug(text, ##__VA_ARGS__)
#define log_warn(text, ...) log_err("Warning: " text, ##__VA_ARGS__)
#define log_err(text, ...) fprintf(stderr, text "\n", ##__VA_ARGS__)
int log_result(struct jool_result *result);

#define log_delete(text, ...) log_err("DELETE ME! %s(%s:%d): " text, \
		__func__, __FILE__, __LINE__, ##__VA_ARGS__)

#endif /* SRC_USR_ARGP_LOG_H_ */
