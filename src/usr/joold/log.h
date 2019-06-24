#ifndef SRC_USR_JOOLD_LOG_H_
#define SRC_USR_JOOLD_LOG_H_

#include <syslog.h>
#include "usr/util/result.h"

#define log_debug(text, ...) syslog(LOG_DEBUG, text, ##__VA_ARGS__)
#define log_info(text, ...) syslog(LOG_INFO, text, ##__VA_ARGS__)
#define log_err(text, ...) syslog(LOG_ERR, text, ##__VA_ARGS__)
int log_result(struct jool_result *result);

/**
 * perror() writes into stderror. joold doesn't want that so here's the
 * replacement.
 *
 * This also thread safe.
 *
 * ** perror() should not be used anywhere in this project! **
 */
void log_perror(char *prefix, int error);

#endif /* SRC_USR_JOOLD_LOG_H_ */
