#ifndef _JOOL_USR_LOG_H
#define _JOOL_USR_LOG_H

#ifdef JOOLD

#include <syslog.h>
#define log_debug(text, ...) syslog(LOG_DEBUG, text, ##__VA_ARGS__)
#define log_info(text, ...) syslog(LOG_INFO, text, ##__VA_ARGS__)
#define log_err(text, ...) syslog(LOG_ERR, text, ##__VA_ARGS__)

#else

#include <stdio.h>
#define log_debug(text, ...) printf(text "\n", ##__VA_ARGS__)
#define log_info(text, ...) log_debug(text, ##__VA_ARGS__)
#define log_err(text, ...) fprintf(stderr, text "\n", ##__VA_ARGS__)

#endif

/**
 * perror() writes into stderror. joold doesn't want that so here's the
 * replacement.
 *
 * This also thread safe.
 *
 * ** perror() should not be used anywhere in this project! **
 */
void log_perror(char *prefix, int error);

#endif /* _JOOL_USR_LOG_H */
