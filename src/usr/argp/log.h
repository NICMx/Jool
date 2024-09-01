#ifndef SRC_USR_ARGP_LOG_H_
#define SRC_USR_ARGP_LOG_H_

#include "usr/util/result.h"

#if __GNUC__
#define CHECK_FORMAT(str, args) __attribute__((format(printf, str, args)))
#else
#define CHECK_FORMAT(str, args) /* Nothing */
#endif

void pr_warn(const char *fmt, ...) CHECK_FORMAT(1, 2);
void pr_err(const char *fmt, ...) CHECK_FORMAT(1, 2);
int pr_result(struct jool_result *result);
int pr_enomem(void);
int pr_result_syslog(struct jool_result *result);
void pr_perror(char *prefix, int error);

#endif /* SRC_USR_ARGP_LOG_H_ */
