#ifndef TEST_GRAYBOX_USR_LOG_H_
#define TEST_GRAYBOX_USR_LOG_H_

int pr_err(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
int pr_enomem(void);

#endif /* TEST_GRAYBOX_USR_LOG_H_ */
