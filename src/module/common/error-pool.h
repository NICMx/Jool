#ifndef _JOOL_MOD_ERROR_POOL_H
#define _JOOL_MOD_ERROR_POOL_H

#include <linux/types.h>

void errormsg_enable(void);
void errormsg_add(int len, const char *fmt, ...);
int errormsg_get(char **out_message, size_t *msg_len);
void errormsg_disable(void);

#endif
