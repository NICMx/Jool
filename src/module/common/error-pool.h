#ifndef _JOOL_MOD_ERROR_POOL_H
#define _JOOL_MOD_ERROR_POOL_H

#include <linux/types.h>

void error_pool_init(void);
void error_pool_destroy(void);

void error_pool_activate(void);
int error_pool_add_message(char * msg);
int error_pool_has_errors(void);
int error_pool_get_message(char **out_message, size_t *msg_len);
void error_pool_deactivate(void);

#endif
