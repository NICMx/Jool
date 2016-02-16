#include "nat64/mod/common/error_pool.h"
#include <linux/errno.h>

void error_pool_init(void)
{
	/* No code. */
}

void error_pool_destroy(void)
{
	/* No code. */
}

int error_pool_add_message(char *msg)
{
	return 0;
}

int error_pool_get_message(char **out_message, size_t *msg_len)
{
	return -EINVAL;
}

