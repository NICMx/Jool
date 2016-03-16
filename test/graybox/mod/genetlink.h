#ifndef _GRAYBOX_MOD_GENETLINK_H
#define _GRAYBOX_MOD_GENETLINK_H

#include <net/genetlink.h>

void genl_init(struct genl_family *family);
/* There's no genl_destroy; just unregister the family. */

int genl_respond(struct genl_info *info, int error);
int genl_respond_attr(struct genl_info *info, int attr_id, void *attr,
		size_t attr_len);

#endif
