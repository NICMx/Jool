#include "nl/nl-common.h"

#include "types.h"

int verify_privileges(void)
{
	if (!capable(CAP_NET_ADMIN)) {
		log_err("Administrative privileges required.");
		return -EPERM;
	}

	return 0;
}

struct request_hdr *get_jool_hdr(struct genl_info *info)
{
	/* TODO validate length? */
	return info->userhdr;
}

void *get_jool_payload(struct genl_info *info)
{
	return nla_data(info->attrs[ATTR_DATA]);
}
