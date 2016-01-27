#include "nat64/mod/common/nl/nl_common.h"

#include "nat64/common/genetlink.h"
#include "nat64/mod/common/types.h"

int verify_superpriv(void)
{
	if (!capable(CAP_NET_ADMIN)) {
		log_err("Administrative privileges required.");
		return -EPERM;
	}

	return 0;
}

struct request_hdr *get_jool_hdr(struct genl_info *info)
{
	return (struct request_hdr *)(info->attrs[ATTR_DATA] + 1);
}
