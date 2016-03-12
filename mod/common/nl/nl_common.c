#include "nat64/mod/common/nl/nl_common.h"

#include "nat64/common/types.h"

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
	return nla_data(info->attrs[ATTR_DATA]);
}

int validate_request_size(struct genl_info *info, size_t min_expected)
{
	size_t request_size = nla_len(info->attrs[ATTR_DATA]);

	min_expected += sizeof(struct request_hdr);
	if (request_size < min_expected) {
		log_err("The minimum expected request size was %zu bytes; got %zu instead.",
				min_expected, request_size);
		return -EINVAL;
	}

	return 0;
}
