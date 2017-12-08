#include "nat64/mod/common/nl/atomic_config.h"

#include "nat64/mod/common/nl/nl_common.h"
#include "nat64/mod/common/nl/nl_core2.h"
#include "nat64/mod/common/atomic_config.h"

int handle_atomconfig_request(struct xlator *jool, struct genl_info *info)
{
	struct request_hdr *hdr;
	size_t total_len;
	int error;

	if (verify_superpriv())
		return nlcore_respond(info, -EPERM);

	hdr = nla_data(info->attrs[ATTR_DATA]);
	total_len = nla_len(info->attrs[ATTR_DATA]);

	error = atomconfig_add(jool, hdr + 1, total_len - sizeof(*hdr));
	return nlcore_respond(info, error);
}
