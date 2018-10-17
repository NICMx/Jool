#include "mod/common/nl/atomic_config.h"

#include "mod/common/nl/nl_common.h"
#include "mod/common/nl/nl_core2.h"
#include "mod/common/atomic_config.h"

int handle_atomconfig_request(struct genl_info *info)
{
	struct request_hdr *hdr;
	size_t total_len;

	hdr = nla_data(info->attrs[ATTR_DATA]);
	total_len = nla_len(info->attrs[ATTR_DATA]);

	return nlcore_respond(info, atomconfig_add(get_iname(info), hdr + 1,
			total_len - sizeof(*hdr), hdr->force));
}
