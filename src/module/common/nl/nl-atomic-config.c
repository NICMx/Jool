#include "atomic-config.h"

#include "nl/nl-common.h"
#include "nl/nl-core.h"
#include "common/atomic-config.h"

int handle_atomconfig_request(struct xlator *jool, struct genl_info *info)
{
	struct request_hdr *hdr;
	size_t total_len;
	int error;

	if (verify_privileges())
		return jnl_respond(info, -EPERM);

	hdr = nla_data(info->attrs[ATTR_DATA]);
	total_len = nla_len(info->attrs[ATTR_DATA]);

	error = atomconfig_add(jool, hdr + 1, total_len - sizeof(*hdr));
	return jnl_respond(info, error);
}
