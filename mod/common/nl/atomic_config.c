#include "nat64/mod/common/nl/atomic_config.h"

#include "nat64/mod/common/nl/nl_common.h"
#include "nat64/mod/common/nl/nl_core2.h"
#include "nat64/mod/common/atomic_config.h"

int handle_atomconfig_request(struct xlator *jool, struct genl_info *info)
{
	struct request_hdr *hdr;
	int error;

	hdr = get_jool_hdr(info);
	error = atomconfig_add(jool, hdr + 1, hdr->length - sizeof(*hdr));
	return nlcore_respond(info, error);
}
