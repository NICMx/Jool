#include "nat64/mod/common/nl/joold.h"

#include "nat64/mod/stateful/joold.h"
#include "nat64/mod/common/nl/nl_common.h"
#include "nat64/mod/common/nl/nl_core2.h"

int handle_joold_request(struct xlator *jool, struct genl_info *info)
{
	struct request_hdr *hdr;
	int error;

	if (xlat_is_siit()) {
		log_err("SIIT Jool doesn't need a synchronization daemon.");
		return nlcore_respond(info, -EINVAL);
	}

	hdr = get_jool_hdr(info);
	error = joold_sync_entries(jool, hdr + 1, hdr->length - sizeof(*hdr));
	return nlcore_respond(info, error);
}
