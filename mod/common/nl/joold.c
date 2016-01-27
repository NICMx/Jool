#include "nat64/mod/common/nl/joold.h"

#include "nat64/mod/stateful/joold.h"
#include "nat64/mod/common/nl/nl_common.h"

int handle_joold_request(struct xlator *jool, struct genl_info *info)
{
	struct request_hdr *jool_hdr;
	__u8 *request_data;

	if (xlat_is_siit()) {
		log_err("SIIT Jool doesn't need a synchronization daemon.");
		return -EINVAL;
	}

	jool_hdr = get_jool_hdr(info);
	request_data = (__u8 *)(jool_hdr + 1);
	return joold_sync_entries(jool, request_data, jool_hdr->length);
}
