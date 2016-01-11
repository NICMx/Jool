#include "nat64/mod/stateful/joold.h"
#include "nat64/mod/common/nl/nl_core2.h"

int handle_joold_request(struct genl_info *info)
{
	struct request_hdr *jool_hdr;
	__u8* request_data;

	jool_hdr = (struct request_hdr *) (info->attrs[ATTR_DATA] + 1);
	request_data = (__u8*)(jool_hdr + 1);

	if (xlat_is_siit()) {
		log_err("SIIT Jool doesn't need a synchronization daemon.");
		return -EINVAL;
	}

	return joold_sync_entires(request_data, jool_hdr->length);
}

