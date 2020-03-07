#include "mod/common/nl/joold.h"

#include "mod/common/log.h"
#include "mod/common/nl/nl_common.h"
#include "mod/common/nl/nl_core.h"
#include "mod/common/joold.h"

int handle_joold_request(struct xlator *jool, struct genl_info *info)
{
	struct joolnl_hdr *hdr;
	size_t total_len;
	int error;

	log_debug("Received a joold request.");

	if (xlator_is_siit(jool)) {
		log_err("SIIT Jool doesn't need a synchronization daemon.");
		return jresponse_send_simple(info, -EINVAL);
	}

	hdr = get_jool_hdr(info);

	switch (hdr->operation) {
	case OP_ADD:
		total_len = nla_len(info->attrs[ATTR_DATA]);
		error = joold_sync(jool, hdr + 1, total_len - sizeof(*hdr));
		if (!error) {
			/*
			 * Do not bother userspace with an ACK; it's not
			 * waiting nor has anything to do with it.
			 */
			return 0;
		}
		break;
	case OP_TEST:
		error = joold_test(jool);
		break;
	case OP_ADVERTISE:
		error = joold_advertise(jool);
		break;
	case OP_ACK:
		joold_ack(jool);
		return 0; /* Do not ack the ack! */
	default:
		log_err("Unknown operation: %u", hdr->operation);
		error = -EINVAL;
	}

	return jresponse_send_simple(info, error);
}
