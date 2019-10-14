#include "mod/common/nl/eam.h"

#include "common/types.h"
#include "mod/common/log.h"
#include "mod/common/nl/nl_common.h"
#include "mod/common/nl/nl_core.h"
#include "mod/common/db/eam.h"

static int eam_entry_to_userspace(struct eamt_entry const *entry, void *arg)
{
	struct nlcore_buffer *buffer = (struct nlcore_buffer *)arg;
	return nlbuffer_write(buffer, entry, sizeof(*entry));
}

static int handle_eamt_display(struct eam_table *eamt, struct genl_info *info,
		union request_eamt *request)
{
	struct nlcore_buffer buffer;
	struct ipv4_prefix *prefix4;
	int error;

	log_debug("Sending EAMT to userspace.");

	error = nlbuffer_init_response(&buffer, info, nlbuffer_response_max_size());
	if (error)
		return nlcore_respond(info, error);

	prefix4 = request->foreach.prefix4_set ? &request->foreach.prefix4 : NULL;
	error = eamt_foreach(eamt, eam_entry_to_userspace, &buffer, prefix4);
	nlbuffer_set_pending_data(&buffer, error > 0);
	error = (error >= 0)
			? nlbuffer_send(info, &buffer)
			: nlcore_respond(info, error);

	nlbuffer_clean(&buffer);
	return error;
}

static int handle_eamt_add(struct eam_table *eamt, union request_eamt *request,
		bool force)
{
	log_debug("Adding EAMT entry.");
	return eamt_add(eamt, &request->add.prefix6, &request->add.prefix4,
			force);
}

static int handle_eamt_rm(struct eam_table *eamt, union request_eamt *request)
{
	struct ipv6_prefix *prefix6;
	struct ipv4_prefix *prefix4;

	log_debug("Removing EAMT entry.");

	prefix6 = request->rm.prefix6_set ? &request->rm.prefix6 : NULL;
	prefix4 = request->rm.prefix4_set ? &request->rm.prefix4 : NULL;
	return eamt_rm(eamt, prefix6, prefix4);
}

static int handle_eamt_flush(struct eam_table *eamt)
{
	eamt_flush(eamt);
	return 0;
}

int handle_eamt_config(struct xlator *jool, struct genl_info *info)
{
	struct request_hdr *hdr;
	union request_eamt *request;
	int error;

	if (xlator_is_nat64(jool)) {
		log_err("Stateful NAT64 doesn't have an EAMT.");
		return nlcore_respond(info, -EINVAL);
	}

	hdr = get_jool_hdr(info);
	request = (union request_eamt *)(hdr + 1);

	error = validate_request_size(info, sizeof(*request));
	if (error)
		return nlcore_respond(info, error);

	switch (hdr->operation) {
	case OP_FOREACH:
		return handle_eamt_display(jool->siit.eamt, info, request);
	case OP_ADD:
		error = handle_eamt_add(jool->siit.eamt, request, hdr->force);
		break;
	case OP_REMOVE:
		error = handle_eamt_rm(jool->siit.eamt, request);
		break;
	case OP_FLUSH:
		error = handle_eamt_flush(jool->siit.eamt);
		break;
	default:
		log_err("Unknown operation: %u", hdr->operation);
		error = -EINVAL;
	}

	return nlcore_respond(info, error);
}
