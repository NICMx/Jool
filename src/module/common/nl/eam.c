#include "nat64/mod/common/nl/eam.h"

#include "nat64/common/types.h"
#include "nat64/mod/common/nl/nl_common.h"
#include "nat64/mod/common/nl/nl_core2.h"
#include "nat64/mod/stateless/eam.h"

static int eam_entry_to_userspace(struct eamt_entry *entry, void *arg)
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
		nlcore_respond(info, error);

	prefix4 = request->display.prefix4_set ? &request->display.prefix4 : NULL;
	error = eamt_foreach(eamt, eam_entry_to_userspace, &buffer, prefix4);
	nlbuffer_set_pending_data(&buffer, error > 0);
	error = (error >= 0)
			? nlbuffer_send(info, &buffer)
			: nlcore_respond(info, error);

	nlbuffer_free(&buffer);
	return error;
}

static int handle_eamt_count(struct eam_table *eamt, struct genl_info *info)
{
	__u64 count;
	int error;

	log_debug("Returning EAMT count.");

	error = eamt_count(eamt, &count);
	if (error)
		return nlcore_respond(info, error);

	return nlcore_respond_struct(info, &count, sizeof(count));
}

static int handle_eamt_add(struct eam_table *eamt, union request_eamt *request)
{
	if (verify_superpriv())
		return -EPERM;

	log_debug("Adding EAMT entry.");
	return eamt_add(eamt, &request->add.prefix6, &request->add.prefix4,
			request->add.force);
}

static int handle_eamt_rm(struct eam_table *eamt, union request_eamt *request)
{
	struct ipv6_prefix *prefix6;
	struct ipv4_prefix *prefix4;

	if (verify_superpriv())
		return -EPERM;

	log_debug("Removing EAMT entry.");

	prefix6 = request->rm.prefix6_set ? &request->rm.prefix6 : NULL;
	prefix4 = request->rm.prefix4_set ? &request->rm.prefix4 : NULL;
	return eamt_rm(eamt, prefix6, prefix4);
}

static int handle_eamt_flush(struct eam_table *eamt)
{
	if (verify_superpriv())
		return -EPERM;

	eamt_flush(eamt);
	return 0;
}

int handle_eamt_config(struct xlator *jool, struct genl_info *info)
{
	struct request_hdr *hdr;
	union request_eamt *request;
	int error;

	if (xlat_is_nat64()) {
		log_err("Stateful NAT64 doesn't have an EAMT.");
		return nlcore_respond(info, -EINVAL);
	}

	hdr = get_jool_hdr(info);
	request = (union request_eamt *)(hdr + 1);

	error = validate_request_size(info, sizeof(*request));
	if (error)
		return nlcore_respond(info, error);

	switch (be16_to_cpu(hdr->operation)) {
	case OP_DISPLAY:
		return handle_eamt_display(jool->siit.eamt, info, request);
	case OP_COUNT:
		return handle_eamt_count(jool->siit.eamt, info);
	case OP_ADD:
		error = handle_eamt_add(jool->siit.eamt, request);
		break;
	case OP_REMOVE:
		error = handle_eamt_rm(jool->siit.eamt, request);
		break;
	case OP_FLUSH:
		error = handle_eamt_flush(jool->siit.eamt);
		break;
	default:
		log_err("Unknown operation: %u", be16_to_cpu(hdr->operation));
		error = -EINVAL;
	}

	return nlcore_respond(info, error);
}
