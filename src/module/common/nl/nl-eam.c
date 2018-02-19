#include "nl/nl-eam.h"

#include "types.h"
#include "nl/nl-common.h"
#include "nl/nl-core.h"
#include "siit/eam.h"

static int eam_entry_to_userspace(struct eamt_entry *entry, void *arg)
{
	struct nlcore_buffer *buffer = (struct nlcore_buffer *)arg;
	return nlbuffer_write(buffer, entry, sizeof(*entry));
}

static int handle_eamt_display(struct eam_table *eamt, struct genl_info *info,
		struct request_eamt_display *request)
{
	struct nlcore_buffer buffer;
	struct ipv4_prefix *prefix4;
	int error;

	log_debug("Sending EAMT to userspace.");

	error = nlbuffer_init_response(&buffer, info, nlbuffer_response_max_size());
	if (error)
		nlcore_respond(info, error);

	prefix4 = request->prefix4_set ? &request->prefix4 : NULL;
	error = eamt_foreach(eamt, eam_entry_to_userspace, &buffer, prefix4);
	nlbuffer_set_pending_data(&buffer, error > 0);
	error = (error >= 0)
			? nlbuffer_send(info, &buffer)
			: nlcore_respond(info, error);

	nlbuffer_free(&buffer);
	return error;
}

static int handle_eamt_add(struct eam_table *eamt,
		struct request_eamt_add *request)
{
	if (verify_privileges())
		return -EPERM;

	log_debug("Adding EAMT entry.");
	return eamt_add(eamt, &request->prefix6, &request->prefix4,
			request->force);
}

static int handle_eamt_rm(struct eam_table *eamt,
		struct request_eamt_rm *request)
{
	struct ipv6_prefix *prefix6;
	struct ipv4_prefix *prefix4;

	if (verify_privileges())
		return -EPERM;

	log_debug("Removing EAMT entry.");

	prefix6 = request->prefix6_set ? &request->prefix6 : NULL;
	prefix4 = request->prefix4_set ? &request->prefix4 : NULL;
	return eamt_rm(eamt, prefix6, prefix4);
}

static int handle_eamt_flush(struct eam_table *eamt)
{
	if (verify_privileges())
		return -EPERM;

	eamt_flush(eamt);
	return 0;
}

int handle_eamt_config(struct xlator *jool, struct genl_info *info)
{
	struct request_hdr *hdr = get_jool_hdr(info);
	void *payload = get_jool_payload(info);
	int error;

	switch (be16_to_cpu(hdr->operation)) {
	case OP_DISPLAY:
		return handle_eamt_display(jool->eamt, info, payload);
	case OP_ADD:
		error = handle_eamt_add(jool->eamt, payload);
		break;
	case OP_REMOVE:
		error = handle_eamt_rm(jool->eamt, payload);
		break;
	case OP_FLUSH:
		error = handle_eamt_flush(jool->eamt);
		break;
	default:
		log_err("Unknown operation: %u", be16_to_cpu(hdr->operation));
		error = -EINVAL;
	}

	return nlcore_respond(info, error);
}
