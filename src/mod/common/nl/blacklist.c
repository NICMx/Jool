#include "mod/common/nl/blacklist.h"

#include "common/types.h"
#include "mod/common/nl/nl_common.h"
#include "mod/common/nl/nl_core2.h"
#include "mod/siit/pool.h"

static int pool_to_usr(struct ipv4_prefix *prefix, void *arg)
{
	return nlbuffer_write(arg, prefix, sizeof(*prefix));
}

static int handle_blacklist_display(struct addr4_pool *pool,
		struct genl_info *info, union request_blacklist *request)
{
	struct nlcore_buffer buffer;
	struct ipv4_prefix *offset;
	int error;

	log_debug("Sending the blacklist to userspace.");

	error = nlbuffer_init_response(&buffer, info, nlbuffer_response_max_size());
	if (error)
		return nlcore_respond(info, error);

	offset = request->display.offset_set ? &request->display.offset : NULL;
	error = pool_foreach(pool, pool_to_usr, &buffer, offset);
	nlbuffer_set_pending_data(&buffer, error > 0);
	error = (error >= 0)
			? nlbuffer_send(info, &buffer)
			: nlcore_respond(info, error);

	nlbuffer_clean(&buffer);
	return error;
}

static int handle_blacklist_add(struct addr4_pool *pool,
		union request_blacklist *request, bool force)
{
	log_debug("Adding an address to the blacklist.");
	return pool_add(pool, &request->add.addrs, force);
}

static int handle_blacklist_rm(struct addr4_pool *pool,
		union request_blacklist *request)
{
	log_debug("Removing an address from the blacklist.");
	return pool_rm(pool, &request->rm.addrs);
}

static int handle_blacklist_flush(struct addr4_pool *pool)
{
	log_debug("Flushing the blacklist...");
	return pool_flush(pool);
}

int handle_blacklist_config(struct xlator *jool, struct genl_info *info)
{
	struct request_hdr *hdr = get_jool_hdr(info);
	union request_blacklist *request = (union request_blacklist *)(hdr + 1);
	int error;

	if (xlat_is_nat64()) {
		log_err("Stateful NAT64 doesn't have a blacklist.");
		return nlcore_respond(info, -EINVAL);
	}

	error = validate_request_size(info, sizeof(*request));
	if (error)
		return nlcore_respond(info, error);

	switch (hdr->operation) {
	case OP_FOREACH:
		return handle_blacklist_display(jool->siit.blacklist, info,
				request);
	case OP_ADD:
		error = handle_blacklist_add(jool->siit.blacklist, request,
				hdr->force);
		break;
	case OP_REMOVE:
		error = handle_blacklist_rm(jool->siit.blacklist, request);
		break;
	case OP_FLUSH:
		error = handle_blacklist_flush(jool->siit.blacklist);
		break;
	default:
		log_err("Unknown operation: %u", hdr->operation);
		error = -EINVAL;
	}

	return nlcore_respond(info, error);
}
