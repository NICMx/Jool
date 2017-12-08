#include "nat64/mod/common/nl/pool.h"

#include "nat64/common/types.h"
#include "nat64/mod/common/nl/nl_common.h"
#include "nat64/mod/common/nl/nl_core2.h"
#include "nat64/mod/stateless/pool.h"

static int pool_to_usr(struct ipv4_prefix *prefix, void *arg)
{
	return nlbuffer_write(arg, prefix, sizeof(*prefix));
}

static int handle_addr4pool_display(struct addr4_pool *pool,
		struct genl_info *info, union request_pool *request)
{
	struct nlcore_buffer buffer;
	struct ipv4_prefix *offset;
	int error;

	log_debug("Sending IPv4 address pool to userspace.");

	error = nlbuffer_init_response(&buffer, info, nlbuffer_response_max_size());
	if (error)
		return nlcore_respond(info, error);

	offset = request->display.offset_set ? &request->display.offset : NULL;
	error = pool_foreach(pool, pool_to_usr, &buffer, offset);
	nlbuffer_set_pending_data(&buffer, error > 0);
	error = (error >= 0)
			? nlbuffer_send(info, &buffer)
			: nlcore_respond(info, error);

	nlbuffer_free(&buffer);
	return error;
}

static int handle_addr4pool_count(struct addr4_pool *pool,
		struct genl_info *info)
{
	__u64 count;
	int error;

	log_debug("Returning address count.");
	error = pool_count(pool, &count);
	if (error)
		return nlcore_respond(info, error);

	return nlcore_respond_struct(info, &count, sizeof(count));
}

static int handle_addr4pool_add(struct addr4_pool *pool,
		union request_pool *request)
{
	if (verify_superpriv())
		return -EPERM;

	log_debug("Adding an address to an IPv4 address pool.");
	return pool_add(pool, &request->add.addrs, request->add.force);
}

static int handle_addr4pool_rm(struct addr4_pool *pool,
		union request_pool *request)
{
	if (verify_superpriv())
		return -EPERM;

	log_debug("Removing an address from an IPv4 address pool.");
	return pool_rm(pool, &request->rm.addrs);
}

static int handle_addr4pool_flush(struct addr4_pool *pool)
{
	if (verify_superpriv())
		return -EPERM;

	log_debug("Flushing an IPv4 address pool...");
	return pool_flush(pool);
}

static int handle_addr4pool(struct addr4_pool *pool, struct genl_info *info)
{
	struct request_hdr *hdr = get_jool_hdr(info);
	union request_pool *request = (union request_pool *)(hdr + 1);
	int error;

	if (xlat_is_nat64()) {
		log_err("Stateful NAT64 doesn't have IPv4 address pools.");
		return nlcore_respond(info, -EINVAL);
	}

	error = validate_request_size(info, sizeof(*request));
	if (error)
		return nlcore_respond(info, error);

	switch (be16_to_cpu(hdr->operation)) {
	case OP_DISPLAY:
		return handle_addr4pool_display(pool, info, request);
	case OP_COUNT:
		return handle_addr4pool_count(pool, info);
	case OP_ADD:
		error = handle_addr4pool_add(pool, request);
		break;
	case OP_REMOVE:
		error = handle_addr4pool_rm(pool, request);
		break;
	case OP_FLUSH:
		error = handle_addr4pool_flush(pool);
		break;
	default:
		log_err("Unknown operation: %u", be16_to_cpu(hdr->operation));
		error = -EINVAL;
	}

	return nlcore_respond(info, error);
}

int handle_blacklist_config(struct xlator *jool, struct genl_info *info)
{
	return handle_addr4pool(jool->siit.blacklist, info);
}

int handle_pool6791_config(struct xlator *jool, struct genl_info *info)
{
	return handle_addr4pool(jool->siit.pool6791, info);
}
