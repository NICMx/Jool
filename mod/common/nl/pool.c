#include "nat64/mod/common/nl/pool.h"

#include "nat64/mod/common/types.h"
#include "nat64/mod/common/nl/nl_common.h"
#include "nat64/mod/common/nl/nl_core2.h"
#include "nat64/mod/stateless/pool.h"

static int pool_to_usr(struct ipv4_prefix *prefix, void *arg)
{
	return nl_core_write_to_buffer(arg, prefix, sizeof(*prefix));
}

static int handle_addr4pool_display(struct addr4_pool *pool,
		struct genl_info *info, enum config_mode command,
		union request_pool *request)
{
	struct nl_core_buffer *buffer;
	struct ipv4_prefix *offset;
	int error;

	log_debug("Sending IPv4 address pool to userspace.");

	error = nl_core_new_core_buffer(&buffer, nl_core_data_max_size());
	if (error)
		return nl_core_respond_error(info, command, error);

	offset = request->display.offset_set ? &request->display.offset : NULL;
	error = pool_foreach(pool, pool_to_usr, buffer, offset);
	buffer->pending_data = error > 0;
	error = (error >= 0)
			? nl_core_send_buffer(info, command, buffer)
			: nl_core_respond_error(info, command, error);

	nl_core_free_buffer(buffer);
	return error;
}

static int handle_addr4pool_count(struct addr4_pool *pool,
		struct genl_info *info, enum config_mode command)
{
	__u64 count;
	int error;

	log_debug("Returning address count.");
	error = pool_count(pool, &count);
	if (error)
		return nl_core_respond_error(info, command, error);

	return nlcore_respond_struct(info, command, &count, sizeof(count));
}

static int handle_addr4pool_add(struct addr4_pool *pool,
		union request_pool *request)
{
	if (verify_superpriv())
		return -EPERM;

	log_debug("Adding an address to an IPv4 address pool.");
	return pool_add(pool, &request->add.addrs);
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

int handle_addr4pool_config(struct addr4_pool *pool, enum config_mode command,
		struct genl_info *info)
{
	struct request_hdr *jool_hdr = get_jool_hdr(info);
	union request_pool *request = (union request_pool *)(jool_hdr + 1);
	int error;

	if (xlat_is_nat64()) {
		log_err("Stateful NAT64 doesn't have pure IPv4 address pools.");
		return nl_core_respond_error(info, command, -EINVAL);
	}

	switch (jool_hdr->operation) {
	case OP_DISPLAY:
		return handle_addr4pool_display(pool, info, command, request);
	case OP_COUNT:
		return handle_addr4pool_count(pool, info, command);
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
		log_err("Unknown operation: %d", jool_hdr->operation);
		error = -EINVAL;
	}

	return nlcore_respond(info, command, error);
}
