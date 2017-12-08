#include "nat64/mod/common/nl/pool6.h"

#include "nat64/common/types.h"
#include "nat64/mod/common/nl/nl_common.h"
#include "nat64/mod/common/nl/nl_core2.h"
#include "nat64/mod/common/pool6.h"
#include "nat64/mod/stateful/bib/db.h"

static int pool6_entry_to_userspace(struct ipv6_prefix *prefix, void *arg)
{
	return nlbuffer_write(arg, prefix, sizeof(*prefix));
}

static int handle_pool6_display(struct pool6 *pool, struct genl_info *info,
		union request_pool6 *request)
{
	struct nlcore_buffer buffer;
	struct ipv6_prefix *prefix;
	int error;

	log_debug("Sending pool6 to userspace.");

	error = nlbuffer_init_response(&buffer, info, nlbuffer_response_max_size());
	if (error)
		return nlcore_respond(info, error);

	prefix = request->prefix_set ? &request->prefix : NULL;
	error = pool6_foreach(pool, pool6_entry_to_userspace, &buffer, prefix);
	nlbuffer_set_pending_data(&buffer, error > 0);
	error = (error >= 0)
			? nlbuffer_send(info, &buffer)
			: nlcore_respond(info, error);

	nlbuffer_free(&buffer);
	return error;
}

static int handle_pool6_count(struct pool6 *pool, struct genl_info *info)
{
	__u64 count;
	int error;

	log_debug("Returning pool6's prefix count.");
	error = pool6_count(pool, &count);
	if (error)
		return nlcore_respond(info, error);

	return nlcore_respond_struct(info, &count, sizeof(count));
}

static int handle_pool6_add(struct pool6 *pool, union request_pool6 *request)
{
	if (verify_superpriv())
		return -EPERM;

	log_debug("Adding a prefix to pool6.");
	return pool6_add(pool, &request->prefix);
}

static int handle_pool6_rm(struct xlator *jool, union request_pool6 *request)
{
	int error;

	if (verify_superpriv())
		return -EPERM;

	log_debug("Removing a prefix from pool6.");
	error = pool6_rm(jool->pool6, &request->prefix);

	if (xlat_is_nat64()) {
		/*
		 * Sorry; there's no "quick" pool6 rm anymore. This is because
		 * BIB and session now assume that the prefix won't change for
		 * significant performance and simplifying reasons.
		 */
		bib_flush(jool->nat64.bib);
	}

	return error;
}

static int handle_pool6_flush(struct xlator *jool, union request_pool6 *request)
{
	int error;

	if (verify_superpriv())
		return -EPERM;

	log_debug("Flushing pool6.");
	error = pool6_flush(jool->pool6);

	if (xlat_is_nat64()) {
		/*
		 * Sorry; there's no "quick" pool6 flush anymore. This is
		 * because BIB/session now assume that the prefix won't change
		 * for significant performance and simplifying reasons.
		 */
		bib_flush(jool->nat64.bib);
	}

	return error;
}

int handle_pool6_config(struct xlator *jool, struct genl_info *info)
{
	struct request_hdr *hdr = get_jool_hdr(info);
	union request_pool6 *request = (union request_pool6 *)(hdr + 1);
	int error;

	error = validate_request_size(info, sizeof(*request));
	if (error)
		return nlcore_respond(info, error);

	switch (be16_to_cpu(hdr->operation)) {
	case OP_DISPLAY:
		return handle_pool6_display(jool->pool6, info, request);
	case OP_COUNT:
		return handle_pool6_count(jool->pool6, info);
	case OP_ADD:
	case OP_UPDATE:
		error = handle_pool6_add(jool->pool6, request);
		break;
	case OP_REMOVE:
		error = handle_pool6_rm(jool, request);
		break;
	case OP_FLUSH:
		error = handle_pool6_flush(jool, request);
		break;
	default:
		log_err("Unknown operation: %u", be16_to_cpu(hdr->operation));
		error = -EINVAL;
	}

	return nlcore_respond(info, error);
}
