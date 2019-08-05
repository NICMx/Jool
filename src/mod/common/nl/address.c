#include "mod/common/nl/address.h"

#include "mod/common/address_xlat.h"
#include "mod/common/log.h"
#include "mod/common/nl/nl_common.h"
#include "mod/common/nl/nl_core.h"

static int handle_xlat64(struct xlator *jool, struct genl_info *info,
		struct request_addrxlat *request)
{
	struct result_addrxlat64 result;
	struct addrxlat_result verdict;

	log_debug("Handling 6->4 address translation query.");

	verdict = addrxlat_siit64(jool, &request->addr.v6, &result);

	if (verdict.verdict != ADDRXLAT_CONTINUE) {
		log_err("%s.", verdict.reason);
		return nlcore_respond(info, -EINVAL);
	}

	return nlcore_respond_struct(info, &result, sizeof(result));
}

static int handle_xlat46(struct xlator *jool, struct genl_info *info,
		struct request_addrxlat *request)
{
	struct result_addrxlat46 result;
	struct addrxlat_result verdict;

	log_debug("Handling 4->6 address translation query.");

	verdict = addrxlat_siit46(jool, true, request->addr.v4.s_addr, &result);

	if (verdict.verdict != ADDRXLAT_CONTINUE) {
		log_err("%s.", verdict.reason);
		return nlcore_respond(info, -EINVAL);
	}

	return nlcore_respond_struct(info, &result, sizeof(result));
}

int handle_address_query(struct xlator *jool, struct genl_info *info)
{
	struct request_hdr *hdr = get_jool_hdr(info);
	struct request_addrxlat *request = (struct request_addrxlat *)(hdr + 1);
	int error;

	if (xlat_is_nat64()) {
		log_err("Stateful NAT64 doesn't support address translation queries yet.");
		return nlcore_respond(info, -EINVAL);
	}

	error = validate_request_size(info, sizeof(*request));
	if (error)
		return nlcore_respond(info, error);

	switch (request->direction) {
	case 64:
		return handle_xlat64(jool, info, request);
	case 46:
		return handle_xlat46(jool, info, request);
	}

	log_err("Unknown translation direction: %u", request->direction);
	return nlcore_respond(info, -EINVAL);
}
