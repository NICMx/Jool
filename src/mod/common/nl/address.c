#include "mod/common/nl/address.h"

#include "mod/common/address_xlat.h"
#include "mod/common/log.h"
#include "mod/common/xlator.h"
#include "mod/common/nl/attribute.h"
#include "mod/common/nl/nl_common.h"
#include "mod/common/nl/nl_core.h"

static int jnla_put_entry(struct jool_response *response,
		struct address_translation_entry *entry)
{
	switch (entry->method) {
	case AXM_RFC6052:
		return jnla_put_prefix6(response->skb, AQA_PREFIX6052, &entry->prefix6052);
	case AXM_EAMT:
		return jnla_put_eam(response->skb, AQA_EAM, &entry->eam);
	case AXM_RFC6791:
		return 0;
	}

	log_err("Unknown translation method: %u", entry->method);
	return -EINVAL;
}

int handle_address_query64(struct sk_buff *skb, struct genl_info *info)
{
	struct xlator jool;
	struct in6_addr request;
	struct result_addrxlat64 result;
	struct addrxlat_result verdict;
	struct jool_response response;
	int error;

	log_debug("Handling 6->4 address translation query.");

	error = request_handle_start(info, XT_SIIT, &jool);
	if (error)
		goto end;

	/* Parse request */
	error = jnla_get_addr6(info->attrs[RA_ADDR_QUERY], "IPv6 address", &request);
	if (error)
		goto revert_start;

	/* Perform query */
	verdict = addrxlat_siit64(&jool, &request, &result);
	if (verdict.verdict != ADDRXLAT_CONTINUE) {
		log_err("%s.", verdict.reason);
		error = -EINVAL;
		goto revert_start;
	}

	/* Build response */
	error = jresponse_init(&response, info);
	if (error)
		goto revert_start;
	error = jnla_put_addr4(response.skb, AQA_ADDR4, &result.addr);
	if (error)
		goto drop_response;
	error = jnla_put_entry(&response, &result.entry);
	if (error)
		goto drop_response;

	/* Send response */
	request_handle_end(&jool);
	return jresponse_send(&response);

drop_response:
	jresponse_cleanup(&response);
revert_start:
	request_handle_end(&jool);
end:
	return nlcore_respond(info, error);
}

int handle_address_query46(struct sk_buff *skb, struct genl_info *info)
{
	struct xlator jool;
	struct in_addr request;
	struct result_addrxlat46 result;
	struct addrxlat_result verdict;
	struct jool_response response;
	int error;

	log_debug("Handling 4->6 address translation query.");

	error = request_handle_start(info, XT_SIIT, &jool);
	if (error)
		goto end;

	/* Parse request */
	error = jnla_get_addr4(info->attrs[RA_ADDR_QUERY], "IPv4 address", &request);
	if (error)
		goto revert_start;

	/* Perform query */
	verdict = addrxlat_siit46(&jool, request.s_addr, &result, true, true);
	if (verdict.verdict != ADDRXLAT_CONTINUE) {
		log_err("%s.", verdict.reason);
		error = -EINVAL;
		goto revert_start;
	}

	/* Build response */
	error = jresponse_init(&response, info);
	if (error)
		goto revert_start;
	error = jnla_put_addr6(response.skb, AQA_ADDR6, &result.addr);
	if (error)
		goto drop_response;
	error = jnla_put_entry(&response, &result.entry);
	if (error)
		goto drop_response;

	/* Send response */
	request_handle_end(&jool);
	return jresponse_send(&response);

drop_response:
	jresponse_cleanup(&response);
revert_start:
	request_handle_end(&jool);
end:
	return nlcore_respond(info, error);
}
