#include "mod/common/nl/address.h"

#include "mod/common/address_xlat.h"
#include "mod/common/log.h"
#include "mod/common/xlator.h"
#include "mod/common/nl/attribute.h"
#include "mod/common/nl/nl_common.h"

static int jnla_put_entry(struct jnl_state *state,
		struct address_translation_entry *entry)
{
	int error;

	switch (entry->method) {
	case AXM_RFC6052:
		error = jnla_put_prefix6(jnls_skb(state), JNLAAQ_PREFIX6052,
				&entry->prefix6052);
		break;
	case AXM_EAMT:
		error = jnla_put_eam(jnls_skb(state), JNLAAQ_EAM, &entry->eam);
		break;
	case AXM_RFC6791:
		return 0;
	default:
		return jnls_err(state, "Unknown translation method: %u",
				entry->method);
	}

	if (error)
		report_put_failure(state);
	return error;
}

int handle_address_query64(struct sk_buff *skb, struct genl_info *info)
{
	struct jnl_state *state;
	struct in6_addr request;
	struct result_addrxlat64 result;
	struct addrxlat_result verdict;
	int error;

	error = jnl_start(&state, info, XT_SIIT, true);
	if (error)
		return jnl_reply(state, error);

	jnls_debug(state, "Handling 6->4 address translation query.");

	/* Parse request */
	error = jnla_get_addr6(info->attrs[JNLAR_ADDR_QUERY], "IPv6 address",
			&request, state);
	if (error)
		return jnl_reply(state, error);

	/* Perform query */
	verdict = addrxlat_siit64(jnls_xlator(state), &request, &result, true);
	if (verdict.verdict != ADDRXLAT_CONTINUE)
		return jnl_reply(state, jnls_err(state, "Unable to translate %pI6c: %s", &request, verdict.reason));

	/* Build response */
	error = jnla_put_addr4(jnls_skb(state), JNLAAQ_ADDR4, &result.addr);
	if (error) {
		report_put_failure(state);
		return jnl_reply(state, error);
	}

	return jnl_reply(state, jnla_put_entry(state, &result.entry));
}

int handle_address_query46(struct sk_buff *skb, struct genl_info *info)
{
	struct jnl_state *state;
	struct in_addr query;
	struct result_addrxlat46 result;
	struct addrxlat_result verdict;
	int error;

	error = jnl_start(&state, info, XT_SIIT, true);
	if (error)
		return jnl_reply(state, error);

	jnls_debug(state, "Handling 4->6 address translation query.");

	/* Parse request */
	error = jnla_get_addr4(info->attrs[JNLAR_ADDR_QUERY], "IPv4 address",
			&query, state);
	if (error)
		return jnl_reply(state, error);

	/* Perform query */
	verdict = addrxlat_siit46(jnls_xlator(state), query.s_addr, &result,
			true, true);
	if (verdict.verdict != ADDRXLAT_CONTINUE)
		return jnl_reply(state, jnls_err(state, "Unable to translate %pI4: %s", &query, verdict.reason));

	/* Build response */
	error = jnla_put_addr6(jnls_skb(state), JNLAAQ_ADDR6, &result.addr);
	if (error) {
		report_put_failure(state);
		return jnl_reply(state, error);
	}

	return jnl_reply(state, jnla_put_entry(state, &result.entry));
}
