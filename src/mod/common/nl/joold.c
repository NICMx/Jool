#include "mod/common/nl/joold.h"

#include "mod/common/log.h"
#include "mod/common/nl/nl_common.h"
#include "mod/common/nl/nl_core.h"
#include "mod/common/joold.h"

int handle_joold_add(struct sk_buff *skb, struct genl_info *info)
{
	struct xlator jool;
	int error;

	log_debug("Handling joold add.");

	error = request_handle_start(info, XT_NAT64, &jool);
	if (error)
		goto end;

	error = joold_sync(&jool, info->attrs[RA_SESSION_ENTRIES]);
	if (error)
		goto revert_start;

	request_handle_end(&jool);
	/*
	 * Do not bother userspace with an ACK; it's not
	 * waiting nor has anything to do with it.
	 */
	return 0;

revert_start:
	request_handle_end(&jool);
end:
	return jresponse_send_simple(info, error);
}

int handle_joold_test(struct sk_buff *skb, struct genl_info *info)
{
	struct xlator jool;
	int error;

	log_debug("Handling joold test.");

	error = request_handle_start(info, XT_NAT64, &jool);
	if (error)
		goto end;

	error = joold_test(&jool);
	request_handle_end(&jool);
end:	return jresponse_send_simple(info, error);
}

int handle_joold_advertise(struct sk_buff *skb, struct genl_info *info)
{
	struct xlator jool;
	int error;

	log_debug("Handling joold advertise.");

	error = request_handle_start(info, XT_NAT64, &jool);
	if (error)
		goto end;

	error = joold_advertise(&jool);
	request_handle_end(&jool);
end:
	return jresponse_send_simple(info, error);
}

int handle_joold_ack(struct sk_buff *skb, struct genl_info *info)
{
	struct xlator jool;
	int error;

	log_debug("Handling joold ack.");

	error = request_handle_start(info, XT_NAT64, &jool);
	if (error)
		return jresponse_send_simple(info, error);

	joold_ack(&jool);

	request_handle_end(&jool);
	return 0; /* Do not ack the ack. */
}
