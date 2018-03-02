#include "nl/nl-eam.h"

#include "types.h"
#include "nl/nl-common.h"
#include "nl/nl-core.h"
#include "siit/eam.h"

static int eam_entry_to_userspace(struct eamt_entry *entry, void *skb)
{
	struct nlattr *eam_attr;

	eam_attr = nla_nest_start(skb, JNLA_EAM);
	if (!eam_attr)
		return 1;

	if (jnla_put_prefix6(skb, &entry->prefix6)
			|| jnla_put_prefix4(skb, &entry->prefix4)) {
		nla_nest_cancel(skb, eam_attr);
		return 1;
	}

	nla_nest_end(skb, eam_attr);
	return 0;
}

int handle_eamt_foreach(struct eam_table *eamt, struct genl_info *info,
		struct request_eamt_foreach *request)
{
	struct jnl_packet pkt;
	int error;

	log_debug("Sending EAMT to userspace.");

	error = jnl_init_pkt(info, JNL_MAX_PAYLOAD, &pkt);
	if (error)
		return jnl_respond_error(info, error);

	error = eamt_foreach(eamt, eam_entry_to_userspace, pkt.skb,
			request->prefix4_set ? &request->prefix4 : NULL);
	if (error < 0) {
		jnl_destroy_pkt(&pkt);
		return jnl_respond_error(info, error);
	}

	return jnl_respond_pkt(info, &pkt);
}

int handle_eamt_add(struct eam_table *eamt, struct request_eamt_add *request)
{
	if (verify_privileges())
		return -EPERM;

	log_debug("Adding EAMT entry.");
	return eamt_add(eamt, &request->prefix6, &request->prefix4,
			request->force);
}

int handle_eamt_rm(struct eam_table *eamt, struct request_eamt_rm *request)
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

int handle_eamt_flush(struct eam_table *eamt)
{
	if (verify_privileges())
		return -EPERM;

	eamt_flush(eamt);
	return 0;
}
