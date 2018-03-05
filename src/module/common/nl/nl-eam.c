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

static int __handle_eamt_foreach(struct xlator *jool, struct genl_info *info)
{
	struct ipv4_prefix offset, *offset_ptr;
	struct jnl_packet pkt;
	int error;

	log_debug("Sending EAMT to userspace.");

	/* Get request params */
	offset_ptr = jnla_get_prefix4(info, &offset) ? &offset : NULL;

	/* Create response packet */
	error = jnl_init_pkt(info, JNL_MAX_PAYLOAD, &pkt);
	if (error)
		return jnl_respond_error(info, error);

	/* Populate response packet with EAMs */
	error = eamt_foreach(jool->eamt, eam_entry_to_userspace, pkt.skb,
			offset_ptr);
	if (error < 0) {
		jnl_destroy_pkt(&pkt);
		return jnl_respond_error(info, error);
	}

	/* Fetch response packet */
	return jnl_respond_pkt(info, &pkt);
}

int handle_eamt_foreach(struct sk_buff *skb, struct genl_info *info)
{
	return jnl_wrap_instance(info, __handle_eamt_foreach);
}

static int __handle_eamt_add(struct xlator *jool, struct genl_info *info)
{
	struct ipv6_prefix prefix6;
	struct ipv4_prefix prefix4;
	bool force;

	if (verify_privileges())
		return jnl_respond_error(info, -EPERM);

	log_debug("Adding EAMT entry.");

	/* Get request params */
	if (!jnla_get_prefix6(info, &prefix6)) {
		log_err("The IPv6 prefix argument is mandatory.");
		return jnl_respond_error(info, -EINVAL);
	}
	if (!jnla_get_prefix4(info, &prefix4)) {
		log_err("The IPv4 prefix argument is mandatory.");
		return jnl_respond_error(info, -EINVAL);
	}
	if (!jnla_get_bool(info, JNLA_FORCE, &force))
		force = false;

	/* Add entry */
	return jnl_respond_error(info, eamt_add(jool->eamt, &prefix6, &prefix4,
			force));
}

int handle_eamt_add(struct sk_buff *skb, struct genl_info *info)
{
	return jnl_wrap_instance(info, __handle_eamt_add);
}

int __handle_eamt_rm(struct xlator *jool, struct genl_info *info)
{
	struct ipv6_prefix prefix6, *prefix6_ptr;
	struct ipv4_prefix prefix4, *prefix4_ptr;

	if (verify_privileges())
		return jnl_respond_error(info, -EPERM);

	log_debug("Removing EAMT entry.");

	prefix6_ptr = jnla_get_prefix6(info, &prefix6) ? &prefix6 : NULL;
	prefix4_ptr = jnla_get_prefix4(info, &prefix4) ? &prefix4 : NULL;
	return jnl_respond_error(info, eamt_rm(jool->eamt, prefix6_ptr,
			prefix4_ptr));
}

int handle_eamt_rm(struct sk_buff *skb, struct genl_info *info)
{
	return jnl_wrap_instance(info, __handle_eamt_rm);
}

static int __handle_eamt_flush(struct xlator *jool, struct genl_info *info)
{
	if (verify_privileges())
		return jnl_respond_error(info, -EPERM);

	log_debug("Flushing the EAMT.");

	eamt_flush(jool->eamt);
	return jnl_respond_error(info, 0);
}

int handle_eamt_flush(struct sk_buff *skb, struct genl_info *info)
{
	return jnl_wrap_instance(info, __handle_eamt_flush);
}
