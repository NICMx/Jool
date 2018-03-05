#include "nl/nl-session.h"

#include "nl/nl-common.h"
#include "nl/nl-core.h"
#include "nat64/bib/db.h"

static int session_entry_to_userspace(struct session_entry *entry, void *skb)
{
	struct nlattr *session_attr;
	unsigned long dying_time;

	session_attr = nla_nest_start(skb, JNLA_SESSION_ENTRY);
	if (!session_attr)
		return 1;

	dying_time = entry->update_time + entry->timeout;
	dying_time = (dying_time > jiffies)
			? jiffies_to_msecs(dying_time - jiffies)
			: 0;

	/*
	 * No need to waste room with the L4 protocol;
	 * all the entries of the packet share the same protocol.
	 */
	if (jnla_put_src_taddr6(skb, &entry->src6)
			|| jnla_put_dst_taddr6(skb, &entry->dst6)
			|| jnla_put_src_taddr4(skb, &entry->src4)
			|| jnla_put_dst_taddr4(skb, &entry->dst4)
			|| jnla_put_l4proto(skb, entry->proto)
			|| nla_put_u64(skb, JNLA_DYING_TIME, dying_time)
			|| nla_put_u8(skb, JNLA_TCP_STATE, entry->state)) {
		nla_nest_cancel(skb, session_attr);
		return 1;
	}

	nla_nest_end(skb, session_attr);
	return 0;
}

int __handle_session_foreach(struct xlator *jool, struct genl_info *info)
{
	l4_protocol proto;
	struct session_foreach_offset offset;
	bool found_src, found_dst;
	struct jnl_packet pkt;
	struct session_foreach_func func;
	int error;

	if (verify_privileges())
		return jnl_respond_error(info, -EPERM);

	log_debug("Sending session table to userspace.");

	/* Get request params */
	if (!jnla_get_l4proto(info, &proto)) {
		log_err("The l4-protocol argument is mandatory.");
		return jnl_respond_error(info, -EINVAL);
	}

	found_src = jnla_get_src_taddr4(info, &offset.offset.src);
	found_dst = jnla_get_dst_taddr4(info, &offset.offset.dst);
	offset.include_offset = false;
	if (found_src ^ found_dst) {
		log_err("Expected either zero or two v4 transport addresses, one given.");
		return jnl_respond_error(info, -EINVAL);
	}

	/* Create and populate response packet */
	error = jnl_init_pkt(info, JNL_MAX_PAYLOAD, &pkt);
	if (error)
		return jnl_respond_error(info, error);

	func.cb = session_entry_to_userspace;
	func.arg = pkt.skb;
	error = bib_foreach_session(jool->bib, &jool->global->cfg, proto, &func,
			found_src ? &offset : NULL);
	if (error < 0) {
		jnl_destroy_pkt(&pkt);
		return jnl_respond_error(info, error);
	}

	/* Fetch response packet */
	return jnl_respond_pkt(info, &pkt);
}

int handle_session_foreach(struct sk_buff *skb, struct genl_info *info)
{
	return jnl_wrap_instance(info, __handle_session_foreach);
}
