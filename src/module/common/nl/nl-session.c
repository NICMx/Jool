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
	if (nla_put_taddr6(skb, &entry->src6)
			|| nla_put_taddr6(skb, &entry->dst6)
			|| nla_put_taddr4(skb, &entry->src4)
			|| nla_put_taddr4(skb, &entry->dst4)
			|| nla_put_u8(skb, JNLA_TCP_STATE, entry->state)
			|| nla_put_be64(skb, JNLA_DYING_TIME, cpu_to_be64(dying_time))) {
		nla_nest_cancel(skb, session_attr);
		return 1;
	}

	nla_nest_end(skb, session_attr);
	return 0;
}

int handle_session_foreach(struct bib *db,
		struct globals *globals,
		struct genl_info *info,
		struct request_session_foreach *request)
{
	struct jnl_packet pkt;
	struct session_foreach_func func;
	struct session_foreach_offset offset_struct;
	struct session_foreach_offset *offset = NULL;
	int error;

	if (verify_privileges())
		return jnl_respond_error(info, -EPERM);

	log_debug("Sending session table to userspace.");

	error = jnl_init_pkt(info, JNL_MAX_PAYLOAD, &pkt);
	if (error)
		return jnl_respond_error(info, error);

	func.cb = session_entry_to_userspace;
	func.arg = pkt.skb;

	if (request->offset_set) {
		offset_struct.offset = request->offset;
		offset_struct.include_offset = false;
		offset = &offset_struct;
	}

	error = bib_foreach_session(db, globals, request->l4_proto, &func,
			offset);
	if (error < 0) {
		jnl_destroy_pkt(&pkt);
		return jnl_respond_error(info, error);
	}

	return jnl_respond_pkt(info, &pkt);
}
