#include "nl/nl-bib.h"

#include "nl/nl-common.h"
#include "nl/nl-core.h"
#include "nat64/pool4/db.h"
#include "nat64/bib/db.h"

static int bib_entry_to_userspace(struct bib_entry *entry, bool is_static,
		void *skb)
{
	struct nlattr *bib_attr;

	bib_attr = nla_nest_start(skb, JNLA_BIB_ENTRY);
	if (!bib_attr)
		return 1;

	/*
	 * No need to waste room with the L4 protocol;
	 * all the entries of the packet share the same protocol.
	 */
	if (jnla_put_src_taddr6(skb, &entry->ipv6)
			|| jnla_put_src_taddr4(skb, &entry->ipv4)
			|| jnla_put_bool(skb, JNLA_STATIC, is_static)) {
		nla_nest_cancel(skb, bib_attr);
		return 1;
	}

	nla_nest_end(skb, bib_attr);
	return 0;
}

static int __handle_bib_foreach(struct xlator *jool, struct genl_info *info)
{
	l4_protocol proto;
	struct ipv4_transport_addr offset, *offset_ptr;
	struct jnl_packet pkt;
	struct bib_foreach_func func;
	int error;

	if (verify_privileges())
		return jnl_respond_error(info, -EPERM);

	log_debug("Sending BIB to userspace.");

	/* Get request params */
	if (!jnla_get_l4proto(info, &proto)) {
		log_err("The l4-protocol argument is mandatory.");
		return jnl_respond_error(info, -EINVAL);
	}

	offset_ptr = jnla_get_src_taddr4(info, &offset) ? &offset : NULL;

	/* Create response packet */
	error = jnl_init_pkt(info, JNL_MAX_PAYLOAD, &pkt);
	if (error)
		return jnl_respond_error(info, error);

	/* Populate response packet with BIB entries */
	func.cb = bib_entry_to_userspace;
	func.arg = pkt.skb;
	error = bib_foreach(jool->bib, proto, &func, offset_ptr);
	if (error < 0) {
		jnl_destroy_pkt(&pkt);
		return jnl_respond_error(info, error);
	}

	/* Fetch response packet */
	return jnl_respond_pkt(info, &pkt);
}

int handle_bib_foreach(struct sk_buff *skb, struct genl_info *info)
{
	return jnl_wrap_instance(info, __handle_bib_foreach);
}

static int __handle_bib_add(struct xlator *jool, struct genl_info *info)
{
	struct bib_entry new;
	struct bib_entry old;
	int error;

	if (verify_privileges())
		return jnl_respond_error(info, -EPERM);

	log_debug("Adding BIB entry.");

	/* Get request params */
	if (!jnla_get_l4proto(info, &new.l4_proto)) {
		log_err("The l4-protocol argument is mandatory.");
		return jnl_respond_error(info, -EINVAL);
	}
	if (!jnla_get_src_taddr4(info, &new.ipv4)) {
		log_err("The IPv4 transport address argument is mandatory.");
		return jnl_respond_error(info, -EINVAL);
	}
	if (!jnla_get_src_taddr6(info, &new.ipv6)) {
		log_err("The IPv6 transport address argument is mandatory.");
		return jnl_respond_error(info, -EINVAL);
	}

	/* Add entry */
	/*
	if (!pool4db_contains(jool->pool4, new.l4_proto, &new.ipv4)) {
		log_err("The transport address '%pI4#%u' does not belong to pool4.",
				&new.ipv4.l3, new.ipv4.l4);
		log_err("Please add it there first.");
		return jnl_respond_error(info, -EINVAL);
	}
	*/

	error = bib_add_static(jool->bib, &new, &old);
	switch (error) {
	case 0:
		break;
	case -EEXIST:
		log_err("Entry %pI4#%u|%pI6c#%u collides with %pI4#%u|%pI6c#%u.",
				&new.ipv4.l3, new.ipv4.l4,
				&new.ipv6.l3, new.ipv6.l4,
				&old.ipv4.l3, old.ipv4.l4,
				&old.ipv6.l3, old.ipv6.l4);
		break;
	default:
		log_err("Unknown error code: %d", error);
		break;
	}

	return jnl_respond_error(info, error);
}

int handle_bib_add(struct sk_buff *skb, struct genl_info *info)
{
	return jnl_wrap_instance(info, __handle_bib_add);
}

static int __handle_bib_rm(struct xlator *jool, struct genl_info *info)
{
	struct bib_entry bib;
	bool taddr6_found;
	bool taddr4_found;
	int error;

	if (verify_privileges())
		return jnl_respond_error(info, -EPERM);

	log_debug("Removing BIB entry.");

	/* Get request params */
	if (!jnla_get_l4proto(info, &bib.l4_proto)) {
		log_err("The l4-protocol argument is mandatory.");
		return jnl_respond_error(info, -EINVAL);
	}

	taddr6_found = jnla_get_src_taddr6(info, &bib.ipv6);
	taddr4_found = jnla_get_src_taddr4(info, &bib.ipv4);

	if (taddr6_found && taddr4_found) {
		error = 0;
	} else if (taddr6_found) {
		error = bib_find6(jool->bib, bib.l4_proto, &bib.ipv6, &bib);
	} else if (taddr4_found) {
		error = bib_find4(jool->bib, bib.l4_proto, &bib.ipv4, &bib);
	} else {
		log_err("You need to provide an address so I can find the entry you want to remove.");
		return jnl_respond_error(info, -EINVAL);
	}

	if (error == -ESRCH)
		goto esrch;
	if (error)
		return jnl_respond_error(info, error);

	/* Remove entry */
	error = bib_rm(jool->bib, &bib);
	if (error == -ESRCH) {
		if (taddr6_found && taddr4_found)
			goto esrch;
		/* It died on its own between the find and the rm. */
		return jnl_respond_error(info, 0);
	}

	return jnl_respond_error(info, error);

esrch:
	log_err("The entry wasn't in the database.");
	return jnl_respond_error(info, -ESRCH);
}

int handle_bib_rm(struct sk_buff *skb, struct genl_info *info)
{
	return jnl_wrap_instance(info, __handle_bib_rm);
}
