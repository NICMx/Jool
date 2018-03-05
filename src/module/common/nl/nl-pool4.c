#include "nl/nl-pool4.h"

#include "nl/nl-common.h"
#include "nl/nl-core.h"
#include "nat64/pool4/db.h"
#include "nat64/bib/db.h"

static int pool4_entry_to_userspace(struct pool4_sample *sample, void *skb)
{
	struct nlattr *pool4_attr;

	pool4_attr = nla_nest_start(skb, JNLA_POOL4_ENTRY);
	if (!pool4_attr)
		return 1;

	/*
	 * No need to waste room with the L4 protocol;
	 * all the entries of the packet share the same protocol.
	 */
	if (nla_put_u32(skb, JNLA_MARK, sample->mark)
			|| nla_put_u32(skb, JNLA_ITERATIONS, sample->iterations)
			|| nla_put_u8(skb, JNLA_ITERATION_FLAGS, sample->iteration_flags)
			|| jnla_put_l4proto(skb, sample->proto)
			|| jnla_put_addr4(skb, JNLA_SADDR4, &sample->range.addr)
			|| jnla_put_port(skb, JNLA_SPORT4, sample->range.ports.min)
			|| jnla_put_port(skb, JNLA_SPORT4, sample->range.ports.max)) {
		nla_nest_cancel(skb, pool4_attr);
		return 1;
	}

	nla_nest_end(skb, pool4_attr);
	return 0;
}

static int __handle_pool4_foreach(struct xlator *jool, struct genl_info *info)
{
	l4_protocol proto;
	struct jnl_packet pkt;
	int error;

	log_debug("Sending pool4 to userspace.");

	/* Get request params */
	if (!jnla_get_l4proto(info, &proto)) {
		log_err("The l4-protocol argument is mandatory.");
		return jnl_respond_error(info, -EINVAL);
	}

	/* Create response packet */
	error = jnl_init_pkt(info, JNL_MAX_PAYLOAD, &pkt);
	if (error)
		return jnl_respond_error(info, error);

	/* Populate response packet with EAMs */
	error = pool4db_foreach_sample(jool->pool4, proto,
			pool4_entry_to_userspace, pkt.skb, NULL);
	if (error < 0) {
		jnl_destroy_pkt(&pkt);
		return jnl_respond_error(info, error);
	}

	/* Fetch response packet */
	return jnl_respond_pkt(info, &pkt);
}

int handle_pool4_foreach(struct sk_buff *skb, struct genl_info *info)
{
	return jnl_wrap_instance(info, __handle_pool4_foreach);
}

static bool get_pool4_entry(struct genl_info *info,
		struct pool4_entry_usr *entry)
{
	if (!jnla_get_u32(info, JNLA_MARK, &entry->mark))
		entry->mark = 0;
	if (!jnla_get_u32(info, JNLA_ITERATIONS, &entry->iterations))
		entry->iterations = 0;
	if (!jnla_get_u8(info, JNLA_ITERATION_FLAGS, &entry->flags))
		entry->flags = 0;
	if (!jnla_get_l4proto(info, &entry->proto))
		entry->proto = L4PROTO_TCP;

	if (!jnla_get_prefix4(info, &entry->range.prefix)) {
		log_err("The IPv4 prefix argument is mandatory.");
		return false;
	}

	if (!jnla_get_port(info, JNLA_MINPORT, &entry->range.ports.min))
		entry->range.ports.min = DEFAULT_POOL4_MIN_PORT;
	if (!jnla_get_port(info, JNLA_MAXPORT, &entry->range.ports.max))
		entry->range.ports.max = DEFAULT_POOL4_MAX_PORT;

	return true;
}

int __handle_pool4_add(struct xlator *jool, struct genl_info *info)
{
	struct pool4_entry_usr entry;

	if (verify_privileges())
		return jnl_respond_error(info, -EPERM);

	log_debug("Adding elements to pool4.");

	if (!get_pool4_entry(info, &entry))
		return jnl_respond_error(info, -EINVAL);

	return jnl_respond_error(info, pool4db_add(jool->pool4, &entry));
}

int handle_pool4_add(struct sk_buff *skb, struct genl_info *info)
{
	return jnl_wrap_instance(info, __handle_pool4_add);
}

int __handle_pool4_rm(struct xlator *jool, struct genl_info *info)
{
	struct pool4_entry_usr entry;
	bool quick;
	int error;

	if (verify_privileges())
		return jnl_respond_error(info, -EPERM);

	log_debug("Removing elements from pool4.");

	if (!get_pool4_entry(info, &entry))
		return jnl_respond_error(info, -EINVAL);
	if (!jnla_get_bool(info, JNLA_QUICK, &quick))
		quick = false;

	error = pool4db_rm_usr(jool->pool4, &entry);
	if (error)
		return jnl_respond_error(info, error);

	if (!quick)
		bib_rm_range(jool->bib, entry.proto, &entry.range);

	return jnl_respond_error(info, 0);
}

int handle_pool4_rm(struct sk_buff *skb, struct genl_info *info)
{
	return jnl_wrap_instance(info, __handle_pool4_rm);
}

static int __handle_pool4_flush(struct xlator *jool, struct genl_info *info)
{
	bool quick;

	if (verify_privileges())
		return jnl_respond_error(info, -EPERM);

	log_debug("Flushing pool4.");

	if (!jnla_get_bool(info, JNLA_QUICK, &quick))
		quick = false;

	pool4db_flush(jool->pool4);
	if (!quick) {
		/*
		 * This will also clear *previously* orphaned entries, but given
		 * that "not quick" generally means "please clean up", this is
		 * more likely what people wants.
		 */
		bib_flush(jool->bib);
	}

	return jnl_respond_error(info, 0);
}

int handle_pool4_flush(struct sk_buff *skb, struct genl_info *info)
{
	return jnl_wrap_instance(info, __handle_pool4_flush);
}
