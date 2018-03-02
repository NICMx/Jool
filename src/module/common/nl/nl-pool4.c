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
	if (nla_put_be32(skb, JNLA_MARK, cpu_to_be32(sample->mark))
			|| nla_put_be32(skb, JNLA_ITERATIONS, cpu_to_be32(sample->iterations))
			|| nla_put_u8(skb, JNLA_ITERATION_FLAGS, sample->iterations_flags)
			|| jnla_put_addr4(skb, &sample->range.addr)
			|| jnla_put_port(skb, sample->range.ports.min)
			|| jnla_put_port(skb, sample->range.ports.max)) {
		nla_nest_cancel(skb, pool4_attr);
		return 1;
	}

	nla_nest_end(skb, pool4_attr);
	return 0;
}

int handle_pool4_foreach(struct pool4 *pool, struct genl_info *info,
		struct request_pool4_foreach *request)
{
	struct jnl_packet pkt;
	int error;

	log_debug("Sending pool4 to userspace.");

	error = jnl_init_pkt(info, JNL_MAX_PAYLOAD, &pkt);
	if (error)
		return jnl_respond_error(info, error);

	error = pool4db_foreach_sample(pool, request->proto,
			pool4_entry_to_userspace, pkt.skb,
			request->offset_set ? &request->offset : NULL);
	if (error < 0) {
		jnl_destroy_pkt(&pkt);
		return jnl_respond_error(info, error);
	}

	return jnl_respond_pkt(info, &pkt);
}

int handle_pool4_add(struct pool4 *pool, struct genl_info *info,
		struct request_pool4_add *request)
{
	if (verify_privileges())
		return jnl_respond_error(info, -EPERM);

	log_debug("Adding elements to pool4.");
	return jnl_respond_error(info, pool4db_add(pool, &request->entry));
}

/*
static int handle_pool4_update(struct pool4 *pool, struct genl_info *info,
		struct request_pool4 *request)
{
	if (verify_privileges())
		return nlcore_respond(info, -EPERM);

	log_debug("Updating pool4 table.");
	return nlcore_respond(info, pool4db_update(pool, &request->update));
}
*/

int handle_pool4_rm(struct xlator *jool, struct genl_info *info,
		struct request_pool4_rm *request)
{
	int error;

	if (verify_privileges())
		return jnl_respond_error(info, -EPERM);

	log_debug("Removing elements from pool4.");

	error = pool4db_rm_usr(jool->pool4, &request->entry);

	if (!request->quick) {
		bib_rm_range(jool->bib, request->entry.proto,
				&request->entry.range);
	}

	return jnl_respond_error(info, error);
}

int handle_pool4_flush(struct xlator *jool, struct genl_info *info,
		struct request_pool4_flush *request)
{
	if (verify_privileges())
		return jnl_respond_error(info, -EPERM);

	log_debug("Flushing pool4.");

	pool4db_flush(jool->pool4);
	if (!request->quick) {
		/*
		 * This will also clear *previously* orphaned entries, but given
		 * that "not quick" generally means "please clean up", this is
		 * more likely what people wants.
		 */
		bib_flush(jool->bib);
	}

	return jnl_respond_error(info, 0);
}
