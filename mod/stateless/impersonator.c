#include "nat64/common/types.h"
#include "nat64/common/config.h"
#include "nat64/mod/common/packet.h"
#include "nat64/mod/stateful/compute_outgoing_tuple.h"
#include "nat64/mod/stateful/determine_incoming_tuple.h"
#include "nat64/mod/stateful/filtering_and_updating.h"
#include "nat64/mod/stateful/fragment_db.h"
#include "nat64/mod/stateful/pool4/db.h"
#include "nat64/mod/stateful/bib/db.h"
#include "nat64/mod/stateful/bib/static_routes.h"
#include "nat64/mod/stateful/session/db.h"

/**
 * @file
 * NAT64-specific functions, as linked by SIIT code.
 *
 * These are all supposed to be unreachable code, so they're very noisy on the
 * kernel log.
 */

static int fail(const char *function_name)
{
	WARN(true, "%s() was called from SIIT code.", function_name);
	return -EINVAL;
}

verdict determine_in_tuple(struct packet *pkt, struct tuple *in_tuple)
{
	fail(__func__);
	return VERDICT_DROP;
}

verdict filtering_and_updating(struct packet *pkt, struct tuple *in_tuple)
{
	fail(__func__);
	return VERDICT_DROP;
}

verdict compute_out_tuple(struct tuple *in, struct tuple *out, struct packet *pkt_in)
{
	fail(__func__);
	return VERDICT_DROP;
}

int pool4db_add(const __u32 mark, enum l4_protocol proto,
		struct ipv4_prefix *prefix, struct port_range *ports)
{
	return fail(__func__);
}

int pool4db_rm(const __u32 mark, enum l4_protocol proto,
		struct ipv4_prefix *prefix, struct port_range *ports)
{
	return fail(__func__);
}

int pool4db_flush(void)
{
	return fail(__func__);
}

int pool4db_foreach_sample(int (*cb)(struct pool4_sample *, void *), void *arg,
		struct pool4_sample *offset)
{
	return fail(__func__);
}

void pool4db_count(__u32 *tables, __u64 *samples, __u64 *taddrs)
{
	fail(__func__);
}

bool pool4db_is_empty(void)
{
	fail(__func__);
	return true;
}

void bibdb_delete_taddr4s(const struct ipv4_prefix *prefix,
		struct port_range *ports)
{
	fail(__func__);
}

void bibdb_flush(void)
{
	fail(__func__);
}

int bibdb_foreach(const l4_protocol proto,
		int (*func)(struct bib_entry *, void *), void *arg,
		const struct ipv4_transport_addr *offset)
{
	return fail(__func__);
}

int bibdb_count(const l4_protocol proto, __u64 *result)
{
	return fail(__func__);
}

int add_static_route(struct request_bib *request)
{
	return fail(__func__);
}

int delete_static_route(struct request_bib *request)
{
	return fail(__func__);
}

void sessiondb_delete_taddr6s(struct ipv6_prefix *prefix)
{
	fail(__func__);
}

void sessiondb_delete_taddr4s(struct ipv4_prefix *prefix,
		struct port_range *ports)
{
	fail(__func__);
}

void sessiondb_flush(void)
{
	fail(__func__);
}

int sessiondb_foreach(l4_protocol proto,
		int (*func)(struct session_entry *, void *), void *arg,
		struct ipv4_transport_addr *offset_remote,
		struct ipv4_transport_addr *offset_local)
{
	return fail(__func__);
}

int sessiondb_count(l4_protocol proto, __u64 *result)
{
	return fail(__func__);
}

void sessiondb_update_timers(void)
{
	fail(__func__);
}

verdict fragdb_handle(struct packet *pkt)
{
	fail(__func__);
	return VERDICT_DROP;
}

int joold_sync_entires(__u8 *data, __u32 size)
{
	fail(__func__);
	return -EINVAL;
}

//Dummy function
int joold_init(void)
{
    fail(__func__);
    return -EINVAL;
}
//Dummy function
void joold_update_config(void)
{
    fail(__func__);

}
//Dummy function
void joold_start(void)
{
    fail(__func__);
}
//Dummy function
void joold_stop(void)
{
    fail(__func__);

}
//Dummy function
void joold_destroy(void)
{
    fail(__func__);

}
//Dummy function
int joold_add_session_element(struct session_entry *entry)
{
    fail(__func__);
    return -EINVAL;
}



