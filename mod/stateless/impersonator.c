#include "nat64/common/types.h"
#include "nat64/common/config.h"
#include "nat64/mod/common/packet.h"
#include "nat64/mod/stateful/compute_outgoing_tuple.h"
#include "nat64/mod/stateful/determine_incoming_tuple.h"
#include "nat64/mod/stateful/filtering_and_updating.h"
#include "nat64/mod/stateful/fragment_db.h"
#include "nat64/mod/stateful/joold.h"
#include "nat64/mod/stateful/pool4/db.h"
#include "nat64/mod/stateful/bib/bib.h"
#include "nat64/mod/stateful/session/db.h"

/**
 * @file
 * NAT64-specific functions, as linked by SIIT code.
 *
 * Most of these are supposed to be unreachable code, so they're very noisy on
 * the kernel log.
 */

static int fail(const char *function_name)
{
	WARN(true, "%s() was called from SIIT code.", function_name);
	return -EINVAL;
}

verdict determine_in_tuple(struct xlation *state)
{
	fail(__func__);
	return VERDICT_DROP;
}

verdict filtering_and_updating(struct xlation *state)
{
	fail(__func__);
	return VERDICT_DROP;
}

verdict compute_out_tuple(struct xlation *state)
{
	fail(__func__);
	return VERDICT_DROP;
}

int pool4db_init(struct pool4 **pool)
{
	return fail(__func__);
}

void pool4db_get(struct pool4 *pool)
{
	fail(__func__);
}

void pool4db_put(struct pool4 *pool)
{
	fail(__func__);
}

int pool4db_add_usr(struct pool4 *pool, struct pool4_entry_usr *entry)
{
	return fail(__func__);
}

int pool4db_rm_usr(struct pool4 *pool, struct pool4_entry_usr *entry)
{
	return fail(__func__);
}

void pool4db_flush(struct pool4 *pool)
{
	fail(__func__);
}

int pool4db_foreach_sample(struct pool4 *pool, l4_protocol proto,
		int (*cb)(struct pool4_sample *, void *), void *arg,
		struct pool4_sample *offset)
{
	return fail(__func__);
}

bool pool4db_contains(struct pool4 *pool, struct net *ns,
		enum l4_protocol proto, struct ipv4_transport_addr *addr)
{
	fail(__func__);
	return false;
}

int bibdb_init(struct bib **db)
{
	return fail(__func__);
}

void bibdb_get(struct bib *db)
{
	fail(__func__);
}

void bibdb_put(struct bib *db)
{
	fail(__func__);
}

void bibdb_config_copy(struct bib *db, struct bib_config *config)
{
	/* No code. */
}

void bibdb_config_set(struct bib *db, struct bib_config *config)
{
	/* No code. */
}

int bibdb_find6(struct bib *db, const struct ipv6_transport_addr *addr,
		const l4_protocol proto, struct bib_entry **result)
{
	return fail(__func__);
}

int bibdb_find4(struct bib *db, const struct ipv4_transport_addr *addr,
		const l4_protocol proto, struct bib_entry **result)
{
	return fail(__func__);
}

int bibdb_add(struct bib *db, struct bib_entry *entry, struct bib_entry **old)
{
	return fail(__func__);
}

void bibdb_rm_range(struct bib *db, const struct ipv4_prefix *prefix,
		struct port_range *ports)
{
	fail(__func__);
}

void bibdb_flush(struct bib *db)
{
	fail(__func__);
}

int bibdb_foreach(struct bib *db, const l4_protocol proto,
		int (*func)(struct bib_entry *, void *), void *arg,
		const struct ipv4_transport_addr *offset)
{
	return fail(__func__);
}

int bibdb_count(struct bib *db, const l4_protocol proto, __u64 *result)
{
	return fail(__func__);
}

struct bib_entry *bibentry_create_usr(struct bib_entry_usr *usr)
{
	fail(__func__);
	return NULL;
}

struct bib_entry *bibentry_create(const struct ipv4_transport_addr *addr4,
		const struct ipv6_transport_addr *addr6,
		const bool is_static, const l4_protocol proto)
{
	fail(__func__);
	return NULL;
}

void bibentry_get_db(struct bib_entry *bib)
{
	fail(__func__);
}

int bibentry_put_db(struct bib_entry *bib)
{
	return fail(__func__);
}

void bibentry_put_thread(struct bib_entry *bib, bool must_die)
{
	fail(__func__);
}

void session_put(struct session_entry *session, bool must_die)
{
	fail(__func__);
}

int sessiondb_init(struct sessiondb **db)
{
	return fail(__func__);
}

void sessiondb_get(struct sessiondb *db)
{
	fail(__func__);
}

void sessiondb_put(struct sessiondb *db)
{
	fail(__func__);
}

void sessiondb_config_copy(struct sessiondb *db, struct session_config *config)
{
	/* No code. */
}

void sessiondb_config_set(struct sessiondb *db, struct session_config *config)
{
	/* No code. */
}

void sessiondb_rm_prefix6(struct sessiondb *db, struct ipv6_prefix *prefix)
{
	fail(__func__);
}

void sessiondb_rm_range(struct sessiondb *db, struct ipv4_prefix *prefix,
		struct port_range *ports)
{
	fail(__func__);
}

int sessiondb_rm_bib(struct sessiondb *db, struct bib_entry *bib)
{
	return fail(__func__);
}

void sessiondb_flush(struct sessiondb *db)
{
	fail(__func__);
}

int sessiondb_foreach(struct sessiondb *db, l4_protocol proto,
		int (*func)(struct session_entry *, void *), void *arg,
		struct ipv4_transport_addr *offset_remote,
		struct ipv4_transport_addr *offset_local,
		bool include_offset)
{
	return fail(__func__);
}

int sessiondb_count(struct sessiondb *db, l4_protocol proto, __u64 *result)
{
	return fail(__func__);
}

struct joold_queue *joold_create(struct net *ns)
{
	fail(__func__);
	return NULL;
}

void joold_get(struct joold_queue *queue)
{
	fail(__func__);
}

void joold_put(struct joold_queue *queue)
{
	fail(__func__);
}

void joold_config_copy(struct joold_queue *queue, struct joold_config *config)
{
	/* No code. */
}

void joold_config_set(struct joold_queue *queue, struct joold_config *config)
{
	/* No code. */
}

struct fragdb *fragdb_create(void)
{
	fail(__func__);
	return NULL;
}

void fragdb_get(struct fragdb *db)
{
	fail(__func__);
}

void fragdb_put(struct fragdb *db)
{
	fail(__func__);
}

void fragdb_config_copy(struct fragdb *db, struct fragdb_config *config)
{
	/* No code. */
}

void fragdb_config_set(struct fragdb *db, struct fragdb_config *config)
{
	/* No code. */
}

verdict fragdb_handle(struct fragdb *db, struct packet *pkt)
{
	fail(__func__);
	return VERDICT_DROP;
}

int joold_sync(struct xlator *jool, void *data, __u32 size)
{
	return fail(__func__);
}

int joold_test(struct xlator *jool)
{
	return fail(__func__);
}

int joold_advertise(struct xlator *jool)
{
	return fail(__func__);
}

void joold_ack(struct xlator *jool)
{
	fail(__func__);
}
