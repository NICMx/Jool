#include "nat64/mod/stateful/compute_outgoing_tuple.h"
#include "nat64/mod/stateful/determine_incoming_tuple.h"
#include "nat64/mod/stateful/filtering_and_updating.h"
#include "nat64/mod/stateful/fragment_db.h"
#include "nat64/mod/stateful/joold.h"
#include "nat64/mod/stateful/pool4/db.h"
#include "nat64/mod/stateful/bib/db.h"

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

struct fragdb *fragdb_create(struct net *ns)
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

struct bib *bib_create(void)
{
	fail(__func__);
	return NULL;
}

void bib_get(struct bib *db)
{
	fail(__func__);
}

void bib_put(struct bib *db)
{
	fail(__func__);
}

void bib_config_copy(struct bib *db, struct bib_config *config)
{
	/* No code. */
}

void bib_config_set(struct bib *db, struct bib_config *config)
{
	/* No code. */
}

int bib_find6(struct bib *db, l4_protocol proto,
		struct ipv6_transport_addr *addr,
		struct bib_entry *result)
{
	return fail(__func__);
}

int bib_find4(struct bib *db, l4_protocol proto,
		struct ipv4_transport_addr *addr,
		struct bib_entry *result)
{
	return fail(__func__);
}

int bib_add_static(struct bib *db, struct bib_entry *new, struct bib_entry *old)
{
	return fail(__func__);
}

int bib_rm(struct bib *db, struct bib_entry *entry)
{
	return fail(__func__);
}

void bib_rm_range(struct bib *db, l4_protocol proto, struct ipv4_range *range)
{
	fail(__func__);
}

void bib_flush(struct bib *db)
{
	fail(__func__);
}

int bib_foreach(struct bib *db, l4_protocol proto,
		struct bib_foreach_func *func,
		const struct ipv4_transport_addr *offset)
{
	return fail(__func__);
}

int bib_foreach_session(struct bib *db, l4_protocol proto,
		struct session_foreach_func *collision_cb,
		struct session_foreach_offset *offset)
{
	return fail(__func__);
}

int bib_count(struct bib *db, const l4_protocol proto, __u64 *result)
{
	return fail(__func__);
}

int bib_count_sessions(struct bib *db, l4_protocol proto, __u64 *count)
{
	return fail(__func__);
}

void bib_session_init(struct bib_session *bs)
{
	/* No code. */
}

void joold_ack(struct xlator *jool)
{
	fail(__func__);
}
