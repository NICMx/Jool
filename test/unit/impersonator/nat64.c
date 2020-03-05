#include "mod/common/joold.h"
#include "mod/common/db/pool4/db.h"
#include "mod/common/db/bib/db.h"
#include "mod/common/steps/compute_outgoing_tuple.h"
#include "mod/common/steps/determine_incoming_tuple.h"
#include "mod/common/steps/filtering_and_updating.h"

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

struct joold_queue *joold_alloc(struct net *ns)
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

struct pool4 *pool4db_alloc(void)
{
	fail(__func__);
	return NULL;
}

void pool4db_get(struct pool4 *pool)
{
	fail(__func__);
}

void pool4db_put(struct pool4 *pool)
{
	fail(__func__);
}

int pool4db_add(struct pool4 *pool, const struct pool4_entry *entry)
{
	return fail(__func__);
}

int pool4db_update(struct pool4 *pool, const struct pool4_update *update)
{
	return fail(__func__);
}

int pool4db_rm_usr(struct pool4 *pool, struct pool4_entry *entry)
{
	return fail(__func__);
}

void pool4db_flush(struct pool4 *pool)
{
	fail(__func__);
}

int pool4db_foreach_sample(struct pool4 *pool, l4_protocol proto,
		pool4db_foreach_entry_cb cb, void *arg,
		struct pool4_entry *offset)
{
	return fail(__func__);
}

bool pool4db_contains(struct pool4 *pool, struct net *ns,
		enum l4_protocol proto, struct ipv4_transport_addr *addr)
{
	fail(__func__);
	return false;
}

struct bib *bib_alloc(void)
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

int bib_add_static(struct xlator *jool, struct bib_entry *new)
{
	return fail(__func__);
}

int bib_rm(struct xlator *jool, struct bib_entry *entry)
{
	return fail(__func__);
}

void bib_rm_range(struct xlator *jool, l4_protocol proto,
		struct ipv4_range *range)
{
	fail(__func__);
}

void bib_flush(struct xlator *jool)
{
	fail(__func__);
}

int bib_foreach(struct bib *db, l4_protocol proto,
		bib_foreach_entry_cb cb, void *cb_arg,
		const struct ipv4_transport_addr *offset)
{
	return fail(__func__);
}

int bib_foreach_session(struct xlator *jool, l4_protocol proto,
		session_foreach_entry_cb cb, void *cb_arg,
		struct session_foreach_offset *offset)
{
	return fail(__func__);
}

void joold_ack(struct xlator *jool)
{
	fail(__func__);
}

bool is_hairpin_nat64(struct xlation *state)
{
	fail(__func__);
	return false;
}

verdict handling_hairpinning_nat64(struct xlation *old)
{
	fail(__func__);
	return VERDICT_DROP;
}
