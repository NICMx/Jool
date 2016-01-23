#include "nat64/mod/stateful/pool4/db.h"

#include <linux/hash.h>
#include <linux/list.h>
#include <linux/slab.h>
#include "nat64/mod/common/rcu.h"
#include "nat64/mod/common/types.h"
#include "nat64/mod/common/tags.h"
#include "nat64/mod/stateful/pool4/empty.h"
#include "nat64/mod/stateful/pool4/table.h"

struct pool4 {
	/** Note, this is an array (size 2^@power). */
	struct hlist_head __rcu *db;
	/** Number of entries (ie. tables) in the database. */
	unsigned int tables;
	/**
	 * Defines the number of "slots" in the table (2^power).
	 * (Each slot is a hlist_head.)
	 *
	 * It doesn't require locking because it never changes after init.
	 */
	unsigned int power;

	struct kref refcounter;
};

/** Protects @db and @tables, only on updater code. */
static DEFINE_MUTEX(lock);

RCUTAG_FREE
static unsigned int slots(struct pool4 *pool)
{
	return 1 << pool->power;
}

RCUTAG_FREE
static struct pool4_table *table_entry(struct hlist_node *node)
{
	return hlist_entry(node, struct pool4_table, hlist_hook);
}

RCUTAG_USR /* Only because of GFP_KERNEL. Can be easily upgraded to FREE. */
static struct hlist_head *init_hlist(unsigned int size)
{
	struct hlist_head *result;
	unsigned int i;

	result = kmalloc(size * sizeof(*result), GFP_KERNEL);
	if (!result)
		return NULL;
	for (i = 0; i < size; i++)
		INIT_HLIST_HEAD(&result[i]);

	return result;
}

/*
 * This NEEDS to be called during initialization because @power needs to stay
 * put after that.
 */
RCUTAG_INIT
static int init_power(struct pool4 *pool, unsigned int size)
{
	if (size == 0)
		size = 16;

	if (size > (1U << 31)) {
		/*
		 * If you ever want to remove this validation for some crazy
		 * reason... keep in mind it's preventing overflow from the for
		 * below.
		 */
		log_err("Pool4's hashtable size is too large.");
		return -EINVAL;
	}

	/* 2^@power = smallest power of two greater or equal than @size. */
	for (pool->power = 0; slots(pool) < size; pool->power++)
		/* Chomp chomp. */;

	return 0;
}

RCUTAG_INIT /* Inherits INIT from init_power(). */
int pool4db_init(struct pool4 **pool, unsigned int size)
{
	struct pool4 *result;
	struct hlist_head *hlist;
	int error;

	result = kmalloc(sizeof(*result), GFP_KERNEL);
	if (!result)
		return -ENOMEM;

	error = init_power(result, size);
	if (error) {
		kfree(result);
		return error;
	}
	result->tables = 0;
	hlist = init_hlist(slots(result));
	if (!hlist) {
		kfree(result);
		return -ENOMEM;
	}
	RCU_INIT_POINTER(result->db, hlist);
	kref_init(&result->refcounter);

	*pool = result;
	return 0;
}

void pool4db_get(struct pool4 *pool)
{
	kref_get(&pool->refcounter);
}

RCUTAG_FREE
static void __destroy(struct hlist_head *db, unsigned int db_len)
{
	struct hlist_node *node;
	struct hlist_node *tmp;
	unsigned int i;

	for (i = 0; i < db_len; i++) {
		hlist_for_each_safe(node, tmp, &db[i]) {
			hlist_del(node);
			pool4table_destroy(table_entry(node));
		}
	}

	kfree(db);
}

static void release(struct kref *refcounter)
{
	struct pool4 *pool;
	pool = container_of(refcounter, typeof(*pool), refcounter);
	__destroy(rcu_dereference_raw(pool->db), slots(pool));
	kfree(pool);
}

void pool4db_put(struct pool4 *pool)
{
	kref_put(&pool->refcounter, release);
}

RCUTAG_PKT /* Assumes locking (whether RCU or mutex) has already been done. */
static struct pool4_table *find_table(struct hlist_head *database,
		unsigned int power, const __u32 mark, enum l4_protocol proto)
{
	struct pool4_table *table;
	struct hlist_node *node;
	u32 hash;

	hash = hash_32(mark, power);

	/* Short version: node = database[hash]->first. */
	node = rcu_dereference_bh_check(hlist_first_rcu(&database[hash]),
			lockdep_is_held(&lock));

	while (node) {
		table = table_entry(node);
		if (table->mark == mark && table->proto == proto)
			return table;

		/* Short version: node = node->next. */
		node = rcu_dereference_bh_check(hlist_next_rcu(node),
				lockdep_is_held(&lock));
	}

	return NULL;
}

int pool4db_add(struct pool4 *pool, const __u32 mark, enum l4_protocol proto,
		struct ipv4_prefix *prefix, struct port_range *ports)
{
	struct hlist_head *db;
	struct pool4_table *table;
	int error;

	mutex_lock(&lock);

	db = rcu_dereference_protected(pool->db, lockdep_is_held(&lock));
	table = find_table(db, pool->power, mark, proto);
	if (!table) {
		table = pool4table_create(mark, proto);
		if (!table) {
			error = -ENOMEM;
			goto end;
		}

		error = pool4table_add(table, prefix, ports);
		if (error) {
			pool4table_destroy(table);
			return error;
		}

		pool->tables++;
		hlist_add_head_rcu(&table->hlist_hook,
				&db[hash_32(mark, pool->power)]);
		if (pool->tables > slots(pool))
			log_warn_once("You have lots of pool4s, which can lag Jool. Consider increasing pool4_size.");

	} else {
		error = pool4table_add(table, prefix, ports);

	}

end:
	mutex_unlock(&lock);
	return error;
}

RCUTAG_USR
int pool4db_rm(struct pool4 *pool, const __u32 mark, enum l4_protocol proto,
		struct ipv4_prefix *prefix, struct port_range *ports)
{
	struct hlist_head *db;
	struct pool4_table *table;
	int error;

	mutex_lock(&lock);

	db = rcu_dereference_protected(pool->db, lockdep_is_held(&lock));
	table = find_table(db, pool->power, mark, proto);
	if (!table) {
		error = -ESRCH;
		goto end;
	}

	error = pool4table_rm(table, prefix, ports);
	if (error)
		goto end;

	if (pool4table_is_empty(table)) {
		hlist_del_rcu(&table->hlist_hook);
		synchronize_rcu_bh();
		pool4table_destroy(table);
		pool->tables--;
	}

end:
	mutex_unlock(&lock);
	return error;
}

RCUTAG_USR
int pool4db_flush(struct pool4 *pool)
{
	struct hlist_head *new;
	struct hlist_head *old;

	new = init_hlist(slots(pool));
	if (!new)
		return -ENOMEM;

	mutex_lock(&lock);
	old = rcu_dereference_protected(pool->db, lockdep_is_held(&lock));
	rcu_assign_pointer(pool->db, new);
	pool->tables = 0;
	mutex_unlock(&lock);

	synchronize_rcu_bh();

	__destroy(old, slots(pool));
	return 0;
}

/* TODO Why is this not receving mark? */
RCUTAG_PKT
bool pool4db_contains(struct pool4 *pool, struct net *ns,
		enum l4_protocol proto, struct ipv4_transport_addr *addr)
{
	struct hlist_head *db;
	struct pool4_table *table;
	struct hlist_node *node;
	unsigned int i;
	bool found = false;

	rcu_read_lock_bh();

	if (pool4db_is_empty(pool)) {
		found = pool4empty_contains(ns, addr);
		goto end;
	}

	db = rcu_dereference_bh(pool->db);
	for (i = 0; i < slots(pool); i++) {
		hlist_for_each_rcu_bh(node, &db[i]) {
			table = table_entry(node);
			if (table->proto != proto)
				continue;

			if (pool4table_contains(table, addr)) {
				found = true;
				goto end;
			}
		}
	}

end:
	rcu_read_unlock_bh();
	return found;
}

RCUTAG_PKT
bool pool4db_is_empty(struct pool4 *pool)
{
	struct hlist_head *db;
	struct hlist_node *node;
	unsigned int i;
	bool empty = true;

	rcu_read_lock_bh();

	db = rcu_dereference_bh(pool->db);
	for (i = 0; i < slots(pool); i++) {
		hlist_for_each_rcu_bh(node, &db[i]) {
			if (!pool4table_is_empty(table_entry(node))) {
				empty = false;
				goto end;
			}
		}
	}

end:
	rcu_read_unlock_bh();
	return empty;
}

RCUTAG_PKT
void pool4db_count(struct pool4 *pool, __u32 *tables_out, __u64 *samples,
		__u64 *taddrs)
{
	struct hlist_head *db;
	struct hlist_node *node;
	unsigned int i;

	(*tables_out) = 0;
	(*samples) = 0;
	(*taddrs) = 0;

	rcu_read_lock_bh();
	db = rcu_dereference_bh(pool->db);
	for (i = 0; i < slots(pool); i++) {
		hlist_for_each_rcu_bh(node, &db[i]) {
			(*tables_out)++;
			pool4table_count(table_entry(node), samples, taddrs);
		}
	}
	rcu_read_unlock_bh();
}

RCUTAG_PKT
int pool4db_foreach_sample(struct pool4 *pool,
		int (*cb)(struct pool4_sample *, void *), void *arg,
		struct pool4_sample *offset)
{
	struct hlist_head *db;
	struct pool4_table *table;
	struct hlist_node *node;
	u32 hash = offset ? hash_32(offset->mark, pool->power) : 0;
	int error = 0;

	rcu_read_lock_bh();

	db = rcu_dereference_bh(pool->db);
	for (; hash < slots(pool); hash++) {
		hlist_for_each_rcu_bh(node, &db[hash]) {
			table = table_entry(node);
			if (offset) {
				if (table->mark == offset->mark && table->proto == offset->proto) {
					error = pool4table_foreach_sample(table,
							cb, arg, offset);
					if (error)
						goto end;
					offset = NULL;
				}
			} else {
				error = pool4table_foreach_sample(table, cb,
						arg, NULL);
				if (error)
					goto end;
			}
		}
	}

end:
	rcu_read_unlock_bh();
	return error;
}

static enum l4_protocol proto_to_l4proto(__u8 proto)
{
	switch (proto) {
	case IPPROTO_TCP:
		return L4PROTO_TCP;
	case IPPROTO_UDP:
		return L4PROTO_UDP;
	case IPPROTO_ICMP:
		return L4PROTO_ICMP;
	}

	return L4PROTO_OTHER;
}

/**
 * As a contract, this function will return:
 *
 * - As usual, negative integers as errors (in particular, -ESRCH if there's at
 *   least one element in the pool and there's no pool4 entry mapped to @in's
 *   mark and proto).
 * - If cb decides to stop iteration early, it will do so by returning nonzero
 *   (preferably positive), and that will in turn become the result of this
 *   function.
 * - 0 if iteration ended with no interruptions.
 *
 * This function might need to route, hence it has lots of noisy arguments.
 */
RCUTAG_PKT
int pool4db_foreach_taddr4(struct pool4 *pool, struct net *ns,
		struct in_addr *daddr, __u8 tos, __u8 proto, __u32 mark,
		int (*cb)(struct ipv4_transport_addr *, void *), void *arg,
		unsigned int offset)
{
	struct pool4_table *table;
	int error;

	rcu_read_lock_bh();

	if (pool4db_is_empty(pool)) {
		error = pool4empty_foreach_taddr4(ns, daddr, tos, proto, mark,
				cb, arg, offset);
	} else {
		table = find_table(rcu_dereference_bh(pool->db), pool->power,
				mark, proto_to_l4proto(proto));
		if (!table) {
			error = -ESRCH;
			goto end;
		}
		error = pool4table_foreach_taddr4(table, cb, arg, offset);
	}

end:
	rcu_read_unlock_bh();
	return error;
}
