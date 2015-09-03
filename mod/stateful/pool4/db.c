#include "nat64/mod/stateful/pool4/db.h"

#include <linux/hash.h>
#include <linux/list.h>
#include <linux/rculist.h>
#include <linux/slab.h>
#include "nat64/mod/common/rcu.h"
#include "nat64/mod/common/tags.h"
#include "nat64/mod/common/types.h"
#include "nat64/mod/stateful/pool4/table.h"

/** Note, this is an array (size 2^@power). */
static struct hlist_head __rcu *db;
/** Number of entries (ie. tables) in the database. */
static unsigned int tables;

/**
 * Defines the number of "slots" in the table (2^power).
 * (Each slot is a hlist_head.)
 *
 * It doesn't require locking because it never changes after init.
 */
static unsigned int power;

/** Protects @db and @tables, only on updater code. */
static DEFINE_MUTEX(lock);

RCUTAG_FREE
static unsigned int slots(void)
{
	return 1 << power;
}

RCUTAG_FREE
static struct pool4_table *table_entry(struct hlist_node *node)
{
	return hlist_entry(node, struct pool4_table, hlist_hook);
}

RCUTAG_USR /* Only because of GFP_KERNEL. Can be easily upgraded to FREE. */
static struct hlist_head *init_db(unsigned int size)
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

RCUTAG_USR
static int add_prefix_strings(char *prefix_strs[], int prefix_count)
{
	struct ipv4_prefix prefix;
	struct port_range ports;
	unsigned int i;
	int error;

	ports.max = 65535U;
	for (i = 0; i < prefix_count; i++) {
		error = prefix4_parse(prefix_strs[i], &prefix);
		if (error)
			return error;

		ports.min = 61001U;
		error = pool4db_add(0, L4PROTO_TCP, &prefix, &ports);
		if (error)
			return error;
		error = pool4db_add(0, L4PROTO_UDP, &prefix, &ports);
		if (error)
			return error;

		ports.min = 0U;
		error = pool4db_add(0, L4PROTO_ICMP, &prefix, &ports);
		if (error)
			return error;
	}

	return 0;
}

/*
 * This NEEDS to be called during initialization because @power needs to stay
 * put after that.
 */
RCUTAG_INIT
static int init_power(unsigned int size)
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
	for (power = 0; slots() < size; power++)
		/* Chomp chomp. */;

	return 0;
}

RCUTAG_INIT /* Inherits INIT from init_power(). */
int pool4db_init(unsigned int size, char *prefix_strs[], int prefix_count)
{
	struct hlist_head *tmp;
	int error;

	error = init_power(size);
	if (error)
		return error;

	tables = 0;
	tmp = init_db(slots());
	if (!tmp)
		return -ENOMEM;
	rcu_assign_pointer(db, tmp);

	error = add_prefix_strings(prefix_strs, prefix_count);
	if (error)
		pool4db_destroy();

	return error;
}

RCUTAG_FREE
static void __destroy(struct hlist_head *db)
{
	struct hlist_node *node;
	struct hlist_node *tmp;
	unsigned int i;

	for (i = 0; i < slots(); i++) {
		hlist_for_each_safe(node, tmp, &db[i]) {
			hlist_del(node);
			pool4table_destroy(table_entry(node));
		}
	}

	kfree(db);
}

RCUTAG_USR
static void pool4db_replace(struct hlist_head *new, unsigned int count)
{
	struct hlist_head *old;

	mutex_lock(&lock);
	old = rcu_dereference_protected(db, lockdep_is_held(&lock));
	rcu_assign_pointer(db, new);
	tables = count;
	mutex_unlock(&lock);

	synchronize_rcu_bh();

	__destroy(old);
}

RCUTAG_USR
void pool4db_destroy(void)
{
	pool4db_replace(NULL, 0);
}

RCUTAG_PKT /* Assumes locking (whether RCU or mutex) has already been done. */
static struct pool4_table *find_table(struct hlist_head *database,
		const __u32 mark, enum l4_protocol proto)
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

RCUTAG_USR
int pool4db_add(const __u32 mark, enum l4_protocol proto,
		struct ipv4_prefix *prefix, struct port_range *ports)
{
	struct hlist_head *database;
	struct pool4_table *table;
	int error;

	mutex_lock(&lock);

	database = rcu_dereference_protected(db, lockdep_is_held(&lock));
	table = find_table(database, mark, proto);
	if (!table) {
		table = pool4table_create(mark, proto);
		if (!table) {
			error = -ENOMEM;
			goto end;
		}

		error = pool4table_add(table, prefix, ports);
		if (error) {
			pool4table_destroy(table);
			goto end;
		}

		tables++;
		hlist_add_head_rcu(&table->hlist_hook,
				&database[hash_32(mark, power)]);
		if (tables > slots()) {
			log_warn_once("You have lots of pool4s, which can lag "
					"Jool. Consider increasing "
					"pool4_size.");
		}

	} else {
		error = pool4table_add(table, prefix, ports);

	}

end:
	mutex_unlock(&lock);
	return error;
}

RCUTAG_USR
int pool4db_rm(const __u32 mark, enum l4_protocol proto,
		struct ipv4_prefix *prefix, struct port_range *ports)
{
	struct hlist_head *database;
	struct pool4_table *table;
	int error;

	mutex_lock(&lock);

	database = rcu_dereference_protected(db, lockdep_is_held(&lock));
	table = find_table(database, mark, proto);
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
		tables--;
	}

end:
	mutex_unlock(&lock);
	return error;
}

RCUTAG_USR
int pool4db_flush(void)
{
	struct hlist_head *new;

	new = init_db(slots());
	if (!new)
		return -ENOMEM;

	pool4db_replace(new, 0);
	return 0;
}

RCUTAG_PKT
bool pool4db_contains(enum l4_protocol proto, struct ipv4_transport_addr *addr)
{
	struct hlist_head *database;
	struct pool4_table *table;
	struct hlist_node *node;
	unsigned int i;
	bool found = false;

	rcu_read_lock_bh();

	database = rcu_dereference_bh(db);
	for (i = 0; i < slots(); i++) {
		hlist_for_each_rcu_bh(node, &database[i]) {
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
bool pool4db_is_empty(void)
{
	struct hlist_head *database;
	struct hlist_node *node;
	unsigned int i;
	bool empty = true;

	rcu_read_lock_bh();

	database = rcu_dereference_bh(db);
	for (i = 0; i < slots(); i++) {
		hlist_for_each_rcu_bh(node, &database[i]) {
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
void pool4db_count(__u32 *tables_out, __u64 *samples, __u64 *taddrs)
{
	struct hlist_head *database;
	struct hlist_node *node;
	unsigned int i;

	(*tables_out) = 0;
	(*samples) = 0;
	(*taddrs) = 0;

	rcu_read_lock_bh();
	database = rcu_dereference_bh(db);
	for (i = 0; i < slots(); i++) {
		hlist_for_each_rcu_bh(node, &database[i]) {
			(*tables_out)++;
			pool4table_count(table_entry(node), samples, taddrs);
		}
	}
	rcu_read_unlock_bh();

	WARN((*tables_out) != tables, "Computed table count doesn't match "
			"stored table count.");
}

RCUTAG_PKT
int pool4db_foreach_sample(int (*cb)(struct pool4_sample *, void *), void *arg,
		struct pool4_sample *offset)
{
	struct hlist_head *database;
	struct pool4_table *table;
	struct hlist_node *node;
	u32 hash = offset ? hash_32(offset->mark, power) : 0;
	int error = 0;

	rcu_read_lock_bh();

	database = rcu_dereference_bh(db);
	for (; hash < slots(); hash++) {
		hlist_for_each_rcu_bh(node, &database[hash]) {
			table = table_entry(node);
			if (offset) {
				if (table->mark == offset->mark) {
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

/**
 * As a contract, this function will return:
 *
 * - ESRCH if there's no pool4 entry mapped to mark and proto.
 * - 0 if there's at least one pool4 entry mapped to mark and proto, and
 *   eaach of their transport addresses were iterated.
 * - If cb decides to stop iteration early, it will do so by returning nonzero,
 *   and that will in turn become the result of this function.
 */
RCUTAG_PKT
int pool4db_foreach_taddr4(const __u32 mark, enum l4_protocol proto,
		int (*cb)(struct ipv4_transport_addr *, void *), void *arg,
		unsigned int offset)
{
	struct pool4_table *table;
	int error;
	rcu_read_lock_bh();

	table = find_table(rcu_dereference_bh(db), mark, proto);
	error = table ? pool4table_foreach_taddr4(table, cb, arg, offset)
			: -ESRCH;

	rcu_read_unlock_bh();
	return error;
}
