#include "nat64/mod/stateful/pool4/db.h"

#include <linux/hash.h>
#include <linux/slab.h>
#include "nat64/mod/common/types.h"
#include "nat64/mod/stateful/pool4/table.h"

struct hlist_head *db;
/** Defines the number of slots in the table (2^power). */
unsigned int power;
unsigned int values;

static int slots(void)
{
	return 1 << power;
}

static struct hlist_head *init_db(unsigned int size)
{
	struct hlist_head *result;
	unsigned int i;

	result = kmalloc(size * sizeof(*result), GFP_KERNEL);
	if (!result)
		return NULL;
	for (i = 0; i < slots(); i++)
		INIT_HLIST_HEAD(&result[i]);

	return result;
}

static int add_prefix_strings(char *prefix_strs[], int prefix_count)
{
	struct ipv4_prefix prefix;
	struct port_range ports;
	unsigned int i;
	int error;

	/* TODO (issue36) align the defaults with masquerade. */
	ports.min = 60000U;
	ports.max = 65535U;

	for (i = 0; i < prefix_count; i++) {
		error = prefix4_parse(prefix_strs[i], &prefix);
		if (error)
			return error;
		error = pool4db_add(0, &prefix, &ports);
		if (error)
			return error;
	}

	return 0;
}

static int init_power(unsigned int size)
{
	if (size > (1U << 31)) {
		/*
		 * If you ever want to remove this validation for some crazy
		 * reason... keep in mind it's preventing overflow from the for
		 * below.
		 */
		log_err("Pool4's hashtable size is too large.");
		return -EINVAL;
	}

	/* @power = smallest power of two greater or equal than @size. */
	for (power = 1; power < size; power <<= 1)
		/* Chomp chomp. */;

	return 0;
}

int pool4db_init(unsigned int size, char *prefix_strs[], int prefix_count)
{
	int error;

	error = init_power(size);
	if (error)
		return error;
	values = 0;
	db = init_db(slots());
	if (!db)
		return -ENOMEM;

	error = add_prefix_strings(prefix_strs, prefix_count);
	if (error)
		pool4db_destroy();

	return error;
}

void pool4db_destroy(void)
{
	struct hlist_node *hnode;
	struct pool4_table *table;
	unsigned int i;

	for (i = 0; i < slots(); i++) {
		while (!hlist_empty(&db[i])) {
			hnode = db[i].first;
			table = hlist_entry(hnode, typeof(*table), hlist_hook);
			hlist_del(hnode);
			pool4table_destroy(table);
		}
	}

	kfree(db);
}

/**
 * Assumes RCU has been locked, if needed.
 */
static struct pool4_table *find_table(const __u32 mark)
{
	struct pool4_table *table;
	u32 hash;

	hash = hash_32(mark, power);
	hlist_for_each_entry(table, &db[hash], hlist_hook) {
		if (table->mark == mark)
			return table;
	}

	return NULL;
}

int pool4db_add(const __u32 mark, struct ipv4_prefix *prefix,
		struct port_range *ports)
{
	struct pool4_table *table;
	int error;

	table = find_table(mark);
	if (!table) {
		table = pool4table_create(mark);
		if (!table)
			return -ENOMEM;

		error = pool4table_add(table, prefix, ports);
		if (error) {
			pool4table_destroy(table);
			return error;
		}

		values++;
		hlist_add_head(&table->hlist_hook, &db[hash_32(mark, power)]);
		if (values > slots()) {
			log_warn_once("You have lots of pool4s, which can lag "
					"Jool. Consider increasing "
					"pool4_size.");
		}

	} else {
		error = pool4table_add(table, prefix, ports);

	}

	return error;
}

int pool4db_rm(const __u32 mark, struct ipv4_prefix *prefix,
		struct port_range *ports)
{
	struct pool4_table *table;
	int error;

	table = find_table(mark);
	error = table ? pool4table_rm(table, prefix, ports) : -ESRCH;

	return error;
}

int pool4db_flush(const __u32 mark)
{
	struct pool4_table *table;

	table = find_table(mark);
	if (!table)
		return -ESRCH;

	hlist_del_rcu(&table->hlist_hook);
	synchronize_rcu();

	pool4table_destroy(table);
	return 0;
}

bool pool4db_contains(const __u32 mark, struct ipv4_transport_addr *addr)
{
	struct pool4_table *table;
	int error;
	rcu_read_lock();

	table = find_table(mark);
	error = table ? pool4table_contains(table, addr) : -ESRCH;

	rcu_read_unlock();
	return error;
}

bool pool4db_contains_all(struct ipv4_transport_addr *addr)
{
	struct pool4_table *table;
	unsigned int i;
	bool found = false;

	rcu_read_lock();

	for (i = 0; i < slots(); i++) {
		hlist_for_each_entry(table, &db[i], hlist_hook) {
			if (pool4table_contains(table, addr)) {
				found = true;
				goto end;
			}
		}
	}

end:
	rcu_read_unlock();
	return found;
}

bool pool4db_is_empty(void)
{
	struct pool4_table *table;
	unsigned int i;
	bool empty = true;

	rcu_read_lock();

	for (i = 0; i < slots(); i++) {
		hlist_for_each_entry(table, &db[i], hlist_hook) {
			if (pool4table_is_empty(table)) {
				empty = false;
				goto end;
			}
		}
	}

end:
	rcu_read_unlock();
	return empty;
}

int pool4db_foreach_sample(const __u32 mark,
		int (*func)(struct pool4_sample *, void *), void *arg,
		struct pool4_sample *offset)
{
	struct pool4_table *table;
	int error;
	rcu_read_lock();

	table = find_table(mark);
	error = table ? pool4table_foreach_sample(table, func, arg, offset)
			: -ESRCH;

	rcu_read_unlock();
	return error;
}

int pool4db_foreach_port(const __u32 mark,
		int (*func)(struct ipv4_transport_addr *, void *), void *arg,
		unsigned int offset)
{
	struct pool4_table *table;
	int error;
	rcu_read_lock();

	table = find_table(mark);
	error = table ? pool4table_foreach_port(table, func, arg, offset)
			: -ESRCH;

	rcu_read_unlock();
	return error;
}
