#include "nat64/mod/stateful/pool4/db.h"
#include "nat64/mod/stateful/pool4/table.h"
#include <linux/hash.h>

struct hlist_head *table;
/** Defines the number of slots in the table (2^power). */
unsigned int power;
unsigned int values;

static int slots(void)
{
	return 1 << power;
}

static struct hlist_head *init_table(unsigned int size)
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

int pool4db_init(void)
{
	power = 4;
	values = 0;
	table = init_table(slots());
	return table ? 0 : -ENOMEM;
}

void pool4db_destroy(void)
{
	struct hlist_node *hnode;
	struct pool4_node *node;
	unsigned int i;

	for (i = 0; i < slots(); i++) {
		while (!hlist_empty(&table[i])) {
			hnode = table[i].first;
			node = hlist_entry(hnode, typeof(*node), list_hook);
			hlist_del(hnode);
			pool4_node_kfree(node);
		}
	}

	kfree(table);
}

static struct pool4_node *find_node(const __u32 mark)
{
	struct hlist_node *hnode;
	struct pool4_node *node;
	u32 hash;

	hash = hash_32(mark, power);
	hlist_for_each_entry(node, hnode, &table[hash], list_hook) {
		if (node->mark == mark)
			return node;
	}

	return NULL;
}

static int create_node(const __u32 mark, const struct pool4_sample *sample)
{
	struct pool4_node *node;
	int error;

	node = pool4entry_create(sample);
	if (!node)
		return -ENOMEM;

	values++;
	if (values > slots()) {
		/* TODO implement this. */
		log_warning("You have lots of pool4s, which can lag Jool. "
				"Consider increasing --pool4 --capacity.");
	}

	hlist_add_head(&node->list_hook, &table[hash_32(mark, power)]);
	return 0;
}

int pool4db_add(const __u32 mark, const struct pool4_sample *sample)
{
	struct pool4_node *node;
	int error;
	rcu_read_lock();

	node = find_node(mark);
	error = node ? pool4table_add(node, sample) : create_node(mark, sample);

	rcu_read_unlock();
	return error;
}

int pool4db_rm(const __u32 mark, const struct pool4_sample *sample)
{
	struct pool4_node *node;
	int error = -ESRCH;
	rcu_read_lock();

	node = find_node(mark);
	if (node)
		error = pool4table_rm(node, sample);

	rcu_read_unlock();
	return error;
}

int pool4db_foreach_port(const __u32 mark,
		int (*func)(struct ipv4_transport_addr *, void *), void *args,
		unsigned int offset)
{
	struct pool4_node *node;
	int error = -ESRCH;
	rcu_read_lock();

	node = find_node(mark);
	if (node)
		error = pool4table_foreach_port(node, func, args, offset);

	rcu_read_unlock();
	return error;
}
