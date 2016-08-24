#include "nat64/mod/stateful/pool4/db.h"

#include <linux/hash.h>
#include <linux/list.h>
#include <linux/slab.h>
#include "nat64/common/types.h"
#include "nat64/mod/common/rbtree.h"
#include "nat64/mod/common/wkmalloc.h"
#include "nat64/mod/stateful/pool4/empty.h"
#include "nat64/mod/stateful/pool4/rfc6056.h"

struct pool4_table {
	union {
		__u32 mark;
		struct in_addr addr;
	};
	unsigned int taddr_count;
	unsigned int sample_count;
	struct rb_node tree_hook;

	/*
	 * An array of struct pool4_range hangs off here.
	 * (The array length is @sample_count.)
	 */
};

/**
 * Assumes @table has at least one entry.
 */
#define foreach_table_range(entry, table) \
	for (entry = first_table_entry(table); \
			entry < first_table_entry(table) + table->sample_count; \
			entry++)

struct pool4_trees {
	struct rb_root tcp;
	struct rb_root udp;
	struct rb_root icmp;
};

struct pool4 {
	/** Entries indexed via mark. (Normally used in 6->4) */
	struct pool4_trees tree_mark;
	/** Entries indexed via address. (Normally used in 4->6) */
	struct pool4_trees tree_addr;

	spinlock_t lock;
	struct kref refcounter;
};

struct mask_domain {
	unsigned int taddr_count;
	unsigned int taddr_counter;

	unsigned int range_count;
	struct pool4_range *current_range;
	int current_port;

	/**
	 * A "dynamic" domain is one that was generated on the fly - that is,
	 * Jool queried the interface addresses, picked one and used it to
	 * improvise a domain.
	 *
	 * A "static" domain is one the user predefined.
	 *
	 * Empty pool4 generates dynamic domains and populated ones generate
	 * static domains.
	 */
	bool dynamic;

	/*
	 * An array of struct pool4_range hangs off here.
	 * (The array length is @sample_count.)
	 */
};

/**
 * Assumes @domain has at least one entry.
 */
#define foreach_domain_range(entry, domain) \
	for (entry = first_domain_entry(domain); \
			entry < first_domain_entry(domain) + domain->range_count; \
			entry++)

static struct rb_root *get_tree(struct pool4_trees *trees, l4_protocol proto)
{
	switch (proto) {
	case L4PROTO_TCP:
		return &trees->tcp;
	case L4PROTO_UDP:
		return &trees->udp;
	case L4PROTO_ICMP:
		return &trees->icmp;
	case L4PROTO_OTHER:
		break;
	}

	WARN(true, "Unsupported transport protocol: %u.", proto);
	return NULL;
}

static int cmp_mark(struct pool4_table *table, __u32 mark)
{
	return ((int)mark) - (int)table->mark;
}

static struct pool4_table *find_by_mark(struct rb_root *tree, __u32 mark)
{
	if (unlikely(!tree))
		return NULL;
	return rbtree_find(mark, tree, cmp_mark, struct pool4_table, tree_hook);
}

static int cmp_addr(struct pool4_table *table, struct in_addr *addr)
{
	return ipv4_addr_cmp(&table->addr, addr);
}

static struct pool4_table *find_by_addr(struct rb_root *tree,
		struct in_addr *addr)
{
	if (unlikely(!tree))
		return NULL;
	return rbtree_find(addr, tree, cmp_addr, struct pool4_table, tree_hook);
}

static int cmp_prefix(struct pool4_table *table, struct ipv4_prefix *prefix)
{
	if (prefix4_contains(prefix, &table->addr))
		return 0;
	return ipv4_addr_cmp(&table->addr, &prefix->address);
}

static struct pool4_table *find_by_prefix(struct rb_root *tree,
		struct ipv4_prefix *prefix)
{
	return rbtree_find(prefix, tree, cmp_prefix, struct pool4_table,
			tree_hook);
}

static bool is_empty(struct pool4 *pool)
{
	return RB_EMPTY_ROOT(&pool->tree_mark.tcp)
			&& RB_EMPTY_ROOT(&pool->tree_mark.udp)
			&& RB_EMPTY_ROOT(&pool->tree_mark.icmp);
}

static struct pool4_range *first_table_entry(struct pool4_table *table)
{
	return (struct pool4_range *)(table + 1);
}

static struct pool4_range *last_table_entry(struct pool4_table *table)
{
	return first_table_entry(table) + table->sample_count - 1;
}

static struct pool4_range *first_domain_entry(struct mask_domain *domain)
{
	return (struct pool4_range *)(domain + 1);
}

/* Leaves table->addr and table->mark undefined! */
static struct pool4_table *create_table(struct pool4_range *range)
{
	struct pool4_table *table;
	struct pool4_range *entry;

	table = __wkmalloc("pool4table",
			sizeof(struct pool4_table) + sizeof(struct pool4_range),
			GFP_ATOMIC);
	if (!table)
		return NULL;

	table->taddr_count = port_range_count(&range->ports);
	table->sample_count = 1;

	entry = first_table_entry(table);
	*entry = *range;

	return table;
}

int pool4db_init(struct pool4 **pool)
{
	struct pool4 *result;

	result = wkmalloc(struct pool4, GFP_KERNEL);
	if (!result)
		return -ENOMEM;

	result->tree_mark.tcp = RB_ROOT;
	result->tree_mark.udp = RB_ROOT;
	result->tree_mark.icmp = RB_ROOT;
	result->tree_addr.tcp = RB_ROOT;
	result->tree_addr.udp = RB_ROOT;
	result->tree_addr.icmp = RB_ROOT;
	spin_lock_init(&result->lock);
	kref_init(&result->refcounter);

	*pool = result;
	return 0;
}

void pool4db_get(struct pool4 *pool)
{
	kref_get(&pool->refcounter);
}

static void destroy_table(struct pool4_table *table)
{
	__wkfree("pool4table", table);
}

static void destroy_table_by_node(struct rb_node *node, void *arg)
{
	struct pool4_table *table;
	table = rb_entry(node, struct pool4_table, tree_hook);
	destroy_table(table);
}

static void clear_trees(struct pool4 *pool)
{
	rbtree_clear(&pool->tree_mark.tcp, destroy_table_by_node, NULL);
	rbtree_clear(&pool->tree_mark.udp, destroy_table_by_node, NULL);
	rbtree_clear(&pool->tree_mark.icmp, destroy_table_by_node, NULL);
	rbtree_clear(&pool->tree_addr.tcp, destroy_table_by_node, NULL);
	rbtree_clear(&pool->tree_addr.udp, destroy_table_by_node, NULL);
	rbtree_clear(&pool->tree_addr.icmp, destroy_table_by_node, NULL);
}

static void release(struct kref *refcounter)
{
	struct pool4 *pool;
	pool = container_of(refcounter, struct pool4, refcounter);
	clear_trees(pool);
	wkfree(struct pool4, pool);
}

void pool4db_put(struct pool4 *pool)
{
	kref_put(&pool->refcounter, release);
}

static int compare_range(struct pool4_range *r1, struct pool4_range *r2)
{
	int gap;

	gap = ipv4_addr_cmp(&r1->addr, &r2->addr);
	if (gap)
		return gap;

	/*
	 * Reminder: "+/- 1" converts the number into an int.
	 * These are not __u16 comparisons.
	 */
	if (r1->ports.max < r2->ports.min - 1)
		return -1;
	if (r1->ports.min > r2->ports.max + 1)
		return 1;
	return 0;
}

static void pool4_range_fuse(struct pool4_range *r1, struct pool4_range *r2)
{
	return port_range_fuse(&r1->ports, &r2->ports);
}

static void fix_collisions(struct pool4_table *table, struct pool4_range *entry)
{
	struct pool4_range *last = last_table_entry(table);

	while (entry != last && pool4_range_touches(entry, entry + 1)) {
		table->taddr_count -= port_range_count(&entry->ports);
		table->taddr_count -= port_range_count(&(entry + 1)->ports);
		pool4_range_fuse(entry, entry + 1);
		table->taddr_count += port_range_count(&entry->ports);

		last--;
		memmove(entry + 1, entry + 2,
				(last - entry) * sizeof(struct pool4_range));

		table->sample_count--;
	}
}

/**
 * IMPORTANT NOTE: @table should not be dereferenced after this!
 *
 * Will enlarge @table's entry array and place @new before @entry.
 * (@entry must belong to @table, @new must not.)
 */
static int slip_in(struct rb_root *tree, struct pool4_table *table,
		struct pool4_range *entry, struct pool4_range *new)
{
	unsigned int entry_offset;
	size_t new_size;
	struct rb_node tmp;
	struct pool4_table *new_table;
	struct pool4_range *last;

	entry_offset = entry - first_table_entry(table);
	new_size = sizeof(struct pool4_table)
			+ (table->sample_count + 1)
			* sizeof(struct pool4_range);

	rb_replace_node(&table->tree_hook, &tmp, tree);
	new_table = krealloc(table, new_size, GFP_ATOMIC);
	if (!new_table) {
		rb_replace_node(&tmp, &table->tree_hook, tree);
		return -ENOMEM;
	}
	rb_replace_node(&tmp, &new_table->tree_hook, tree);

	entry = first_table_entry(new_table) + entry_offset;
	last = last_table_entry(new_table);
	memmove(entry + 1, entry,
			/*
			 * "+ 1" is before "- entry" to prevent negatives.
			 * I'm not actually sure if negatives are a problem
			 * when it comes to pointers, but whatever.
			 */
			(last + 1 - entry) * sizeof(struct pool4_range));

	*entry = *new;
	new_table->taddr_count += port_range_count(&new->ports);
	new_table->sample_count++;
	return 0;
}

static int pool4_add_range(struct rb_root *tree, struct pool4_table *table,
		struct pool4_range *new)
{
	struct pool4_range *entry;
	int comparison;

	/* Reminder: @table cannot be empty when this function kicks in. */
	foreach_table_range(entry, table) {
		comparison = compare_range(entry, new);
		if (comparison == 0) {
			pool4_range_fuse(entry, new);
			fix_collisions(table, entry);
			return 0;
		}
		if (comparison > 0)
			break; /* Going to slip @new right into this pos. */
	} /* Otherwise place it at the end of the array. */

	return slip_in(tree, table, entry, new);
}

static int add_to_mark_tree(struct pool4 *pool, const __u32 mark,
		l4_protocol proto, struct pool4_range *new)
{
	struct pool4_table *table;
	struct pool4_table *collision;
	struct rb_root *tree;

	tree = get_tree(&pool->tree_mark, proto);
	if (!tree)
		return -EINVAL;

	table = find_by_mark(tree, mark);
	if (table)
		return pool4_add_range(tree, table, new);

	table = create_table(new);
	if (!table)
		return -ENOMEM;
	table->mark = mark;

	collision = rbtree_add(table, mark, tree, cmp_mark, struct pool4_table,
			tree_hook);
	/* The spinlock is held, so this is critical. */
	if (WARN(collision, "Table wasn't and then was in the tree.")) {
		destroy_table(table);
		return -EINVAL;
	}

	return 0;
}

static int add_to_addr_tree(struct pool4 *pool, l4_protocol proto,
		struct pool4_range *new)
{
	struct rb_root *tree;
	struct pool4_table *table;
	struct pool4_table *collision;

	tree = get_tree(&pool->tree_addr, proto);
	if (!tree)
		return -EINVAL;

	table = find_by_addr(tree, &new->addr);
	if (table)
		return pool4_add_range(tree, table, new);

	table = create_table(new);
	if (!table)
		return -ENOMEM;
	table->addr = new->addr;

	collision = rbtree_add(table, &table->addr, tree, cmp_addr,
			struct pool4_table, tree_hook);
	/* The spinlock is held, so this is critical. */
	if (WARN(collision, "Table wasn't and then was in the tree.")) {
		destroy_table(table);
		return -EINVAL;
	}

	return 0;
}

int pool4db_add(struct pool4 *pool, const __u32 mark, l4_protocol proto,
		struct ipv4_range *range)
{
	struct pool4_range addend = { .ports = range->ports };
	u64 tmp;
	int error;

	if (addend.ports.min > addend.ports.max)
		swap(addend.ports.min, addend.ports.max);
	if ((proto == L4PROTO_TCP || proto == L4PROTO_UDP)
			&& addend.ports.min == 0)
		addend.ports.min = 1;

	/* log_debug("Adding range:%pI4/%u %u-%u",
			&range->prefix.address, range->prefix.len,
			range->ports.min, range->ports.max); */

	foreach_addr4(addend.addr, tmp, &range->prefix) {
		spin_lock_bh(&pool->lock);
		error = add_to_mark_tree(pool, mark, proto, &addend);
		if (!error)
			error = add_to_addr_tree(pool, proto, &addend);
		spin_unlock_bh(&pool->lock);
		if (error)
			return error;
	}

	return 0;
}

int pool4db_add_usr(struct pool4 *pool, struct pool4_entry_usr *entry)
{
	return pool4db_add(pool, entry->mark, entry->proto, &entry->range);
}

int pool4db_add_str(struct pool4 *pool, char *prefix_strs[], int prefix_count)
{
	struct ipv4_range range;
	unsigned int i;
	int error;

	/*
	 * We're not using DEFAULT_POOL4_* here because those are defaults for
	 * empty pool4 (otherwise it looks confusing from userspace).
	 */
	range.ports.min = 0;
	range.ports.max = 65535;

	for (i = 0; i < prefix_count; i++) {
		error = prefix4_parse(prefix_strs[i], &range.prefix);
		if (error)
			return error;

		error = pool4db_add(pool, 0, L4PROTO_TCP, &range);
		if (error)
			return error;
		error = pool4db_add(pool, 0, L4PROTO_UDP, &range);
		if (error)
			return error;
		error = pool4db_add(pool, 0, L4PROTO_ICMP, &range);
		if (error)
			return error;
	}

	return 0;
}

static int remove_range(struct rb_root *tree, struct pool4_table *table,
		struct ipv4_range *rm)
{
	struct pool4_range *entry;
	struct port_range *ports;
	struct pool4_range tmp;
	/*
	 * This is not unsigned because there's a i-- below that can happen
	 * during i = 0.
	 */
	int i;
	int error = 0;

	/* log_debug("  removing range %pI4/%u %u-%u",
			&rm->prefix.address, rm->prefix.len,
			rm->ports.min, rm->ports.max); */

	/*
	 * Note: The entries are sorted so this could be a binary search, but I
	 * don't want to risk getting it wrong or complicate the code further.
	 * This is a very rare operation anyway.
	 */
	for (i = 0; i < table->sample_count; i++) {
		entry = first_table_entry(table) + i;

		if (!prefix4_contains(&rm->prefix, &entry->addr))
			continue;

		ports = &entry->ports;

		if (rm->ports.min <= ports->min && ports->max <= rm->ports.max) {
			/* log_debug("    rm fully contains %pI4 %u-%u.",
					&entry->addr, ports->min, ports->max);*/
			table->taddr_count -= port_range_count(ports);
			memmove(entry, entry + 1, sizeof(struct pool4_range)
					* (table->sample_count - i - 1));
			table->sample_count--;
			i--;
			continue;
		}
		if (ports->min < rm->ports.min && rm->ports.max < ports->max) {
			/* log_debug("    rm is inside %pI4 %u-%u.",
					&entry->addr, ports->min, ports->max);*/
			/* Punch a hole in ports. */
			table->taddr_count -= port_range_count(&rm->ports);
			tmp.addr = entry->addr;
			tmp.ports.min = rm->ports.max + 1;
			tmp.ports.max = ports->max;
			ports->max = rm->ports.min - 1;
			error = slip_in(tree, table, entry + 1, &tmp);
			if (error)
				break;
			continue;
		}

		if (rm->ports.max < ports->min || rm->ports.min > ports->max) {
			/* log_debug("    rm has nothing to do with %pI4 %u-%u.",
					&entry->addr, ports->min, ports->max);*/
			continue;
		}

		if (ports->min < rm->ports.min) {
			/* log_debug("    rm touches %pI4 %u-%u's right.",
					&entry->addr, ports->min, ports->max);*/
			table->taddr_count -= ports->max - rm->ports.min + 1;
			ports->max = rm->ports.min - 1;
			continue;
		}
		if (rm->ports.max < ports->max) {
			/* log_debug("    rm touches %pI4 %u-%u's left.",
					&entry->addr, ports->min, ports->max);*/
			table->taddr_count -= rm->ports.max - ports->min + 1;
			ports->min = rm->ports.max + 1;
			continue;
		}
	}

	if (table->sample_count == 0) {
		rb_erase(&table->tree_hook, tree);
		wkfree(struct pool4_table, table);
	}

	return error;
}

static int rm_from_mark_tree(struct pool4 *pool, const __u32 mark,
		l4_protocol proto, struct ipv4_range *range)
{
	struct rb_root *tree;
	struct pool4_table *table;

	tree = get_tree(&pool->tree_mark, proto);
	if (!tree)
		return -EINVAL;

	table = find_by_mark(tree, mark);
	if (!table)
		return 0;

	return remove_range(tree, table, range);
}

static int rm_from_addr_tree(struct pool4 *pool, l4_protocol proto,
		struct ipv4_range *range)
{
	struct rb_root *tree;
	struct pool4_table *table;
	struct rb_node *prev;
	struct rb_node *next;
	int error;

	tree = get_tree(&pool->tree_addr, proto);
	if (!tree)
		return -EINVAL;

	table = find_by_prefix(tree, &range->prefix);
	if (!table)
		return 0;

	prev = rb_prev(&table->tree_hook);
	next = rb_next(&table->tree_hook);

	error = remove_range(tree, table, range);
	if (error)
		return error;

	while (prev) {
		table = rb_entry(prev, struct pool4_table, tree_hook);
		if (!prefix4_contains(&range->prefix, &table->addr))
			break;
		prev = rb_prev(&table->tree_hook);
		error = remove_range(tree, table, range);
		if (error)
			return error;
	}

	while (next) {
		table = rb_entry(next, struct pool4_table, tree_hook);
		if (!prefix4_contains(&range->prefix, &table->addr))
			break;
		next = rb_next(&table->tree_hook);
		error = remove_range(tree, table, range);
		if (error)
			return error;
	}

	return 0;
}

int pool4db_rm(struct pool4 *pool, const __u32 mark, l4_protocol proto,
		struct ipv4_range *range)
{
	int error;

	if (range->ports.min > range->ports.max)
		swap(range->ports.min, range->ports.max);

	spin_lock_bh(&pool->lock);

	error = rm_from_mark_tree(pool, mark, proto, range);
	if (!error)
		error = rm_from_addr_tree(pool, proto, range);

	spin_unlock_bh(&pool->lock);
	return error;
}

int pool4db_rm_usr(struct pool4 *pool, struct pool4_entry_usr *entry)
{
	return pool4db_rm(pool, entry->mark, entry->proto, &entry->range);
}

void pool4db_flush(struct pool4 *pool)
{
	spin_lock_bh(&pool->lock);
	clear_trees(pool);
	spin_unlock_bh(&pool->lock);
}

static struct pool4_range *find_port_range(struct pool4_table *entry, __u16 port)
{
	struct pool4_range *first = first_table_entry(entry);
	struct pool4_range *middle;
	struct pool4_range *last = first + entry->sample_count - 1;

	do {
		middle = first + ((last - first) / 2);
		if (port < middle->ports.min) {
			last = middle - 1;
			continue;
		}
		if (port > middle->ports.max) {
			first = middle + 1;
			continue;
		}
		return middle;
	} while (first <= last);

	return NULL;
}

/**
 * BTW: The reason why this doesn't care about mark is because it's an
 * inherently 4-to-6 function (it doesn't make sense otherwise).
 * Mark is only used in the 6-to-4 direction.
 */
bool pool4db_contains(struct pool4 *pool, struct net *ns, l4_protocol proto,
		struct ipv4_transport_addr *addr)
{
	struct pool4_table *table;
	bool found = false;

	spin_lock_bh(&pool->lock);

	if (is_empty(pool)) {
		spin_unlock_bh(&pool->lock);
		return pool4empty_contains(ns, addr);
	}

	table = find_by_addr(get_tree(&pool->tree_addr, proto), &addr->l3);
	if (table)
		found = find_port_range(table, addr->l4) != NULL;

	spin_unlock_bh(&pool->lock);
	return found;
}

static int find_offset(struct pool4_table *table, struct pool4_range *offset,
		struct pool4_range **result)
{
	struct pool4_range *entry;

	foreach_table_range(entry, table) {
		if (pool4_range_equals(offset, entry)) {
			*result = entry;
			return 0;
		}
	}

	return -ESRCH;
}

/**
 * As a contract, this function will return:
 *
 * - As usual, negative integers as errors.
 * - If cb decides to stop iteration early, it will do so by returning nonzero
 *   (preferably positive), and that will in turn become the result of this
 *   function.
 * - 0 if iteration ended with no interruptions.
 */
int pool4db_foreach_sample(struct pool4 *pool, l4_protocol proto,
		int (*cb)(struct pool4_sample *, void *), void *arg,
		struct pool4_sample *offset)
{
	struct rb_root *tree;
	struct rb_node *node;
	struct pool4_table *table;
	struct pool4_range *entry;
	struct pool4_sample sample = { .proto = proto };
	int error = 0;

	spin_lock_bh(&pool->lock);

	tree = get_tree(&pool->tree_mark, proto);
	if (!tree) {
		error = -EINVAL;
		goto end;
	}

	if (offset) {
		table = find_by_mark(tree, offset->mark);
		if (!table)
			goto eagain;
		error = find_offset(table, &offset->range, &entry);
		if (error)
			goto eagain;
		sample.mark = table->mark;
		goto offset_start;
	}

	node = rb_first(tree);
	while (node) {
		table = rb_entry(node, struct pool4_table, tree_hook);
		sample.mark = table->mark;

		foreach_table_range(entry, table) {
			sample.range = *entry;
			error = cb(&sample, arg);
			if (error)
				goto end;
offset_start:; /* <- The semicolon prevents a compiler error. */
		}

		node = rb_next(&table->tree_hook);
	}

end:
	spin_unlock_bh(&pool->lock);
	return error;

eagain:
	spin_unlock_bh(&pool->lock);
	log_err("Oops. Pool4 changed while I was iterating so I lost track of where I was. Try again.");
	return -EAGAIN;
}

static void print_tree(struct rb_root *tree, bool mark)
{
	struct rb_node *node = rb_first(tree);
	struct pool4_table *table;
	struct pool4_range *entry;

	if (!node) {
		log_info("	Empty.");
		return;
	}

	while (node) {
		table = rb_entry(node, struct pool4_table, tree_hook);
		if (mark)
			log_info("\tMark:%u", table->mark);
		else
			log_info("\tAddress:%pI4", &table->addr);
		log_info("\tSample count:%u", table->sample_count);
		log_info("\tTaddr count:%u", table->taddr_count);

		foreach_table_range(entry, table) {
			log_info("\t\t%pI4 %u-%u", &entry->addr,
					entry->ports.min, entry->ports.max);
		}

		node = rb_next(node);
	}
}

void pool4db_print(struct pool4 *pool)
{
	log_info("-------- Mark trees --------");
	log_info("TCP:");
	print_tree(&pool->tree_mark.tcp, true);
	log_info("UDP:");
	print_tree(&pool->tree_mark.udp, true);
	log_info("ICMP:");
	print_tree(&pool->tree_mark.icmp, true);

	log_info("-------- Addr trees --------");
	log_info("TCP:");
	print_tree(&pool->tree_addr.tcp, false);
	log_info("UDP:");
	print_tree(&pool->tree_addr.udp, false);
	log_info("ICMP:");
	print_tree(&pool->tree_addr.icmp, false);
}

static struct mask_domain *find_empty(struct route4_args *args,
		unsigned int offset)
{
	struct mask_domain *masks;
	struct pool4_range *range;

	masks = __wkmalloc("mask_domain",
			sizeof(struct mask_domain) * sizeof(struct pool4_range),
			GFP_ATOMIC);
	if (!masks)
		return NULL;

	range = (struct pool4_range *)(masks + 1);
	if (pool4empty_find(args, range))
		return NULL;

	masks->taddr_count = port_range_count(&range->ports);
	masks->taddr_counter = 0;
	masks->range_count = 1;
	masks->current_range = range;
	masks->current_port = range->ports.min + offset % masks->taddr_count;
	masks->dynamic = true;
	return masks;
}

struct mask_domain *mask_domain_find(struct pool4 *pool, struct tuple *tuple6,
		__u8 f_args, struct route4_args *route_args)
{
	struct pool4_table *table;
	struct pool4_range *entry;
	struct mask_domain *masks;
	unsigned int offset;

	if (rfc6056_f(tuple6, f_args, &offset))
		return NULL;

	spin_lock_bh(&pool->lock);

	if (is_empty(pool)) {
		spin_unlock_bh(&pool->lock);
		return find_empty(route_args, offset);
	}

	table = find_by_mark(get_tree(&pool->tree_mark, tuple6->l4_proto),
			route_args->mark);
	if (!table)
		goto fail;

	masks = __wkmalloc("mask_domain", sizeof(struct mask_domain)
			+ table->sample_count * sizeof(struct pool4_range),
			GFP_ATOMIC);
	if (!masks)
		goto fail;

	memcpy(masks + 1, table + 1,
			table->sample_count * sizeof(struct pool4_range));
	masks->taddr_count = table->taddr_count;
	masks->range_count = table->sample_count;

	spin_unlock_bh(&pool->lock);

	masks->taddr_counter = 0;
	masks->dynamic = false;
	offset %= masks->taddr_count;

	foreach_domain_range(entry, masks) {
		if (offset <= port_range_count(&entry->ports)) {
			masks->current_range = entry;
			masks->current_port = entry->ports.min + offset - 1;
			return masks; /* Happy path */
		}
		offset -= port_range_count(&entry->ports);
	}

	WARN(true, "Bug: pool4 entry counter does not match entry count.");
	__wkfree("mask_domain", masks);
	return NULL;

fail:
	spin_unlock_bh(&pool->lock);
	return NULL;
}

void mask_domain_put(struct mask_domain *masks)
{
	__wkfree("mask_domain", masks);
}

int mask_domain_next(struct mask_domain *masks,
		struct ipv4_transport_addr *addr,
		bool *consecutive)
{
	masks->taddr_counter++;
	if (masks->taddr_counter > masks->taddr_count)
		return -ENOENT;

	masks->current_port++;
	if (masks->current_port > masks->current_range->ports.max) {
		*consecutive = false;
		masks->current_range++;
		if (masks->current_range > first_domain_entry(masks) + masks->range_count)
			masks->current_range = first_domain_entry(masks);
		masks->current_port = masks->current_range->ports.min;
	} else {
		*consecutive = (masks->taddr_counter != 1);
	}

	addr->l3 = masks->current_range->addr;
	addr->l4 = masks->current_port;
	return 0;
}

bool mask_domain_matches(struct mask_domain *masks,
		struct ipv4_transport_addr *addr)
{
	struct pool4_range *entry;

	foreach_domain_range(entry, masks) {
		if (entry->addr.s_addr != addr->l3.s_addr)
			continue;
		if (port_range_contains(&entry->ports, addr->l4))
			return true;
	}

	return false;
}

bool mask_domain_is_dynamic(struct mask_domain *masks)
{
	return masks->dynamic;
}
