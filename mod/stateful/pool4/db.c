#include "nat64/mod/stateful/pool4/db.h"

#include <linux/hash.h>
#include <linux/list.h>
#include <linux/slab.h>
#include "nat64/common/types.h"
#include "nat64/mod/common/rbtree.h"
#include "nat64/mod/common/wkmalloc.h"
#include "nat64/mod/stateful/pool4/empty.h"

/**
 * An address within the pool, along with its ports.
 */
struct pool4_entry {
	struct in_addr addr;
	/** This is a sorted array. */
	struct port_range *ports;
	unsigned int ports_len;
	unsigned int taddr_count;

	/* Chains this in the table's entry list. */
	struct pool4_entry *next;
	/** Used in the address tree. */
	struct rb_node addr_tree_hook;
};

struct pool4_table {
	__u32 mark;
	/**
	 * This is a circular linked list.
	 * Why is it not a typical list_head? Because the first list_head is
	 * supposed to be a placeholder, "root" kind of element.
	 * This is bad now because I need any node to be a natural starting
	 * point.
	 */
	struct pool4_entry first_entry;
	/* Must not be zero! */
	unsigned int taddr_count;

	/** Used in the mark tree. */
	struct rb_node mark_tree_hook;
};

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

static struct rb_root *get_tree_u8(struct pool4_trees *trees, __u8 proto)
{
	switch (proto) {
	case IPPROTO_TCP:
		return &trees->tcp;
	case IPPROTO_UDP:
		return &trees->udp;
	case IPPROTO_ICMP:
		return &trees->icmp;
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
	return rbtree_find(mark, tree, cmp_mark, struct pool4_table,
			mark_tree_hook);
}

static int cmp_addr(struct pool4_entry *entry, struct in_addr *addr)
{
	return ipv4_addr_cmp(&entry->addr, addr);
}

static struct pool4_entry *find_by_addr(struct rb_root *tree,
		struct in_addr *addr)
{
	if (unlikely(!tree))
		return NULL;
	return rbtree_find(addr, tree, cmp_addr, struct pool4_entry,
			addr_tree_hook);
}

static int cmp_prefix(struct pool4_entry *entry, struct ipv4_prefix *prefix)
{
	if (prefix4_contains(prefix, &entry->addr))
		return 0;
	return ipv4_addr_cmp(&entry->addr, &prefix->address);
}

static struct pool4_entry *find_by_prefix(struct rb_root *tree,
		struct ipv4_prefix *prefix)
{
	return rbtree_find(prefix, tree, cmp_prefix, struct pool4_entry,
			addr_tree_hook);
}

static bool is_empty(struct pool4 *pool)
{
	return RB_EMPTY_ROOT(&pool->tree_mark.tcp)
			&& RB_EMPTY_ROOT(&pool->tree_mark.udp)
			&& RB_EMPTY_ROOT(&pool->tree_mark.icmp);
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

static void destroy_table(struct rb_node *node, void *arg)
{
	struct pool4_table *table;
	struct pool4_entry *entry;
	struct pool4_entry *next;

	table = rb_entry(node, struct pool4_table, mark_tree_hook);

	next = table->first_entry.next;
	for (entry = next; entry != &table->first_entry; entry = next) {
		next = entry->next;
		wkfree(struct port_range, entry->ports);
		wkfree(struct pool4_entry, entry);
	}

	wkfree(struct port_range, table->first_entry.ports);
	wkfree(struct pool4_table, table);
}

static void release(struct kref *refcounter)
{
	struct pool4 *pool;
	pool = container_of(refcounter, struct pool4, refcounter);

	rbtree_clear(&pool->tree_mark.tcp, destroy_table, NULL);
	rbtree_clear(&pool->tree_mark.udp, destroy_table, NULL);
	rbtree_clear(&pool->tree_mark.icmp, destroy_table, NULL);

	wkfree(struct pool4, pool);
}

void pool4db_put(struct pool4 *pool)
{
	kref_put(&pool->refcounter, release);
}

static struct pool4_entry *create_entry(struct in_addr *addr,
		struct port_range *ports)
{
	struct pool4_entry *entry;

	entry = wkmalloc(struct pool4_entry, GFP_ATOMIC);
	if (!entry)
		return NULL;
	entry->ports = wkmalloc(struct port_range, GFP_ATOMIC);
	if (!entry->ports) {
		wkfree(struct pool4_entry, entry);
		return NULL;
	}

	memcpy(&entry->addr, addr, sizeof(*addr));
	memcpy(entry->ports, ports, sizeof(*ports));
	entry->ports_len = 1;
	entry->taddr_count = port_range_count(ports);

	return entry;
}

static int slip_in(struct pool4_entry *entry, struct port_range *ports,
		unsigned int i)
{
	size_t new_size = sizeof(struct port_range) * (entry->ports_len + 1);

	entry->ports = krealloc(entry->ports, new_size, GFP_ATOMIC);
	if (!entry->ports)
		return -ENOMEM;

	memmove(&entry->ports[i + 1], &entry->ports[i],
			sizeof(struct port_range) * (entry->ports_len - i));
	entry->ports_len++;
	entry->taddr_count += port_range_count(ports);
	memcpy(&entry->ports[i], ports, sizeof(struct port_range));

	return 0;
}

static void mix(struct port_range *a, struct port_range *b)
{
	a->min = min(a->min, b->min);
	a->max = max(a->max, b->max);
}

static int merge(struct pool4_entry *entry, struct port_range *new,
		unsigned int i)
{
	struct port_range *ports = entry->ports;
	unsigned int ports_len = entry->ports_len;
	unsigned int j;

	entry->taddr_count -= port_range_count(&ports[i]);
	mix(&ports[i], new);

	j = i + 1;
	while (j < ports_len && port_range_touches(&ports[i], &ports[j])) {
		entry->taddr_count -= port_range_count(&ports[j]);
		mix(&ports[i], &ports[j]);
		j++;
	}
	entry->taddr_count += port_range_count(&ports[i]);

	if (j != i + 1) {
		memmove(&ports[i + 1], &ports[j],
				sizeof(struct port_range) * (ports_len - j));
		entry->ports_len = i + 1 + (ports_len - j);
	}

	return 0;
}

static int add_ports(struct pool4_entry *entry, struct port_range *ports)
{
	unsigned int i;

	for (i = 0; i < entry->ports_len; i++) {
		if (ports->max < entry->ports[i].min)
			return slip_in(entry, ports, i);
		if (port_range_touches(ports, &entry->ports[i]))
			return merge(entry, ports, i);
	}

	return slip_in(entry, ports, i);
}

static int recompute_taddr_counts(struct pool4_table *table)
{
	struct pool4_entry *entry;

	table->taddr_count = 0;
	entry = &table->first_entry;
	do {
		table->taddr_count += entry->taddr_count;
		entry = entry->next;
	} while (entry != &table->first_entry);

	return 0;
}

static int add_taddrs(struct pool4_table *table, struct in_addr *addr,
		struct port_range *ports)
{
	struct pool4_entry *entry;
	struct pool4_entry *new;
	int error;

	entry = &table->first_entry;
	do {
		if (entry->addr.s_addr == addr->s_addr) {
			error = add_ports(entry, ports);
			return error ? : recompute_taddr_counts(table);
		}
		entry = entry->next;
	} while (entry != &table->first_entry);

	new = create_entry(addr, ports);
	if (!new)
		return -ENOMEM;

	/*
	 * Place it at the end of the list. We don't actually HAVE to do this;
	 * it could be anywhere (eg. first_entry->next) and this would be still
	 * perfectly compliant, but this way looks friendlier from userspace
	 * and specially unit tests.
	 */
	entry = table->first_entry.next;
	while (entry->next != &table->first_entry)
		entry = entry->next;

	entry->next = new;
	new->next = &table->first_entry;
	table->taddr_count += new->taddr_count;
	return 0;
}

static int add_to_mark_tree(struct pool4 *pool, const __u32 mark,
		l4_protocol proto, struct in_addr *addr,
		struct port_range *ports)
{
	struct pool4_table *table;
	struct pool4_table *collision;
	struct rb_root *tree;

	tree = get_tree(&pool->tree_mark, proto);
	if (!tree)
		return -EINVAL;

	table = find_by_mark(tree, mark);
	if (table)
		return add_taddrs(table, addr, ports);

	table = wkmalloc(struct pool4_table, GFP_ATOMIC);
	if (!table)
		return -ENOMEM;
	table->first_entry.ports = wkmalloc(struct port_range, GFP_ATOMIC);
	if (!table->first_entry.ports) {
		wkfree(struct pool4_table, table);
		return -ENOMEM;
	}

	table->mark = mark;
	table->taddr_count = port_range_count(ports);

	memcpy(&table->first_entry.addr, addr, sizeof(*addr));
	memcpy(table->first_entry.ports, ports, sizeof(*ports));
	table->first_entry.ports_len = 1;
	table->first_entry.taddr_count = table->taddr_count;
	table->first_entry.next = &table->first_entry;

	collision = rbtree_add(table, mark, tree, cmp_mark, struct pool4_table,
			mark_tree_hook);
	if (WARN(collision, "Table wasn't and then was in the tree.")) {
		destroy_table(&table->mark_tree_hook, NULL);
		return -EINVAL;
	}

	return 0;
}

static int add_to_addr_tree(struct pool4 *pool, l4_protocol proto,
		struct in_addr *addr, struct port_range *ports)
{
	struct rb_root *tree;
	struct pool4_entry *entry;
	struct pool4_entry *collision;

	tree = get_tree(&pool->tree_addr, proto);
	if (!tree)
		return -EINVAL;

	entry = find_by_addr(tree, addr);
	if (entry)
		return add_ports(entry, ports);

	entry = wkmalloc(struct pool4_entry, GFP_ATOMIC);
	if (!entry)
		return -ENOMEM;
	entry->ports = wkmalloc(struct port_range, GFP_ATOMIC);
	if (!entry->ports) {
		wkfree(struct pool4_entry, entry);
		return -ENOMEM;
	}

	memcpy(&entry->addr, addr, sizeof(*addr));
	memcpy(entry->ports, ports, sizeof(*ports));
	entry->ports_len = 1;
	entry->taddr_count = port_range_count(ports);
	entry->next = entry;

	collision = rbtree_add(entry, addr, tree, cmp_addr, struct pool4_entry,
			addr_tree_hook);
	if (WARN(collision, "Entry wasn't and then was in the tree.")) {
		wkfree(struct port_range, entry->ports);
		wkfree(struct pool4_entry, entry);
		return -EINVAL;
	}

	return 0;
}

static int add_addr(struct pool4 *pool, const __u32 mark, l4_protocol proto,
		struct in_addr *addr, struct port_range *ports)
{
	int error;

	error = add_to_mark_tree(pool, mark, proto, addr, ports);
	if (error)
		return error;

	return add_to_addr_tree(pool, proto, addr, ports);
}

int pool4db_add(struct pool4 *pool, const __u32 mark, l4_protocol proto,
		struct ipv4_range *range)
{
	struct port_range *ports = &range->ports;
	struct in_addr addr;
	u64 tmp;
	int error;

	if (ports->min > ports->max)
		swap(ports->min, ports->max);
	if ((proto == L4PROTO_TCP || proto == L4PROTO_UDP) && ports->min == 0)
		ports->min = 1;

	foreach_addr4(addr, tmp, &range->prefix)
	{
		spin_lock_bh(&pool->lock);
		error = add_addr(pool, mark, proto, &addr, ports);
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

static int __rm_taddrs(struct pool4_entry *entry, struct ipv4_range *range)
{
	struct port_range *rm = &range->ports;
	struct port_range *ports;
	struct port_range tmp;
	/*
	 * This is not unsigned because there's a i-- below that can happen
	 * during i = 0.
	 */
	int i;
	int error;

	if (!prefix4_contains(&range->prefix, &entry->addr))
		return 0;

	for (i = 0; i < entry->ports_len; i++) {
		ports = &entry->ports[i];

		if (rm->min <= ports->min && ports->max <= rm->max) {
			entry->taddr_count -= port_range_count(ports);
			memmove(ports, ports + 1, sizeof(struct port_range)
					* (entry->ports_len - i));
			entry->ports_len--;
			i--;
			continue;
		}
		if (ports->min < rm->min && rm->max < ports->max) {
			/* Punch a hole in ports. */
			entry->taddr_count -= ports[i].max - rm->min + 1;
			tmp.min = rm->max + 1;
			tmp.max = ports[i].max;
			ports[i].max = rm->min - 1;
			error = slip_in(entry, &tmp, i + 1);
			if (error)
				return error;
			continue;
		}

		if (rm->max < ports->min || rm->min > ports->max)
			continue;

		if (ports->min < rm->min) {
			entry->taddr_count -= ports->max - rm->min + 1;
			ports->max = rm->min - 1;
			continue;
		}
		if (rm->max < ports->max) {
			entry->taddr_count -= rm->max - ports->min + 1;
			ports->min = rm->max + 1;
			continue;
		}
	}

	return 0;
}

/*
 * Note: This also takes care of updating the entries' taddr_counts.
 */
static int remove_taddrs(struct pool4_table *table, struct ipv4_range *range)
{
	struct pool4_entry *entry;
	int error;

	entry = &table->first_entry;
	do {
		error = __rm_taddrs(entry, range);
		if (error)
			return error;
		entry = entry->next;
	} while (entry != &table->first_entry);

	return 0;
}

/*
 * Note: This also takes care of updating the tables' taddr_counts.
 */
static int prune_empty_nodes(struct rb_root *tree, struct pool4_table *table)
{
	struct pool4_entry *entry;
	struct pool4_entry *prev;
	struct pool4_entry *next;

	entry = &table->first_entry;
	while (entry->taddr_count == 0) {
		if (entry->next == entry) {
			rb_erase(&table->mark_tree_hook, tree);
			wkfree(struct port_range, entry->ports);
			wkfree(struct pool4_table, table);
			return 0;
		}

		wkfree(struct port_range, entry->ports);
		next = entry->next;
		memcpy(entry, next, sizeof(*entry));
		wkfree(struct pool4_entry, next);
	}
	table->taddr_count = table->first_entry.taddr_count;

	prev = entry;
	entry = entry->next;
	for (; entry != &table->first_entry; entry = entry->next) {
		if (entry->taddr_count == 0) {
			prev->next = entry->next;
			wkfree(struct port_range, entry->ports);
			wkfree(struct pool4_entry, entry);
			entry = prev;
		} else {
			table->taddr_count += entry->taddr_count;
			prev = entry;
		}
	}

	return 0;
}

static int rm_from_mark_tree(struct pool4 *pool, const __u32 mark,
		l4_protocol proto, struct ipv4_range *range)
{
	struct rb_root *tree;
	struct pool4_table *table;
	int error;

	tree = get_tree(&pool->tree_mark, proto);
	if (!tree)
		return -EINVAL;

	table = find_by_mark(tree, mark);
	if (!table)
		return 0;

	error = remove_taddrs(table, range);
	if (error)
		return error;

	return prune_empty_nodes(tree, table);
}

static int __rm(struct rb_root *tree, struct pool4_entry *entry,
		struct ipv4_range *range)
{
	int error;

	error = __rm_taddrs(entry, range);
	if (error)
		return error;

	if (entry->taddr_count == 0) {
		rb_erase(&entry->addr_tree_hook, tree);
		wkfree(struct port_range, entry->ports);
		wkfree(struct pool4_entry, entry);
	}

	return 0;
}

static int rm_from_addr_tree(struct pool4 *pool, l4_protocol proto,
		struct ipv4_range *range)
{
	struct rb_root *tree;
	struct pool4_entry *entry;
	struct rb_node *prev;
	struct rb_node *next;
	int error;

	tree = get_tree(&pool->tree_addr, proto);
	if (!tree)
		return -EINVAL;

	entry = find_by_prefix(tree, &range->prefix);
	if (!entry)
		return 0;

	prev = rb_prev(&entry->addr_tree_hook);
	next = rb_next(&entry->addr_tree_hook);

	error = __rm(tree, entry, range);
	if (error)
		return error;

	while (prev) {
		entry = rb_entry(prev, struct pool4_entry, addr_tree_hook);
		if (!prefix4_contains(&range->prefix, &entry->addr))
			break;
		prev = rb_prev(&entry->addr_tree_hook);
		error = __rm(tree, entry, range);
		if (error)
			return error;
	}

	while (next) {
		entry = rb_entry(next, struct pool4_entry, addr_tree_hook);
		if (!prefix4_contains(&range->prefix, &entry->addr))
			break;
		next = rb_next(&entry->addr_tree_hook);
		error = __rm(tree, entry, range);
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

static void flush_mark_tree(struct rb_node *node, void *arg)
{
	struct pool4_table *table;
	struct pool4_entry *entry;
	struct pool4_entry *next;

	table = rb_entry(node, struct pool4_table, mark_tree_hook);

	entry = table->first_entry.next;
	for (; entry != &table->first_entry; entry = next) {
		next = entry->next;
		wkfree(struct port_range, entry->ports);
		wkfree(struct pool4_entry, entry);
	}

	wkfree(struct port_range, table->first_entry.ports);
	wkfree(struct pool4_table, table);
}

static void flush_addr_tree(struct rb_node *node, void *arg)
{
	struct pool4_entry *entry;
	entry = rb_entry(node, struct pool4_entry, addr_tree_hook);
	wkfree(struct port_range, entry->ports);
	wkfree(struct pool4_entry, entry);
}

void pool4db_flush(struct pool4 *pool)
{
	spin_lock_bh(&pool->lock);
	rbtree_clear(&pool->tree_mark.tcp, flush_mark_tree, NULL);
	rbtree_clear(&pool->tree_mark.udp, flush_mark_tree, NULL);
	rbtree_clear(&pool->tree_mark.icmp, flush_mark_tree, NULL);
	rbtree_clear(&pool->tree_addr.tcp, flush_addr_tree, NULL);
	rbtree_clear(&pool->tree_addr.udp, flush_addr_tree, NULL);
	rbtree_clear(&pool->tree_addr.icmp, flush_addr_tree, NULL);
	spin_unlock_bh(&pool->lock);
}

static struct port_range *find_port_range(struct pool4_entry *entry, __u16 port)
{
	struct port_range *first = entry->ports;
	struct port_range *middle;
	struct port_range *last = entry->ports + entry->ports_len - 1;

	do {
		middle = first + ((last - first) / 2);
		if (port < middle->min) {
			last = middle - 1;
			continue;
		}
		if (port > middle->max) {
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
	struct pool4_entry *entry;
	bool found = false;

	spin_lock_bh(&pool->lock);

	if (is_empty(pool)) {
		found = pool4empty_contains(ns, addr);
		goto end;
	}

	entry = find_by_addr(get_tree(&pool->tree_addr, proto), &addr->l3);
	if (!entry)
		goto end;

	found = find_port_range(entry, addr->l4) != NULL;
	/* Fall through. */

end:
	spin_unlock_bh(&pool->lock);
	return found;
}

static int find_offset(struct pool4_sample *offset, struct pool4_table *table,
		struct pool4_entry **result_entry, unsigned int *result_ports)
{
	struct pool4_entry *entry;
	unsigned int i;

	entry = &table->first_entry;
	do {
		if (addr4_equals(&offset->addr, &entry->addr)) {
			for (i = 0; i < entry->ports_len; i++) {
				if (port_range_equals(&offset->range,
						&entry->ports[i])) {
					*result_entry = entry;
					*result_ports = i + 1;
					return 0;
				}
			}
		}

		entry = entry->next;
	} while (entry != &table->first_entry);

	return -ESRCH;
}

int pool4db_foreach_sample(struct pool4 *pool, l4_protocol proto,
		int (*cb)(struct pool4_sample *, void *), void *arg,
		struct pool4_sample *offset)
{
	struct rb_root *tree;
	struct rb_node *node;
	struct pool4_table *table;
	struct pool4_entry *entry;
	struct pool4_sample sample;
	unsigned int ports;
	int error = 0;

	spin_lock_bh(&pool->lock);

	tree = get_tree(&pool->tree_mark, proto);
	if (!tree) {
		error = -EINVAL;
		goto end;
	}

	sample.proto = proto;

	if (offset) {
		table = find_by_mark(tree, offset->mark);
		if (!table) {
			log_err("Oops. Pool4 changed while I was iterating so I lost track of where I was. Try again.");
			error = -EAGAIN;
			goto end;
		}
		error = find_offset(offset, table, &entry, &ports);
		if (error)
			goto end;
		sample.mark = table->mark;
		sample.addr = entry->addr;
		goto offset_start;
	}

	node = rb_first(tree);
	while (node) {
		table = rb_entry(node, struct pool4_table, mark_tree_hook);
		entry = &table->first_entry;
		sample.mark = table->mark;
		do {
			sample.addr = entry->addr;
			ports = 0;
offset_start:
			for (; ports < entry->ports_len; ports++) {
				sample.range = entry->ports[ports];
				error = cb(&sample, arg);
				if (error)
					goto end;
			}

			entry = entry->next;
		} while (entry != &table->first_entry);

		node = rb_next(&table->mark_tree_hook);
	}

end:
	spin_unlock_bh(&pool->lock);
	return error;
}

static int foreach_taddr4(struct pool4_table *table,
		int (*cb)(struct ipv4_transport_addr *, void *), void *arg,
		unsigned int offset)
{
	struct pool4_entry *entry;
	struct port_range *range;
	struct ipv4_transport_addr addr;
	unsigned int i;
	int error;

	offset %= table->taddr_count;

	/* Find the `offset`th transport address. */
	entry = &table->first_entry;
	for (; offset >= entry->taddr_count; entry = entry->next)
		offset -= entry->taddr_count;
	for (range = entry->ports; offset >= port_range_count(range); range++)
		offset -= port_range_count(range);

	/* Iterate from there. */
	addr.l3.s_addr = entry->addr.s_addr;
	addr.l4 = range->min + offset;
	for (i = 0; i < table->taddr_count; i++) {
		error = cb(&addr, arg);
		if (error)
			return error;

		addr.l4++;
		if (addr.l4 > range->max) {
			range++;
			if (range >= entry->ports + entry->ports_len) {
				entry = entry->next;
				addr.l3 = entry->addr;
				range = entry->ports;
			}
			addr.l4 = range->min;
		}
	}

	return 0;
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
int pool4db_foreach_taddr4(struct pool4 *pool, struct net *ns,
		struct in_addr *daddr, __u8 tos, __u8 proto, __u32 mark,
		int (*cb)(struct ipv4_transport_addr *, void *), void *arg,
		unsigned int offset)
{
	struct pool4_table *table;
	int error;

	spin_lock_bh(&pool->lock);

	if (is_empty(pool)) {
		error = pool4empty_foreach_taddr4(ns, daddr, tos, proto, mark,
				cb, arg, offset);
		goto end;
	}

	table = find_by_mark(get_tree_u8(&pool->tree_mark, proto), mark);
	if (!table) {
		error = -ESRCH;
		goto end;
	}

	error = foreach_taddr4(table, cb, arg, offset);
	/* Fall through. */

end:
	spin_unlock_bh(&pool->lock);
	return error;
}

static void print_mark_tree(struct rb_root *tree)
{
	struct rb_node *node = rb_first(tree);
	struct pool4_table *table;
	struct pool4_entry *entry;
	unsigned int i;

	if (!node) {
		log_info("	Empty.");
		return;
	}

	while (node) {
		table = rb_entry(node, struct pool4_table, mark_tree_hook);
		log_info("\tMark:%u", table->mark);
		log_info("\tTaddr count:%u", table->taddr_count);
		entry = &table->first_entry;
		do {
			log_info("\t\tAddress:%pI4", &entry->addr);
			log_info("\t\tTaddr count:%u", entry->taddr_count);
			log_info("\t\tPorts len:%u", entry->ports_len);

			for (i = 0; i < entry->ports_len; i++) {
				log_info("\t\t\t%u-%u", entry->ports[i].min,
						entry->ports[i].max);
			}

			entry = entry->next;
		} while (entry != &table->first_entry);
		node = rb_next(node);
	}
}

static void print_addr_tree(struct rb_root *tree)
{
	struct rb_node *node = rb_first(tree);
	struct pool4_entry *first;
	struct pool4_entry *entry;
	unsigned int i;

	if (!node) {
		log_info("	Empty.");
		return;
	}

	while (node) {
		first = rb_entry(node, struct pool4_entry, addr_tree_hook);
		entry = first;
		do {
			log_info("\tAddress:%pI4", &entry->addr);
			log_info("\tTaddr count:%u", entry->taddr_count);
			log_info("\tPorts len:%u", entry->ports_len);

			for (i = 0; i < entry->ports_len; i++) {
				log_info("\t\t%u-%u", entry->ports[i].min,
						entry->ports[i].max);
			}

			entry = entry->next;
		} while (entry != first);
		log_info("\t-------------------------");
		node = rb_next(node);
	}
}

void pool4db_print(struct pool4 *pool)
{
	log_info("-------- Mark trees --------");
	log_info("TCP:");
	print_mark_tree(&pool->tree_mark.tcp);
	log_info("UDP:");
	print_mark_tree(&pool->tree_mark.udp);
	log_info("ICMP:");
	print_mark_tree(&pool->tree_mark.icmp);

	log_info("-------- Addr trees --------");
	log_info("TCP:");
	print_addr_tree(&pool->tree_addr.tcp);
	log_info("UDP:");
	print_addr_tree(&pool->tree_addr.udp);
	log_info("ICMP:");
	print_addr_tree(&pool->tree_addr.icmp);
}
