#include "mod/common/db/pool4-v2/block.h"

#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/hashtable.h>

#include "mod/common/address.h"
#include "mod/common/log.h"

struct block {
	struct p4block blk;

	struct in6_addr assigned_addr6; /* Currently assigned client */
	u64 last_used_time;

	bool is_assigned;
	union {
		/* is_assigned false */
		struct list_head list; /* For @idle_blocks */
		/* is_assigned true */
		struct hlist_node htable; /* For @assignments */
	} hook;
};

#define HTABLE_BITS 8

struct p4blocks {
	/* Length of @blocks and @assignments */
	size_t total_blocks;
	/* Extract from @blocks which haven't yet assigned to any IPv6 addresses */
	struct list_head idle_blocks;
	/*
	 * Extract from @blocks which have been assigned IPv6 addresses, indexed by IPv6
	 * address.
	 */
	DECLARE_HASHTABLE(assignments, HTABLE_BITS);

	spinlock_t lock;
	struct kref refs;
};

struct p4blocks *p4block_init(void)
{
	struct p4blocks *result;

	result = kmalloc(sizeof(struct p4blocks), GFP_KERNEL);
	if (!result)
		return NULL;

	result->total_blocks = 0;
	INIT_LIST_HEAD(&result->idle_blocks);
	hash_init(result->assignments);
	spin_lock_init(&result->lock);
	kref_init(&result->refs);

	return result;
}

void p4block_get(struct p4blocks *blocks)
{
	kref_get(&blocks->refs);
}

static void p4block_release(struct kref *refs)
{
	struct p4blocks *blocks;
	struct block *blk;
	struct hlist_node *tmp;
	size_t b;

	blocks = container_of(refs, struct p4blocks, refs);

	while (!list_empty(&blocks->idle_blocks)) {
		blk = list_first_entry(&blocks->idle_blocks, struct block,
				hook.list);
		list_del(&blk->hook.list);
		kfree(blk);
	}

	hash_for_each_safe(blocks->assignments, b, tmp, blk, hook.htable) {
		hash_del(&blk->hook.htable);
		kfree(blk);
	}

	kfree(blocks);
}

void p4block_put(struct p4blocks *blocks)
{
	kref_put(&blocks->refs, p4block_release);
}

int p4block_add(struct p4blocks *blocks, struct p4block *addend)
{
	struct block *node;

	node = kmalloc(sizeof(struct block), GFP_KERNEL);
	if (!node)
		return -ENOMEM;
	node->blk = *addend;
	node->is_assigned = false;

	spin_lock_bh(&blocks->lock);
	list_add_tail(&node->hook.list, &blocks->idle_blocks);
	spin_unlock_bh(&blocks->lock);

	return 0;
}

static bool block_equals(struct block *a, struct p4block *b)
{
	return addr4_equals(&a->blk.addr, &b->addr)
			&& (a->blk.ports.min == b->ports.min)
			&& (a->blk.ports.max == b->ports.max);
}

int p4block_rm(struct p4blocks *blocks, struct p4block *subtrahend)
{
	size_t b;
	struct block *node;

	spin_lock_bh(&blocks->lock);

	list_for_each_entry(node, &blocks->idle_blocks, hook.list) {
		if (block_equals(node, subtrahend)) {
			list_del(&node->hook.list);
			goto success;
		}
	}

	hash_for_each(blocks->assignments, b, node, hook.htable) {
		if (block_equals(node, subtrahend)) {
			hash_del(&node->hook.htable);
			goto success;
		}
	}

	spin_unlock_bh(&blocks->lock);
	return -ESRCH;

success:
	spin_unlock_bh(&blocks->lock);
	kfree(node);
	return 0;
}

void p4block_print(struct p4blocks *blocks, const char *prefix)
{
	size_t b;
	struct block *node;

	pr_info("%s: {\n", prefix ? prefix : "Blocks");
	list_for_each_entry(node, &blocks->idle_blocks, hook.list) {
		pr_info("  %pI4c:%u-%u\n", &node->blk.addr, node->blk.ports.min,
				node->blk.ports.max);
	}
	hash_for_each(blocks->assignments, b, node, hook.htable) {
		pr_info("  %pI4c:%u-%u (assigned to %pI6c)\n", &node->blk.addr,
				node->blk.ports.min, node->blk.ports.max,
				&node->assigned_addr6);
	}
	pr_info("}\n");
}

static u16 hash_addr6(const struct in6_addr *addr6)
{
	__u32 q3;
	__u32 q7;

	q3 = be16_to_cpu(addr6->s6_addr16[3]);
	q7 = be16_to_cpu(addr6->s6_addr16[7]);

	return hash_32((q3 << 16) | q7, HTABLE_BITS);
}

static struct block *get_next_unused_block(struct p4blocks *blocks)
{
	if (list_empty(&blocks->idle_blocks))
		return NULL;
	return list_first_entry(&blocks->idle_blocks, struct block, hook.list);
}

int p4block_find(struct p4blocks *blocks, struct in6_addr *client,
		struct p4block *result)
{
	struct block *db_node;
	u64 now;
	__u16 hash;

	now = get_jiffies_64();
	hash = hash_addr6(client);

	spin_lock_bh(&blocks->lock);

	/* If already assigned, return assigned block */
	hlist_for_each_entry(db_node, &blocks->assignments[hash], hook.htable)
		if (addr6_equals(&db_node->assigned_addr6, client))
			goto success;

	db_node = get_next_unused_block(blocks);
	if (db_node == NULL) {
		spin_unlock_bh(&blocks->lock);
		log_warn_once(
		    "Client %pI6c needs a pool4 block, but I already ran out.",
		    client
		);
		return -ESRCH;
	}

	list_del(&db_node->hook.list);
	hlist_add_head(&db_node->hook.htable, &blocks->assignments[hash]);
	db_node->assigned_addr6 = *client;
	db_node->is_assigned = true;
	/* Fall through */

success:
	db_node->last_used_time = now;
	*result = db_node->blk;
	spin_unlock_bh(&blocks->lock);
	return 0;
}

bool addr4_matches_blk(struct p4block const *blk,
		struct ipv4_transport_addr const *addr4)
{
	return addr4_equals(&blk->addr, &addr4->l3)
			&& (blk->ports.min <= addr4->l4)
			&& (addr4->l4 <= blk->ports.max);
}

bool p4block_contains(struct p4blocks *blocks,
		struct ipv4_transport_addr const *addr)
{
	size_t b;
	struct block *node;

	spin_lock_bh(&blocks->lock);

	list_for_each_entry(node, &blocks->idle_blocks, hook.list)
		if (addr4_matches_blk(&node->blk, addr))
			goto yes;
	hash_for_each(blocks->assignments, b, node, hook.htable)
		if (addr4_matches_blk(&node->blk, addr))
			goto yes;

	spin_unlock_bh(&blocks->lock);
	return false;

yes:
	spin_unlock_bh(&blocks->lock);
	return true;
}

void p4block_expire(struct p4blocks *blocks, u64 time_limit)
{
	u64 now;
	struct block *blk;
	struct hlist_node *tmp;
	size_t b;

	now = get_jiffies_64();

	spin_lock_bh(&blocks->lock);
	hash_for_each_safe(blocks->assignments, b, tmp, blk, hook.htable) {
		if (now - blk->last_used_time > time_limit) {
			blk->is_assigned = false;
			hash_del(&blk->hook.htable);
			list_add_tail(&blk->hook.list, &blocks->idle_blocks);
		}
	}
	spin_unlock_bh(&blocks->lock);
}

/* TODO fix unit tests and remove this */
void p4block_cheat(struct p4blocks *blocks)
{
	size_t b;
	struct block *node;

	hash_for_each(blocks->assignments, b, node, hook.htable) {
		node->last_used_time -= 100000;
	}
}
