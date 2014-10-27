#include "nat64/mod/host6_node.h"

#include "nat64/mod/rbtree.h"
#include "nat64/mod/bib_db.h"

/**
 * IPv6 host table definition.
 * Holds one red-black tree, for indexing IPv6 Host BIB's.
 */
struct host6_table {
	/** Indexes the entries using their IPv6 identifiers. */
	struct rb_root tree;
	/* Number of entries in this table. */
	u64 count;
};

/** The Lock that protect all the external functions and some internals. */
static DEFINE_SPINLOCK(host6_lock);
/** Cache for struct host6_node, for efficient allocation. */
static struct kmem_cache *host6_cache;
/** Cache for struct host_addr4, for efficient allocation. */
static struct kmem_cache *addr4_cache;
/** The Host6 database.*/
static struct host6_table host6_db;

/**
 * Returns > 0 if node->ipv6_addr > addr.
 * Returns < 0 if node->ipv6_addr < addr.
 * Returns 0 if node->ipv6_addr == addr.
 */
static int compare_addr6(const struct host6_node *node, const struct in6_addr *addr)
{
	return ipv6_addr_cmp(&node->ipv6_addr, addr);
}

static struct host6_node *host6_node_create(struct in6_addr *addr)
{
	struct host6_node *host6 = NULL;
	host6 = kmem_cache_alloc(host6_cache, GFP_ATOMIC);
	if (!host6) {
		log_err("Allocation of IPv6 node failed.");
		return NULL;
	}
	host6->ipv6_addr = *addr;
	kref_init(&host6->refcounter);
	RB_CLEAR_NODE(&host6->tree_hook);
	INIT_LIST_HEAD(&host6->ipv4_addr);

	log_debug("HOST6: host6_node create");
	return host6;
}

/**
 * Removes a host6_node entry from the database.
 * An spinlock must be hold.
 *
 * @param entry host6_node reference that you want to remove.
 */
static int host6_node_remove(struct host6_node *entry)
{
	if (WARN(!entry, "The host6_node cannot contain NULL."))
		return -EINVAL;
	if (RB_EMPTY_NODE(&entry->tree_hook)) {
		log_err("Host6_node entry does not belong to the tree.");
		return -EINVAL;
	}

	rb_erase(&entry->tree_hook, &host6_db.tree);
	host6_db.count--;

	return 0;
}

/**
 * Removes the host6_node entry from the database and kfrees it.
 * If you actually holding an spinlock, you must use this.
 *
 * @param ref kref field of the entry you want to remove.
 */
static void host6_node_release_lockless(struct kref *ref)
{
	struct host6_node *node6;
	int error;

	node6 = container_of(ref, struct host6_node, refcounter);

	error = host6_node_remove(node6);
	if (error) {
		WARN(error, "Error code %d when trying to remove a dying host6_node entry from the DB. "
				"Maybe it should have been kfreed directly instead?", error);
		return;
	}

	if (!list_empty(&node6->ipv4_addr))
		WARN(true, "host6_node will be released and contains reference to an ipv4_addr");

	kmem_cache_free(host6_cache, node6);
}

/**
 * Removes the host6_node entry from the database and kfrees it.
 *
 * @param ref kref field of the entry you want to remove.
 */
static void host6_node_release(struct kref *ref)
{
	spin_lock_bh(&host6_lock);
	host6_node_release_lockless(ref);
	spin_unlock_bh(&host6_lock);
}

void host6_node_get(struct host6_node *node6)
{
	kref_get(&node6->refcounter);
}

int host6_node_return(struct host6_node *node6)
{
	return kref_put(&node6->refcounter, host6_node_release);
}

/**
 * Same as host6_node_return, if for some reason you hold an spinlock and need to return a
 * host6_node entry, you have to use this version so the return doesn't try to lock
 * the spinlock again.
 */
static int host6_node_return_lockless(struct host6_node *node6)
{
	return kref_put(&node6->refcounter, host6_node_release_lockless);
}

static struct host_addr4 *host_addr4_create(const struct in_addr *addr) {
	struct host_addr4 *node = NULL;

	node = kmem_cache_alloc(addr4_cache, GFP_ATOMIC);
	if (!node) {
		log_err("Allocation of IPv4 node addr failed.");
		return NULL;
	}

	node->addr = *addr;
	kref_init(&node->refcounter);
	INIT_LIST_HEAD(&node->list_hook);
	node->node6 = NULL;

	log_debug("host_addr4 create");

	return node;
}

static void host_addr4_release(struct kref *ref)
{
	struct host_addr4 *addr4;

	spin_lock_bh(&host6_lock);
	addr4 = container_of(ref, struct host_addr4, refcounter);

	list_del(&addr4->list_hook);
	host6_node_return_lockless(addr4->node6);
	spin_unlock_bh(&host6_lock);
	kmem_cache_free(addr4_cache, addr4);
}

static void host_addr4_get(struct host_addr4 *addr4)
{
	kref_get(&addr4->refcounter);
}

int host_addr4_return(struct host_addr4 *addr4)
{
	return kref_put(&addr4->refcounter, host_addr4_release);
}

int host6_node_get_or_create(struct in6_addr *addr, struct host6_node **result)
{
	struct rb_node **rb_node, *parent;

	spin_lock_bh(&host6_lock);

	rbtree_find_node(addr, &host6_db.tree, compare_addr6, struct host6_node, tree_hook,
			parent, rb_node);
	if (*rb_node) {
		*result = rb_entry(*rb_node, struct host6_node, tree_hook);
		host6_node_get(*result);
		goto end;
	}

	*result = host6_node_create(addr);
	if (!(*result)) {
		log_err("Failed to allocate a Host6_node entry.");
		spin_unlock_bh(&host6_lock);
		return -ENOMEM;
	}

	/* Index it by IPv6. We already have the slot, so we don't need to do another rbtree_find(). */
	rb_link_node(&(*result)->tree_hook, parent, rb_node);
	rb_insert_color(&(*result)->tree_hook, &host6_db.tree);

	host6_db.count++;

end:
	spin_unlock_bh(&host6_lock);
	return 0;
}

int host6_node_for_each_addr4 (struct host6_node *host6,
		int (*func)(struct in_addr *, void *), void *arg)
{
	struct list_head *current_hook, *next_hook;
	struct host_addr4 *addr4;
	int error = 0;

	if (!host6)
		return -EINVAL;

	spin_lock_bh(&host6_lock);

	list_for_each_safe(current_hook, next_hook, &host6->ipv4_addr) {
		addr4 = list_entry(current_hook, struct host_addr4, list_hook);
		error = func(&addr4->addr, arg);
		if (error) {
			spin_unlock_bh(&host6_lock);
			return error;
		}
	}

	spin_unlock_bh(&host6_lock);
	return 0;
}

int host6_node_add_or_increment_addr4(struct host6_node *host6, struct bib_entry *bib)
{
	struct list_head *current_hook, *next_hook;
	struct host_addr4 *host_addr;

	if (!host6 || !bib)
		return -EINVAL;

	spin_lock_bh(&host6_lock);

	list_for_each_safe(current_hook, next_hook, &host6->ipv4_addr) {
		host_addr = list_entry(current_hook, struct host_addr4, list_hook);
		if (!ipv4_addr_cmp(&host_addr->addr, &bib->ipv4.l3)) {
			host_addr4_get(host_addr);
			goto end;
		}
	}

	host_addr = host_addr4_create(&bib->ipv4.l3);
	if (!host_addr) {
		spin_unlock_bh(&host6_lock);
		return -ENOMEM;
	}

	host_addr->node6 = host6;
	host6_node_get(host_addr->node6);
	list_add(&host_addr->list_hook, &host6->ipv4_addr);

end:
	bib->host4_addr = host_addr;
	spin_unlock_bh(&host6_lock);
	return 0;
}

int host6_node_init(void)
{
	host6_cache = kmem_cache_create("jool_host6_nodes", sizeof(struct host6_node), 0, 0, NULL);
	if (!host6_cache) {
		log_err("Could not allocate the Host6_node cache.");
		return -ENOMEM;
	}
	addr4_cache = kmem_cache_create("jool_host_addr4", sizeof(struct host_addr4), 0, 0, NULL);
	if (!addr4_cache) {
		log_err("Could not allocate the Host_addr4 cache.");
		kmem_cache_destroy(host6_cache);
		return -ENOMEM;
	}

	host6_db.tree = RB_ROOT;
	host6_db.count = 0;

	return 0;
}

static void host_addr4_destroy_aux(struct list_head *list)
{
	struct list_head *current_hook, *next_hook;
	struct host_addr4 *host_addr;


	list_for_each_safe(current_hook, next_hook, list) {
		host_addr = list_entry(current_hook, struct host_addr4, list_hook);
		list_del(current_hook);
		kmem_cache_free(addr4_cache, host_addr);
	}

}

static void host6_node_destroy_aux(struct rb_node *node)
{
	struct host6_node *host6;
	host6 = rb_entry(node, struct host6_node, tree_hook);
	if (!(list_empty(&host6->ipv4_addr))) {
		host_addr4_destroy_aux(&host6->ipv4_addr);
	}
	kmem_cache_free(host6_cache, host6);
}


void host6_node_destroy(void)
{
	rbtree_clear(&host6_db.tree, host6_node_destroy_aux);
	kmem_cache_destroy(host6_cache);
	kmem_cache_destroy(addr4_cache);
}
