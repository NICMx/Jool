#include "nat64/mod/stateless/eam.h"

#include <net/ipv6.h>

#include "nat64/mod/common/rbtree.h"
#include "nat64/mod/common/types.h"

/**
 * @author Daniel Hdz Felix
 * @author Alberto Leiva
 *
 * TODO (performance) This data structure doesn't receive updates constantly so RCU should perform
 * much better than the spinlock.
 * Also review the tree... a hash table might be better.
 */

struct eam_db {
	/** Indexes the entries using their IPv6 identifiers. */
	struct rb_root EAMT_tree6;
	/** Indexes the entries using their IPv4 identifiers. */
	struct rb_root EAMT_tree4;
	/* Number of entries in this table. */
	u64 count;
};

static struct eam_db eam_table;

/* The maximum network length for IPv4. */
static const __u8 IPV4_PREFIX = 32;
/* The maximum network length for IPv6. */
static const __u8 IPV6_PREFIX = 128;

/* Use to put all the 32 bits on, to make some operations at bit level.*/
static const __u32 IN_ADDR_FULL = INADDR_BROADCAST;

/**
 * Lock to sync access. This protects both the trees and the entries.
 */
static DEFINE_SPINLOCK(eam_lock);

/** Cache for struct eam_entries, for efficient allocation. */
static struct kmem_cache *entry_cache;

static void eam_kfree(struct eam_entry *entry)
{
	kmem_cache_free(entry_cache, entry);
}

/**
 *	Verify if the IPv4 prefix and the IPv6 prefix have the same network length.
 */
static int validate_prefixes(struct ipv6_prefix *pref6, struct ipv4_prefix *pref4)
{
	int error;

	error = prefix6_validate(pref6);
	if (error)
		return error;

	error = prefix4_validate(pref4);
	if (error)
		return error;

	if ((IPV4_PREFIX - pref4->len) > (IPV6_PREFIX - pref6->len)) {
		log_err("The IPv4 suffix length must be smaller or equal than the IPv6 suffix length.");
		return -EINVAL;
	}

	return 0;
}

static struct eam_entry *eamt_create_entry(struct ipv6_prefix *ip6, struct ipv4_prefix *ip4)
{
	struct eam_entry *entry;

	entry = kmem_cache_alloc(entry_cache, GFP_ATOMIC);
	if (!entry)
		return NULL;

	entry->pref4 = *ip4;
	entry->pref6 = *ip6;
	RB_CLEAR_NODE(&entry->tree4_hook);
	RB_CLEAR_NODE(&entry->tree6_hook);

	return entry;
}

static int eam_ipv6_prefix_equal(struct eam_entry *eam, struct ipv6_prefix *prefix)
{
	__u8 pref_len;

	if (prefix->len > eam->pref6.len)
		pref_len = eam->pref6.len;
	else
		pref_len = prefix->len;

	if (pref_len == IPV6_PREFIX)
		return false;

	return ipv6_prefix_equal(&prefix->address, &eam->pref6.address, pref_len);
}

/**
 * Returns zero if "eam"->pref6.address is equals to "prefix6" or contains the "prefix6".
 * Otherwise return the gap of the comparison result.
 */
static int compare_prefix6(struct eam_entry *entry, struct ipv6_prefix *prefix6)
{
	int gap;

	gap = ipv6_addr_cmp(&prefix6->address, &entry->pref6.address);
	if (gap == 0)
		return 0;

	if (eam_ipv6_prefix_equal(entry, prefix6))
		return 0;

	return gap;
}

static bool eam_ipv4_prefix_equal(struct eam_entry *eam, struct ipv4_prefix *prefix4)
{
	__u8 pref_len;
	__u32 full_bits = IN_ADDR_FULL;

	if (prefix4->len > eam->pref4.len)
		pref_len = eam->pref4.len;
	else
		pref_len = prefix4->len;

	if ((!pref_len) || ((eam->pref4.address.s_addr ^ prefix4->address.s_addr) &
			htonl((full_bits) << (IPV4_PREFIX - pref_len))))
		return false;

	return true;
}

/**
 * Returns zero if "eam"->pref4.address is equals to "prefix4" or contains the "prefix4".
 * Otherwise return the gap of the comparison result.
 */
static int compare_prefix4(struct eam_entry *entry, struct ipv4_prefix *prefix4)
{
	int gap;

	gap = ipv4_addr_cmp(&prefix4->address, &entry->pref4.address);
	if (gap == 0)
		return 0;

	if (eam_ipv4_prefix_equal(entry, prefix4))
		return 0;

	return gap;
}

static int eam_remove(struct eam_entry *entry, struct eam_db *table)
{
	if (!RB_EMPTY_NODE(&entry->tree6_hook))
		rb_erase(&entry->tree6_hook, &table->EAMT_tree6);
	if (!RB_EMPTY_NODE(&entry->tree4_hook))
		rb_erase(&entry->tree4_hook, &table->EAMT_tree4);

	return 1;
}

int eamt_add(struct ipv6_prefix *ip6_pref, struct ipv4_prefix *ip4_pref)
{
	int error;
	struct eam_entry *eam;
	struct rb_node **node, *parent;

	if (!ip6_pref || !ip4_pref) {
		log_err("ip6_prefix or ipv4 can't be NULL");
		return -EINVAL;
	}

	error = validate_prefixes(ip6_pref, ip4_pref);
	if (error)
		return error;

	log_debug("Inserting address mapping to the db: %pI6c/%u - %pI4/%u", &ip6_pref->address,
			ip6_pref->len, &ip4_pref->address, ip4_pref->len);

	spin_lock_bh(&eam_lock);
	rbtree_find_node(ip6_pref, &eam_table.EAMT_tree6, compare_prefix6, struct eam_entry, tree6_hook,
			parent, node);
	if (*node) {
		spin_unlock_bh(&eam_lock);
		log_debug("IPv6 Prefix %pI6c/%u already exist in the database.", &ip6_pref->address, ip6_pref->len);
		return -EEXIST;
	}

	/* The eam_entry is not on the table, so create it. */
	eam = eamt_create_entry(ip6_pref, ip4_pref);
	if (!eam) {
		spin_unlock_bh(&eam_lock);
		return -ENOMEM;
	}

	/* Index it by IPv6. We already have the slot, so we don't need to do another rbtree_find(). */
	rb_link_node(&eam->tree6_hook, parent, node);
	rb_insert_color(&eam->tree6_hook, &eam_table.EAMT_tree6);

	/* Index it by IPv4. */
	error = rbtree_add(eam, &eam->pref4, &eam_table.EAMT_tree4, compare_prefix4, struct eam_entry,
			tree4_hook);
	if (error) {
		rb_erase(&eam->tree6_hook, &eam_table.EAMT_tree6);
		spin_unlock_bh(&eam_lock);
		log_err("IPv4 Prefix %pI4/%u could not be added to the database. Maybe an entry with the "
				"same IPv4 Prefix and different IPv6 Prefix already exists?", &eam->pref4.address,
				eam->pref4.len);
		eam_kfree(eam);
		return error;
	}

	eam_table.count++;
	spin_unlock_bh(&eam_lock);
	return 0;
}

int eamt_remove(struct ipv6_prefix *prefix6, struct ipv4_prefix *prefix4)
{
	int count;
	struct eam_entry *eam;

	spin_lock_bh(&eam_lock);

	if (prefix6) {
		eam = rbtree_find(prefix6, &eam_table.EAMT_tree6, compare_prefix6, struct eam_entry,
				tree6_hook);
		if (!eam) {
			spin_unlock_bh(&eam_lock);
			log_err("There is no EAM entry for prefix %pI6c/%u.", &prefix6->address, prefix6->len);
			return -ESRCH;
		}

		if (prefix4 && !prefix4_equals(prefix4, &eam->pref4)) {
			log_err("The EAM entry whose 6-prefix is %pI6c/%u is mapped to %pI4/%u, not %pI4/%u.",
					&eam->pref6.address, eam->pref6.len,
					&eam->pref4.address, eam->pref4.len,
					&prefix4->address, prefix4->len);
			spin_unlock_bh(&eam_lock);
			return -EINVAL;
		}

		count = eam_remove(eam, &eam_table);

	} else if (prefix4) {
		eam = rbtree_find(prefix4, &eam_table.EAMT_tree4, compare_prefix4, struct eam_entry,
				tree4_hook);
		if (!eam) {
			spin_unlock_bh(&eam_lock);
			log_err("There is no EAM entry for prefix %pI4/%u.", &prefix4->address, prefix4->len);
			return -ESRCH;
		}

		count = eam_remove(eam, &eam_table);
	} else {
		spin_unlock_bh(&eam_lock);
		WARN(true, "Both prefixes are NULL.");
		return -EINVAL;
	}

	eam_table.count -= count;
	spin_unlock_bh(&eam_lock);
	eam_kfree(eam);
	return 0;
}

bool eamt_contains_ipv6(struct in6_addr *addr)
{
	struct ipv6_prefix prefix;
	struct eam_entry *eam;

	if (!addr) {
		log_err("addr6 can't be NULL");
		return false;
	}

	prefix.address = *addr;
	prefix.len = IPV6_PREFIX;

	spin_lock_bh(&eam_lock);
	eam = rbtree_find(&prefix, &eam_table.EAMT_tree6, compare_prefix6, struct eam_entry,
			tree6_hook);

	if (!eam) {
		spin_unlock_bh(&eam_lock);
		return false;
	}
	spin_unlock_bh(&eam_lock);
	return true;
}

bool eamt_contains_ipv4(__be32 addr)
{
	struct ipv4_prefix prefix;
	struct eam_entry *eam;

	prefix.address.s_addr = addr;
	prefix.len = IPV4_PREFIX;

	spin_lock_bh(&eam_lock);
	eam = rbtree_find(&prefix, &eam_table.EAMT_tree4, compare_prefix4, struct eam_entry,
			tree4_hook);

	if (!eam) {
		spin_unlock_bh(&eam_lock);
		return false;
	}
	spin_unlock_bh(&eam_lock);
	return true;
}

int eamt_get_ipv6_by_ipv4(struct in_addr *addr, struct in6_addr *result)
{
	struct ipv4_prefix prefix4;
	struct ipv6_prefix prefix6;
	struct eam_entry *eam;
	unsigned int suffix4_len;
	unsigned int i;

	if (!addr) {
		log_err("The IPv4 Address 'addr' can't be NULL");
		return -EINVAL;
	}

	/* Find the entry. */
	prefix4.address.s_addr = addr->s_addr;
	prefix4.len = IPV4_PREFIX;

	spin_lock_bh(&eam_lock);
	eam = rbtree_find(&prefix4, &eam_table.EAMT_tree4, compare_prefix4, struct eam_entry,
			tree4_hook);
	if (!eam) {
		spin_unlock_bh(&eam_lock);
		return -ESRCH;
	}

	prefix4 = eam->pref4;
	prefix6 = eam->pref6;
	spin_unlock_bh(&eam_lock);

	/* Translate the address. */
	suffix4_len = IPV4_PREFIX - prefix4.len;

	for (i = 0; i < suffix4_len; i++) {
		unsigned int offset4 = prefix4.len + i;
		unsigned int offset6 = prefix6.len + i;
		addr6_set_bit(&prefix6.address, offset6, addr4_get_bit(addr, offset4));
	}

	*result = prefix6.address; /* I'm assuming the prefix address is already zero-trimmed. */
	return 0;
}

int eamt_get_ipv4_by_ipv6(struct in6_addr *addr6, struct in_addr *result)
{
	struct ipv4_prefix prefix4;
	struct ipv6_prefix prefix6;
	struct eam_entry *eam;
	unsigned int i;

	if (!addr6) {
		log_err("The IPv6 Address 'addr6' can't be NULL");
		return -EINVAL;
	}

	prefix6.address = *addr6;
	prefix6.len = IPV6_PREFIX;

	spin_lock_bh(&eam_lock);
	eam = rbtree_find(&prefix6, &eam_table.EAMT_tree6, compare_prefix6, struct eam_entry,
			tree6_hook);
	if (!eam) {
		spin_unlock_bh(&eam_lock);
		return -ESRCH;
	}

	prefix4 = eam->pref4;
	prefix6 = eam->pref6;
	spin_unlock_bh(&eam_lock);

	for (i = 0; i < IPV4_PREFIX - prefix4.len; i++) {
		unsigned int offset4 = prefix4.len + i;
		unsigned int offset6 = prefix6.len + i;
		addr4_set_bit(&prefix4.address, offset4, addr6_get_bit(addr6, offset6));
	}

	*result = prefix4.address; /* I'm assuming the prefix address is already zero-trimmed. */
	return 0;
}

int eamt_count(__u64 *count)
{
	spin_lock_bh(&eam_lock);
	*count = eam_table.count;
	spin_unlock_bh(&eam_lock);
	return 0;
}

bool eamt_is_empty(void)
{
	__u64 count;
	eamt_count(&count);

	if (count)
		return false;

	return true;
}

/**
 * See the function of the same name from the BIB DB module for comments on this.
 */
static struct rb_node *find_next_chunk(struct ipv4_prefix *prefix, bool starting)
{
	struct rb_node **node, *parent;
	struct eam_entry *eam;

	if (starting)
		return rb_first(&eam_table.EAMT_tree4);

	rbtree_find_node(prefix, &eam_table.EAMT_tree4, compare_prefix4, struct eam_entry, tree4_hook,
			parent, node);
	if (*node)
		return rb_next(*node);

	eam = rb_entry(parent, struct eam_entry, tree4_hook);
	return (compare_prefix4(eam, prefix) < 0) ? parent : rb_next(parent);
}

int eamt_for_each(struct ipv4_prefix *prefix, bool starting,
		int (*func)(struct eam_entry *, void *), void *arg)
{
	struct rb_node *node;
	int error = 0;

	if (WARN(!prefix, "The IPv4 prefix is NULL."))
		return -EINVAL;

	spin_lock_bh(&eam_lock);
	for (node = find_next_chunk(prefix, starting); node && !error; node = rb_next(node))
		error = func(rb_entry(node, struct eam_entry, tree4_hook), arg);

	spin_unlock_bh(&eam_lock);
	return error;
}

int eamt_flush(void)
{
	struct eam_entry *root_eam, *eam;
	struct rb_node *node;
	int counter = 0;

	log_debug("Emptying the EAM table...");
	spin_lock_bh(&eam_lock);

	node = eam_table.EAMT_tree4.rb_node;
	if (!node)
		goto success;

	root_eam = rb_entry(node, struct eam_entry, tree4_hook);
	if (!root_eam)
		goto success;

	node = rb_prev(&root_eam->tree4_hook);
	while (node) {
		eam = rb_entry(node, struct eam_entry, tree4_hook);
		node = rb_prev(&eam->tree4_hook);
		counter += eam_remove(eam, &eam_table);
	}

	node = rb_next(&root_eam->tree4_hook);
	while (node) {
		eam = rb_entry(node, struct eam_entry, tree4_hook);
		node = rb_next(&eam->tree4_hook);
		counter += eam_remove(eam, &eam_table);
	}

	counter += eam_remove(root_eam, &eam_table);
	eam_table.count -= counter;
	/* Fall through. */

success:
	spin_unlock_bh(&eam_lock);
	log_debug("Deleted %d EAM entries.", counter);
	return 0;
}

int eamt_init(void)
{
	entry_cache = kmem_cache_create("address_mapping_entries", sizeof(struct eam_entry), 0, 0, NULL);
	if (!entry_cache) {
		log_err("Could not allocate the Address mapping entry cache.");
		return -ENOMEM;
	}

	eam_table.EAMT_tree4 = RB_ROOT;
	eam_table.EAMT_tree6 = RB_ROOT;
	eam_table.count = 0;

	return 0;
}

static void eamt_destroy_aux(struct rb_node *node)
{
	eam_kfree(rb_entry(node, struct eam_entry, tree6_hook));
}

void eamt_destroy(void)
{
	log_debug("Emptying the Address Mapping table...");
	/*
	 * The values need to be released only in one of the trees
	 * because both of them point to the same values.
	 */
	rbtree_clear(&eam_table.EAMT_tree6, eamt_destroy_aux);

	kmem_cache_destroy(entry_cache);
}
