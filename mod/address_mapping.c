#include "nat64/mod/address_mapping.h"

#include <net/ipv6.h>

#include "nat64/mod/rbtree.h"
#include "nat64/mod/types.h"
/*
 * address_mapping.c
 *
 *  Created on: Nov 25, 2014
 *      Author: Daniel Hdz Felix
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
 * Get the IPv4 prefix from the IPv4 address "addr" given by the network length "len", the
 * resulting IPv4 prefix is stored in "result".
 */
static int get_prefix4(struct in_addr *addr, __u8 len, struct ipv4_prefix *result)
{
	__u32 full_bits = IN_ADDR_FULL;

	result->address.s_addr = addr->s_addr & htonl(full_bits << (IPV4_PREFIX - len));
	result->len = len;

	return 0;
}

/**
 * Get the IPv6 prefix from the IPv6 address "addr" given by the network length "len", the
 * resulting IPv6 prefix is stored in "result".
 */
static int get_prefix6(struct in6_addr *addr, __u8 len, struct ipv6_prefix *result)
{
	__u32 full_bits = IN_ADDR_FULL;

	result->address = *addr;
	result->address.s6_addr32[3] &= htonl(full_bits << (IPV6_PREFIX - len));

	result->len = len;

	return 0;
}

/**
 *	Verify if the IPv4 prefix and the IPv6 prefix have the same network length.
 */
static int has_same_prefix(struct ipv6_prefix *pref6, struct ipv4_prefix *pref4)
{
	if ((pref4->len > IPV4_PREFIX) || (pref6->len > IPV6_PREFIX)) {
		log_err("Invalid Prefix Lengths IPv6 Prefix should be less or equals than %u, "
				"IPv4 Prefix should be less or equals than %u", IPV6_PREFIX, IPV4_PREFIX);
		return -EINVAL;
	}

	if ((IPV4_PREFIX - pref4->len) != (IPV6_PREFIX - pref6->len)) {
		log_err("IPv4 and IPv6 network lengths are different.");
		return -EINVAL;
	}

	return 0;
}

static struct eam_entry *address_mapping_create_entry(struct ipv6_prefix *ip6, struct ipv4_prefix *ip4)
{
	struct eam_entry *entry;

	if (!ip4 || !ip6) {
		log_err("ip6_pref or ip4_pref can't be NULL");
		goto fail;
	}

	entry = kmem_cache_alloc(entry_cache, GFP_ATOMIC);
	if (!entry)
		goto fail;

	get_prefix4(&ip4->address, ip4->len, &entry->pref4);
	get_prefix6(&ip6->address, ip6->len, &entry->pref6);

	RB_CLEAR_NODE(&entry->tree4_hook);
	RB_CLEAR_NODE(&entry->tree6_hook);

	return entry;

fail:
	return NULL;
}

static int eam_ipv6_prefix_equal(struct eam_entry *eam, struct ipv6_prefix *prefix)
{
	__u8 pref_len;

	if (prefix->len > eam->pref6.len)
		pref_len = eam->pref6.len;
	else
		pref_len = prefix->len;

	if (pref_len == 128)
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

int address_mapping_insert_entry(struct ipv6_prefix *ip6_pref, struct ipv4_prefix *ip4_pref)
{
	int error;
	struct eam_entry *eam;
	struct rb_node **node, *parent;

	if (!ip6_pref || !ip4_pref) {
		log_err("ip6_prefix or ipv4 can't be NULL");
		return -EINVAL;
	}

	error = has_same_prefix(ip6_pref, ip4_pref);
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
	eam = address_mapping_create_entry(ip6_pref, ip4_pref);
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

	spin_unlock_bh(&eam_lock);
	return 0;
}

static int get_ipv6_by_ipv4(struct eam_entry *eam, struct in_addr *addr,
		struct in6_addr *result)
{
	__u32 full_bits = IN_ADDR_FULL;
	*result = eam->pref6.address;

	if(eam->pref6.len < 128)
		result->s6_addr32[3] |= addr->s_addr & htonl(full_bits >> eam->pref4.len);

	return 0;
}

static int get_ipv4_by_ipv6(struct eam_entry *eam, struct in6_addr *addr6,
		struct in_addr *result)
{
	__u32 full_bits = IN_ADDR_FULL;
	result->s_addr = eam->pref4.address.s_addr;

	if(eam->pref4.len < 32)
		result->s_addr |= addr6->s6_addr32[3] & htonl(full_bits >> eam->pref4.len);

	return 0;
}

int address_mapping_get_ipv6_by_ipv4(struct in_addr *addr, struct in6_addr *result)
{
	struct ipv4_prefix in_pref4;
	struct eam_entry *eam;

	if (!addr) {
		log_err("The IPv4 Address 'addr' can't be NULL");
		return -EINVAL;
	}

	in_pref4.address.s_addr = addr->s_addr;
	in_pref4.len = 32;

	spin_lock_bh(&eam_lock);
	eam = rbtree_find(&in_pref4, &eam_table.EAMT_tree4, compare_prefix4, struct eam_entry,
			tree4_hook);
	if (!eam) {
		spin_unlock_bh(&eam_lock);
		return -ENOENT;
	}

	get_ipv6_by_ipv4(eam, addr, result);
	spin_unlock_bh(&eam_lock);

	return 0;
}

int address_mapping_get_ipv4_by_ipv6(struct in6_addr *addr6, struct in_addr *result)
{
	struct ipv6_prefix in_pref6;
	struct eam_entry *eam;

	if (!addr6) {
		log_err("The IPv6 Address 'addr6' can't be NULL");
		return -EINVAL;
	}

	in_pref6.address = *addr6;
	in_pref6.len = 128;

	spin_lock_bh(&eam_lock);
	eam = rbtree_find(&in_pref6, &eam_table.EAMT_tree6, compare_prefix6, struct eam_entry,
			tree6_hook);
	if (!eam) {
		spin_unlock_bh(&eam_lock);
		return -ENOENT;
	}

	get_ipv4_by_ipv6(eam, addr6, result);
	spin_unlock_bh(&eam_lock);

	return 0;
}

int address_mapping_init(void)
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

static void address_mapping_destroy_aux(struct rb_node *node)
{
	eam_kfree(rb_entry(node, struct eam_entry, tree6_hook));
}

void address_mapping_destroy(void)
{
	log_debug("Emptying the Address Mapping table...");
	/*
	 * The values need to be released only in one of the trees
	 * because both of them point to the same values.
	 */
	rbtree_clear(&eam_table.EAMT_tree6, address_mapping_destroy_aux);

	kmem_cache_destroy(entry_cache);
}
