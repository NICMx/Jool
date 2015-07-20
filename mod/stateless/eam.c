#include "nat64/mod/stateless/eam.h"
#include "nat64/mod/common/rtrie.h"
#include "nat64/mod/common/types.h"

/**
 * @author Daniel Hdz Felix
 * @author Alberto Leiva
 */

#define ADDR6_BITS 128
#define ADDR4_BITS 32

struct rtrie_inode6 {
	struct ipv6_prefix prefix6;
	struct rtrie_node tree6_hook;
};

struct rtrie_inode4 {
	struct ipv4_prefix prefix4;
	struct rtrie_node tree4_hook;
};

struct eamt_entry {
	struct ipv6_prefix prefix6;
	struct ipv4_prefix prefix4;
	struct rtrie_node tree6_hook;
	struct rtrie_node tree4_hook;
};

struct eam_table {
	struct rtrie_node *tree6;
	struct rtrie_node *tree4;
	u64 count;
};

static struct eam_table eamt;
/** Lock to sync access. This protects both the trees and the entries. */
static DEFINE_SPINLOCK(eamt_lock);

static struct eamt_entry *eamt_entry_create(struct ipv6_prefix *prefix6,
		struct ipv4_prefix *prefix4)
{
	struct eamt_entry *entry;

	entry = kmalloc(sizeof(*entry), GFP_ATOMIC);
	if (!entry)
		return NULL;

	entry->prefix4 = *prefix4;
	entry->prefix6 = *prefix6;
	rtrie_node_init(&entry->tree4_hook, true);
	rtrie_node_init(&entry->tree6_hook, true);

	return entry;
}

static struct rtrie_inode6 *inode6_create(struct ipv6_prefix *prefix6)
{
	struct rtrie_inode6 *entry;

	entry = kmalloc(sizeof(*entry), GFP_ATOMIC);
	if (!entry)
		return NULL;

	entry->prefix6 = *prefix6;
	rtrie_node_init(&entry->tree6_hook, false);

	return entry;
}

//static struct rtrie_inode4 *inode4_create(struct ipv4_prefix *prefix4)
//{
//	struct rtrie_inode4 *entry;
//
//	entry = kmalloc(sizeof(*entry), GFP_ATOMIC);
//	if (!entry)
//		return NULL;
//
//	entry->prefix4 = *prefix4;
//	rtrie_node_init(&entry->tree4_hook, false);
//
//	return entry;
//}

static struct eamt_entry *get_entry6(struct rtrie_node *node)
{
	return container_of(node, struct eamt_entry, tree6_hook);
}

//static struct eamt_entry *get_entry4(struct rtrie_node *node)
//{
//	return container_of(node, struct eamt_entry, tree4_hook);
//}

static struct rtrie_inode6 *get_inode6(struct rtrie_node *node)
{
	return container_of(node, struct rtrie_inode6, tree6_hook);
}

//static struct rtrie_inode4 *get_inode4(struct rtrie_node *node)
//{
//	return container_of(node, struct rtrie_inode4, tree6_hook);
//}

static struct ipv6_prefix *get_prefix6(struct rtrie_node *node)
{
	return node->is_leaf
			? &get_entry6(node)->prefix6
			: &get_inode6(node)->prefix6;
}

//static struct ipv4_prefix *get_prefix4(struct rtrie_node *node)
//{
//	return node->is_leaf
//			? &get_entry4(node)->prefix4
//			: &get_inode4(node)->prefix4;
//}

/**
 * validate_prefixes - check @prefix6 and @prefix4 can be joined together to
 * form a (standalone) legal EAM entry.
 */
static int validate_prefixes(struct ipv6_prefix *prefix6,
		struct ipv4_prefix *prefix4)
{
	int error;

	error = prefix6_validate(prefix6);
	if (error)
		return error;

	error = prefix4_validate(prefix4);
	if (error)
		return error;

	if ((ADDR4_BITS - prefix4->len) > (ADDR6_BITS - prefix6->len)) {
		log_err("The IPv4 suffix length must be smaller or equal than "
				"the IPv6 suffix length.");
		return -EINVAL;
	}

	return 0;
}

static unsigned int match6(struct ipv6_prefix *prefix, struct in6_addr *addr)
{
	unsigned int result = 0;
	unsigned int i;
	unsigned int bit1;
	unsigned int bit2;

	for (i = 0; i < ARRAY_SIZE(addr->s6_addr16); i++) {
		if (prefix->address.s6_addr16[i] == addr->s6_addr16[i]) {
			result += 16;
		} else {
			for (i = 0; i < 16; i++) {
				bit1 = !!addr6_get_bit(&prefix->address, result);
				bit2 = !!addr6_get_bit(addr, result);

				if (bit1 != bit2)
					break;

				result++;
			}

			break;
		}
	}

	return result;
}

static struct rtrie_node *find_longest_common_prefix6(struct in6_addr *addr)
{
	struct rtrie_node *node;
	unsigned int node_match;
	unsigned int left_match;
	unsigned int right_match;

	node = eamt.tree6;
	if (!node)
		return NULL;

	node_match = match6(get_prefix6(node), addr);
	if (!node_match)
		return NULL;

	while (!node->is_leaf) {
		left_match = match6(get_prefix6(node->left), addr);
		right_match = match6(get_prefix6(node->right), addr);

		if (node_match == left_match && node_match == right_match) {
			return node;
		} else if (left_match > right_match) {
			node = node->left;
			node_match = left_match;
		} else if (left_match < right_match) {
			node = node->right;
			node_match = right_match;
		} else {
			/* TODO improve error msg. */
			WARN(true, "Inconsistent rtrie!");
			return NULL;
		}
	}

	return node;
}

/**
 * This function assumes all involved prefixes lack suffix (as they're always
 * supposed to).
 */
static int get_common_prefix(struct rtrie_node *node, struct eamt_entry *entry,
		struct ipv6_prefix *result)
{
	struct ipv6_prefix *prefix1, *prefix2;
	__be16 chunk1, chunk2;
	unsigned int bit1, bit2;
	unsigned int i;
	unsigned int min_len;
	int comparison = 0;

	prefix1 = get_prefix6(node);
	prefix2 = &entry->prefix6;
	memset(result, 0, sizeof(*result));

	for (i = 0; i < ARRAY_SIZE(prefix1->address.s6_addr16); i++) {
		chunk1 = prefix1->address.s6_addr16[i];
		chunk2 = prefix2->address.s6_addr16[i];

		if (chunk1 == chunk2) {
			result->address.s6_addr16[i] = chunk1;
			result->len += 16;
		} else {
			comparison = be16_to_cpu(chunk2) - be16_to_cpu(chunk1);

			for (i = 0; i < 16; i++) {
				bit1 = !!addr6_get_bit(&prefix1->address, result->len);
				bit2 = !!addr6_get_bit(&prefix2->address, result->len);

				if (bit1 != bit2)
					break;

				addr6_set_bit(&result->address, result->len, bit1);
				result->len++;
			}

			break;
		}
	}

	min_len = min(prefix1->len, prefix2->len);
	if (result->len > min_len)
		result->len = min_len;

	return (comparison == 0) ? (prefix2->len - prefix1->len) : comparison;
}

static int __add6(struct rtrie_node *node, struct eamt_entry *new_eamt)
{
	struct rtrie_inode6 *new_inode;
	struct ipv6_prefix new_prefix;
	int comparison;

	comparison = get_common_prefix(node, new_eamt, &new_prefix);
	new_inode = inode6_create(&new_prefix);
	if (!new_inode)
		return -ENOMEM;

	if (comparison > 0) {
		rtrie_add_right(&eamt.tree6, node, &new_inode->tree6_hook,
				&new_eamt->tree6_hook);
	} else if (comparison < 0) {
		rtrie_add_left(&eamt.tree6, node, &new_inode->tree6_hook,
				&new_eamt->tree6_hook);
	} else {
		/* TODO improve error msg. */
		log_err("The IPv6 prefix is already mapped.");
		kfree(new_inode);
		return -EEXIST;
	}

	return 0;
}

int eamt_add(struct ipv6_prefix *prefix6, struct ipv4_prefix *prefix4)
{
	struct rtrie_node *node;
	struct eamt_entry *new;
	int error = 0;

	error = validate_prefixes(prefix6, prefix4);
	if (error)
		return error;

	new = eamt_entry_create(prefix6, prefix4);
	if (!new)
		return -ENOMEM;

	spin_lock_bh(&eamt_lock);

	/* TODO test first bit doesn't match root. */
	node = find_longest_common_prefix6(&prefix6->address);
	if (node) {
		log_debug("fusionando con %pI6c/%u",
				&get_prefix6(node)->address,
				get_prefix6(node)->len);

		error = __add6(node, new);
		if (error) {
			kfree(new);
			goto end;
		}
	} else if (eamt.tree6) {
		error = __add6(eamt.tree6, new);
		if (error) {
			kfree(new);
			goto end;
		}
	} else {
		eamt.tree6 = &new->tree6_hook;
	}

	eamt.count++;

end:
	spin_unlock_bh(&eamt_lock);
	return error;
}

/**
 * Returns the longest prefix leaf node that matches @addr.
 */
static struct rtrie_node *find_addr6(struct in6_addr *addr)
{
	struct rtrie_node *node;

	node = eamt.tree6;
	if (!node || !prefix6_contains(get_prefix6(node), addr))
		return NULL;

	while (node && !node->is_leaf) {
		if (prefix6_contains(get_prefix6(node->left), addr)) {
			node = node->left;
			continue;
		}

		if (prefix6_contains(get_prefix6(node->right), addr)) {
			node = node->right;
			continue;
		}

		return NULL;
	}

	return node;
}

int eamt_remove(struct ipv6_prefix *prefix6, struct ipv4_prefix *prefix4)
{
	struct rtrie_node *node;

	spin_lock_bh(&eamt_lock);

	node = find_addr6(&prefix6->address);
	if (!node || !prefix6_equals(get_prefix6(node), prefix6)) {
		spin_unlock_bh(&eamt_lock);
		return -ESRCH;
	}

	rtrie_rm(&eamt.tree6, node);
	eamt.count--;

	spin_unlock_bh(&eamt_lock);

	if (node->parent)
		kfree(get_inode6(node->parent));
	kfree(get_entry6(node));

	return 0;
}

bool eamt_contains_ipv6(struct in6_addr *addr)
{
	struct rtrie_node *node;
	bool result;

	spin_lock_bh(&eamt_lock);

	node = find_addr6(addr);
	result = !!node;

	spin_unlock_bh(&eamt_lock);

	return result;
}

int eamt_get_ipv4_by_ipv6(struct in6_addr *addr6, struct in_addr *result)
{
	struct rtrie_node *node;
	struct eamt_entry *eam;
	struct ipv4_prefix prefix4;
	struct ipv6_prefix prefix6;
	unsigned int i;

	spin_lock_bh(&eamt_lock);

	node = find_addr6(addr6);
	if (!node) {
		spin_unlock_bh(&eamt_lock);
		return -ESRCH;
	}

	eam = get_entry6(node);
	prefix4 = eam->prefix4;
	prefix6 = eam->prefix6;

	spin_unlock_bh(&eamt_lock);

	for (i = 0; i < ADDR4_BITS - prefix4.len; i++) {
		unsigned int offset4 = prefix4.len + i;
		unsigned int offset6 = prefix6.len + i;
		addr4_set_bit(&prefix4.address, offset4,
				addr6_get_bit(addr6, offset6));
	}

	/* I'm assuming the prefix address is already zero-trimmed. */
	*result = prefix4.address;
	return 0;
}

int eamt_count(__u64 *count)
{
	spin_lock_bh(&eamt_lock);
	*count = eamt.count;
	spin_unlock_bh(&eamt_lock);
	return 0;
}

bool eamt_is_empty(void)
{
	__u64 count;
	eamt_count(&count);
	return !count;
}

///**
// * See the function of the same name from the BIB DB module for comments on this.
// */
//static struct rb_node *find_next_chunk(struct ipv4_prefix *offset)
//{
//	struct rb_node **node, *parent;
//	struct eam_entry *eam;
//
//	if (!offset)
//		return rb_first(&eam_table.EAMT_tree4);
//
//	rbtree_find_node(offset, &eam_table.EAMT_tree4, compare_prefix4, struct eam_entry, tree4_hook,
//			parent, node);
//	if (*node)
//		return rb_next(*node);
//
//	eam = rb_entry(parent, struct eam_entry, tree4_hook);
//	return (compare_prefix4(eam, offset) < 0) ? parent : rb_next(parent);
//}
//
//int eamt_for_each(int (*func)(struct eam_entry *, void *), void *arg,
//		struct ipv4_prefix *offset)
//{
//	struct rb_node *node;
//	int error = 0;
//	spin_lock_bh(&eam_lock);
//
//	for (node = find_next_chunk(offset); node && !error; node = rb_next(node))
//		error = func(rb_entry(node, struct eam_entry, tree4_hook), arg);
//
//	spin_unlock_bh(&eam_lock);
//	return error;
//}

//static struct rtrie_node *rtrie_first(struct rtrie_node *root)
//{
//	struct rtrie_node *result = root;
//
//	while (result->left)
//		result = result->left;
//
//	return result;
//}

static struct rtrie_node *rtrie_kfree(struct rtrie_node *node)
{
	struct rtrie_node *parent = node->parent;

	rtrie_swap(&eamt.tree6, node, NULL);
	if (node->is_leaf) {
		kfree(get_entry6(node));
	} else {
		kfree(get_inode6(node));
	}

	return parent;
}

void eamt_flush(void)
{
	struct rtrie_node *node;

	spin_lock_bh(&eamt_lock);

	node = eamt.tree6;
	while (node) {
		if (node->left)
			node = node->left;
		else if (node->right)
			node = node->right;
		else
			node = rtrie_kfree(node);
	}

	eamt.tree6 = NULL;
	spin_unlock_bh(&eamt_lock);
}

int eamt_init(void)
{
	eamt.tree4 = NULL;
	eamt.tree6 = NULL;
	eamt.count = 0;
	return 0;
}

void eamt_destroy(void)
{
	log_debug("Emptying the Address Mapping table...");
	eamt_flush();
}
