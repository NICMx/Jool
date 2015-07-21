#include "nat64/mod/stateless/eam.h"
#include "nat64/mod/common/rtrie.h"
#include "nat64/mod/common/types.h"

/**
 * @author Daniel Hdz Felix
 * @author Alberto Leiva
 */

#define ADDR6_BITS 128
#define ADDR4_BITS 32

struct eamt_entry {
	struct ipv6_prefix prefix6;
	struct ipv4_prefix prefix4;
};

struct eam_table {
	struct rtrie_node *tree6;
	struct rtrie_node *tree4;
	u64 count;
};

static struct eam_table eamt;
/** Lock to sync access. This protects both the trees and the entries. */
static DEFINE_SPINLOCK(eamt_lock);

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

int eamt_add(struct ipv6_prefix *prefix6, struct ipv4_prefix *prefix4)
{
	struct eamt_entry new;
	size_t prefix6_offset;
	int error;

	error = validate_prefixes(prefix6, prefix4);
	if (error)
		return error;

	new.prefix6 = *prefix6;
	new.prefix4 = *prefix4;
	prefix6_offset = offsetof(typeof(new), prefix6.address);

	spin_lock_bh(&eamt_lock);

	error = rtrie_add(&eamt.tree6, &new, sizeof(new), prefix6_offset, new.prefix6.len);
	if (error)
		goto end;

	eamt.count++;

end:
	spin_unlock_bh(&eamt_lock);
	return error;
}

int eamt_remove(struct ipv6_prefix *prefix6, struct ipv4_prefix *prefix4)
{
	struct rtrie_string key;
	int error;

	key.bytes = (__u8 *) &prefix6->address;
	key.len = prefix6->len;

	spin_lock_bh(&eamt_lock);

	error = rtrie_rm(&eamt.tree6, &key);
	if (!error)
		eamt.count--;

	spin_unlock_bh(&eamt_lock);

	return error;
}

static struct eamt_entry *find_addr6(struct in6_addr *addr6)
{
	struct rtrie_string key;

	key.bytes = (__u8 *) addr6;
	key.len = 8 * sizeof(*addr6);

	return rtrie_get(eamt.tree6, &key);
}

bool eamt_contains_ipv6(struct in6_addr *addr)
{
	struct eamt_entry *node;
	bool result;

	spin_lock_bh(&eamt_lock);

	node = find_addr6(addr);
	result = !!node;

	spin_unlock_bh(&eamt_lock);

	return result;
}

int eamt_get_ipv4_by_ipv6(struct in6_addr *addr6, struct in_addr *result)
{
	struct eamt_entry *eam;
	struct ipv4_prefix prefix4;
	struct ipv6_prefix prefix6;
	unsigned int i;

	spin_lock_bh(&eamt_lock);

	eam = find_addr6(addr6);
	if (!eam)
		return -ESRCH;
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

void eamt_flush(void)
{
	spin_lock_bh(&eamt_lock);
	rtrie_flush(&eamt.tree6);
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
