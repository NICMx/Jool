#include "nat64/mod/common/rtrie.h"
#include "nat64/mod/common/types.h" /* TODO delete this. */
#include <linux/slab.h>

static __u8 bits_to_bytes(__u8 bits)
{
	return (bits != 0) ? (((bits - 1) >> 3) + 1) : 0;
}

static struct rtrie_node *create_inode(struct rtrie_key *key,
		struct rtrie_node *left_child,
		struct rtrie_node *right_child)
{
	struct rtrie_node *inode;
	__u8 value_bytes;

	value_bytes = bits_to_bytes(key->len);
	inode = kmalloc(sizeof(*inode) + value_bytes, GFP_ATOMIC);
	if (!inode)
		return NULL;

	inode->left = left_child;
	inode->right = right_child;
	inode->parent = NULL;
	inode->color = COLOR_BLACK;
	INIT_LIST_HEAD(&inode->list_hook);
	inode->key.bytes = (__u8 *) (inode + 1);
	inode->key.len = key->len;
	memcpy(inode->key.bytes, key->bytes, value_bytes);

	return inode;
}

static struct rtrie_node *create_leaf(void *content, size_t content_len,
		size_t key_offset, __u8 key_len)
{
	struct rtrie_node *leaf;

	leaf = kmalloc(sizeof(*leaf) + content_len, GFP_ATOMIC);
	if (!leaf)
		return NULL;

	leaf->left = NULL;
	leaf->right = NULL;
	leaf->parent = NULL;
	leaf->color = COLOR_WHITE;
	INIT_LIST_HEAD(&leaf->list_hook);
	leaf->key.bytes = ((__u8 *) (leaf + 1)) + key_offset;
	leaf->key.len = key_len;
	memcpy(leaf + 1, content, content_len);

	return leaf;
}

static unsigned int get_bit(__u8 byte, unsigned int pos)
{
	return (byte >> (7 - pos)) & 1;
}

static unsigned int __key_match(struct rtrie_key *key1, struct rtrie_key *key2,
		unsigned int bits)
{
	unsigned int result = 0;
	unsigned int y, i; /* b[y]te counter, b[i]t counter. */
	unsigned int bytes;
	unsigned int bit1, bit2;

	bytes = bits >> 3; /* >> 3 = / 8*/
	bits &= 7; /* & 7 = % 8 */

	for (y = 0; y < bytes; y++) {
		if (key1->bytes[y] != key2->bytes[y]) {
			bits = 8;
			break;
		}
		result += 8;
	}

	for (i = 0; i < bits; i++) {
		bit1 = get_bit(key1->bytes[y], i);
		bit2 = get_bit(key2->bytes[y], i);

		if (bit1 != bit2)
			break;

		result++;
	}

	return result;
}

/**
 * match - Returns the number of prefix bits @key1 and @key2 have in common.
 */
static unsigned int key_match(struct rtrie_key *key1, struct rtrie_key *key2)
{
	return __key_match(key1, key2, min(key1->len, key2->len));
}

/**
 * Returns true if @key1 is a prefix of @key2, false otherwise.
 *
 * The name can go both ways so it might be confusing. Think of it like this:
 * If @key1 is 2001:db8::/32 and @key2 is 2001:db8:1::/64, then @key1 contains
 * @key2.
 */
static bool key_contains(struct rtrie_key *key1, struct rtrie_key *key2)
{
	return (key2->len >= key1->len)
			? (__key_match(key1, key2, key1->len) == key1->len)
			: false;
}

static bool key_equals(struct rtrie_key *key1, struct rtrie_key *key2)
{
	return (key1->len == key2->len)
			? (__key_match(key1, key2, key1->len) == key1->len)
			: false;
}

/**
 * find_longest_common_prefix - Returns the node from @root's trie which best
 * matches @key.
 *
 * @root: trie you want to search.
 * @key: the string you want the best match for.
 * @force_white: if true, the resulting node will be the best white match.
 *	If false, the result will be the best match, regardless of color.
 */
static struct rtrie_node *find_longest_common_prefix(struct rtrie_node *root,
		struct rtrie_key *key, bool force_white)
{
	struct rtrie_node *node;
	struct rtrie_node *last_white;

	node = root;
	if (!node || !key_contains(&node->key, key))
		return NULL;

	last_white = NULL;
	do {
		if (node->color == COLOR_WHITE)
			last_white = node;

		if (node->left && key_contains(&node->left->key, key)) {
			node = node->left;
			continue;
		}

		if (node->right && key_contains(&node->right->key, key)) {
			node = node->right;
			continue;
		}

		return force_white ? last_white : node;
	} while (true);

	return NULL; /* <-- Shuts up Eclipse. */
}

static struct rtrie_node **get_parent_ptr(struct rtrie_node **root,
		struct rtrie_node *node)
{
	struct rtrie_node *parent = node->parent;

	if (!parent)
		return root;

	return (parent->left == node) ? &parent->left : &parent->right;
}

static void swap_nodes(struct rtrie_node **root, struct rtrie_node *old,
		struct rtrie_node *new)
{
	struct rtrie_node **parent_ptr;

	new->left = old->left;
	new->right = old->right;
	new->parent = old->parent;

	parent_ptr = get_parent_ptr(root, old);
	(*parent_ptr) = new;

	list_add(&new->list_hook, &old->list_hook);
	list_del(&old->list_hook);

	kfree(old);
}

static int add_to_root(struct rtrie_node **root, struct rtrie_node *new)
{
	struct rtrie_node *root2 = *root;
	struct rtrie_node *inode;
	struct rtrie_key key;

	if (!root2) {
		*root = new;
		return 0;
	}

	if (key_contains(&new->key, &root2->key)) {
		new->left = root2;
		root2->parent = new;
		list_add(&new->list_hook, &root2->list_hook);
		*root = new;
		return 0;
	}

	key.bytes = new->key.bytes;
	key.len = key_match(&root2->key, &new->key);

	inode = create_inode(&key, root2, new);
	if (!inode)
		return -ENOMEM;

	root2->parent = inode;
	new->parent = inode;
	list_add(&inode->list_hook, &root2->list_hook);
	list_add(&new->list_hook, &root2->list_hook);

	*root = inode;
	return 0;
}

static int add_full_collision(struct rtrie_node *parent, struct rtrie_node *new)
{
	/*
	 * We're adding new to
	 *
	 * parent
	 *    |
	 *    +---- child1
	 *    |
	 *    +---- child2
	 *
	 * We need to turn it into this:
	 *
	 * parent
	 *    |
	 *    +---- smallest_prefix_node
	 *    |
	 *    +---- inode
	 *             |
	 *             +---- higher_prefix1
	 *             |
	 *             +---- higher_prefix2
	 *
	 * { smallest_prefix_node, higher_prefix1, higher_prefix2 } is some
	 * combination from { child1, child2, new }.
	 */
	struct rtrie_node *smallest_prefix;
	struct rtrie_node *higher_prefix1;
	struct rtrie_node *higher_prefix2;
	struct rtrie_node *inode;
	struct rtrie_key inode_prefix;

	unsigned int match_lr = key_match(&parent->left->key, &parent->right->key);
	unsigned int match_ln = key_match(&parent->left->key, &new->key);
	unsigned int match_rn = key_match(&parent->right->key, &new->key);

	if (match_lr > match_ln && match_lr > match_rn) {
		smallest_prefix = new;
		higher_prefix1 = parent->left;
		higher_prefix2 = parent->right;
		inode_prefix.len = match_lr;
	} else if (match_ln > match_lr && match_ln > match_rn) {
		smallest_prefix = parent->right;
		higher_prefix1 = new;
		higher_prefix2 = parent->left;
		inode_prefix.len = match_ln;
	} else if (match_rn > match_lr && match_rn > match_ln) {
		smallest_prefix = parent->left;
		higher_prefix1 = new;
		higher_prefix2 = parent->right;
		inode_prefix.len = match_rn;
	} else {
		WARN(true, "Inconsistent bwrtrie! (%u %u %u)",
				match_lr, match_ln, match_rn);
		return -EINVAL;
	}
	inode_prefix.bytes = higher_prefix1->key.bytes;

	inode = create_inode(&inode_prefix, higher_prefix1, higher_prefix2);
	if (!inode)
		return -ENOMEM;

	parent->left = NULL;
	parent->right = NULL;
	parent->left = smallest_prefix;
	parent->right = inode;

	smallest_prefix->parent = parent;
	inode->parent = parent;
	higher_prefix1->parent = inode;
	higher_prefix2->parent = inode;
	list_add(&inode->list_hook, &parent->list_hook);
	list_add(&new->list_hook, &parent->list_hook);

	return 0;
}

int rtrie_add(struct rtrie_node **root, void *content, size_t content_len,
		size_t key_offset, __u8 key_len)
{
	struct rtrie_node *new;
	struct rtrie_node *parent;
	bool contains_left;
	bool contains_right;

	new = create_leaf(content, content_len, key_offset, key_len);
	if (!new)
		return -ENOMEM;

	parent = find_longest_common_prefix(*root, &new->key, false);
	if (!parent)
		return add_to_root(root, new);

	if (key_equals(&parent->key, &new->key)) {
		if (parent->color == COLOR_BLACK) {
			swap_nodes(root, parent, new);
			return 0;
		}
		kfree(new);
		return -EEXIST;
	}

	if (!parent->left) {
		parent->left = new;
		goto simple_success;
	}
	if (!parent->right) {
		parent->right = new;
		goto simple_success;
	}

	contains_left = key_contains(&new->key, &parent->left->key);
	contains_right = key_contains(&new->key, &parent->right->key);

	if (contains_left && contains_right) {
		if (parent->color == COLOR_BLACK) {
			swap_nodes(root, parent, new);
			return 0;
		}

		new->left = parent->left;
		new->right = parent->right;
		parent->left = NULL;
		parent->right = new;

		new->left->parent = new;
		new->right->parent = new;
		goto simple_success;
	}

	if (contains_left) {
		new->left = parent->left;
		parent->left = new;

		new->left->parent = new;
		goto simple_success;
	}

	if (contains_right) {
		new->right = parent->right;
		parent->right = new;

		new->right->parent = new;
		goto simple_success;
	}

	return add_full_collision(parent, new);

simple_success:
	new->parent = parent;
	list_add(&new->list_hook, &parent->list_hook);
	return 0;
}

void *rtrie_get(struct rtrie_node *root, struct rtrie_key *key)
{
	struct rtrie_node *node = find_longest_common_prefix(root, key, true);
	return node ? (node + 1) : NULL;
}

static int prune_if_black(struct rtrie_node **root, struct rtrie_node *node)
{
	struct rtrie_node *parent;
	struct rtrie_node **parent_ptr;

	while (node) {
		if (node->color == COLOR_WHITE)
			return 0;

		/*
		 * At this point, node cannot have two children,
		 * so it's going down.
		 */
		parent = node->parent;
		parent_ptr = get_parent_ptr(root, node);

		if (node->left) {
			(*parent_ptr) = node->left;
			node->left->parent = parent;
			list_del(&node->list_hook);
			kfree(node);
			return 0;
		}

		if (node->right) {
			(*parent_ptr) = node->right;
			node->right->parent = parent;
			list_del(&node->list_hook);
			kfree(node);
			return 0;
		}

		(*parent_ptr) = NULL;
		list_del(&node->list_hook);
		kfree(node);
		node = parent;
	}

	return 0;
}

int rtrie_rm(struct rtrie_node **root, struct rtrie_key *key)
{
	struct rtrie_node *parent;
	struct rtrie_node **parent_ptr;
	struct rtrie_node *node;

	node = find_longest_common_prefix(*root, key, true);
	if (!node || !key_equals(&node->key, key))
		return -ESRCH;

	if (node->left && node->right) {
		/* TODO This is not thread-safe; gonna need to swap nodes. */
		node->color = COLOR_BLACK;
		return 0;
	}

	parent = node->parent;
	parent_ptr = get_parent_ptr(root, node);

	if (node->left) {
		(*parent_ptr) = node->left;
		node->left->parent = parent;
		list_del(&node->list_hook);
		kfree(node);
		return 0;
	}

	if (node->right) {
		(*parent_ptr) = node->right;
		node->right->parent = parent;
		kfree(node);
		list_del(&node->list_hook);
		return 0;
	}

	(*parent_ptr) = NULL;
	list_del(&node->list_hook);
	kfree(node);

	return prune_if_black(root, parent);
}

void rtrie_flush(struct rtrie_node **root)
{
	struct list_head *list;
	struct rtrie_node *node;
	struct rtrie_node *tmp;
	unsigned int i = 0;

	rtrie_print("Flushing trie", *root);

	if (!*root) {
		log_debug("Deleted 0 nodes.");
		return;
	}

	list = &(*root)->list_hook;
	list_for_each_entry_safe(node, tmp, list, list_hook) {
		list_del(&node->list_hook);
		kfree(node);
		i++;
	}

	kfree(*root);
	*root = NULL;
	log_debug("Deleted %u nodes.", i + 1);
}

/**
 * TODO (performance) find offset using a normal trie find.
 */
int rtrie_foreach(struct rtrie_node *root,
		int (*cb)(void *, void *), void *arg,
		struct rtrie_key *offset)
{
	struct rtrie_node *node;
	int error;

	if (!root)
		return 0;

	if (offset) {
		if (key_equals(offset, &root->key))
			offset = NULL;
	} else if (root->color == COLOR_WHITE) {
		error = cb(root + 1, arg);
		if (error)
			return error;
	}

	list_for_each_entry(node, &root->list_hook, list_hook) {
		if (offset) {
			if (key_equals(offset, &node->key))
				offset = NULL;
		} else if (node->color == COLOR_WHITE) {
			error = cb(node + 1, arg);
			if (error)
				return error;
		}
	}

	return 0;
}

static char *color2str(enum rtrie_color color)
{
	switch (color) {
	case COLOR_WHITE:
		return "w";
	case COLOR_BLACK:
		return "b";
	}
	return "u";
}

static void print_node(struct rtrie_node *node, char *side, unsigned int level)
{
	unsigned int i, j;
	unsigned int remainder;

	if (!node)
		return;

	for (i = 0; i < level; i++)
		printk("| ");

	printk("(%s) ", color2str(node->color));

	for (i = 0; i < (node->key.len >> 3); i++)
		printk("%02x", node->key.bytes[i]);
	remainder = node->key.len & 7u;
	if (remainder) {
		printk(" ");
		for (j = 0; j < remainder; j++)
			printk("%u", (node->key.bytes[i] >> (7u - j)) & 1u);
	}

	printk(" (/%u)", node->key.len);

	printk("\n");

	print_node(node->left, "left", level + 1);
	print_node(node->right, "right", level + 1);
}

void rtrie_print(char *prefix, struct rtrie_node *root)
{
	printk(KERN_DEBUG "%s:\n", prefix);
	printk("-----------------------\n");
	if (root) {
		print_node(root, "root", 0);
	} else {
		printk("  (empty)\n");
	}
	printk("-----------------------\n");
}
