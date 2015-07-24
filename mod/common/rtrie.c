#include "nat64/mod/common/rtrie.h"
#include "nat64/mod/common/types.h" /* TODO this can be removed. */
#include <linux/slab.h>

static __u8 bits_to_bytes(__u8 bits)
{
	return (bits != 0) ? (((bits - 1) >> 3) + 1) : 0;
}

static struct rtrie_node *create_inode(struct rtrie_string *key,
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
	inode->color = COLOR_BLACK;
	/* This means a black node cannot be upgraded into a white one. */
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
	leaf->color = COLOR_WHITE;
	leaf->key.bytes = ((__u8 *) (leaf + 1)) + key_offset;
	leaf->key.len = key_len;
	memcpy(leaf + 1, content, content_len);

	return leaf;
}

static unsigned int get_bit(__u8 byte, unsigned int pos)
{
	return (byte >> (7 - pos)) & 1;
}

/**
 * match - Returns the number of prefix bits @str1 and @str have in common.
 */
static unsigned int match(struct rtrie_string *str1, struct rtrie_string *str2)
{
	unsigned int result = 0;
	unsigned int y, i; /* b[y]te counter, b[i]t counter. */
	unsigned int bytes, bits;
	unsigned int bit1, bit2;

	bits = min(str1->len, str2->len);
	bytes = bits >> 3; /* >> 3 = / 8*/
	bits &= 7; /* & 7 = % 8 */

	for (y = 0; y < bytes; y++) {
		if (str1->bytes[y] != str2->bytes[y]) {
			bits = 8;
			break;
		}
		result += 8;
	}

	for (i = 0; i < bits; i++) {
		bit1 = get_bit(str1->bytes[y], i);
		bit2 = get_bit(str2->bytes[y], i);

		if (bit1 != bit2)
			break;

		result++;
	}

	return result;
}

static bool contains(struct rtrie_string *str1, struct rtrie_string *str2)
{
	return (match(str1, str2) >= str1->len);
}

static bool key_equals(struct rtrie_string *str1, struct rtrie_string *str2)
{
	return (str1->len == str2->len)
			? (match(str1, str2) == str1->len)
			: false;
}

/**
 * find_longest_common_prefix - Returns the node from @root's trie which best
 * matches @string, whether leaf or inode.
 *
 * TODO test first bit doesn't match root
 * TODO test adding duplicate nodes
 */
static struct rtrie_node *find_longest_common_prefix(struct rtrie_node *root,
		struct rtrie_string *str)
{
	struct rtrie_node *node;

	node = root;
	if (!node || !contains(&node->key, str))
		return NULL;

	do {
		if (node->left && contains(&node->left->key, str)) {
			node = node->left;
			continue;
		}

		if (node->right && contains(&node->right->key, str)) {
			node = node->right;
			continue;
		}

		return node;
	} while (true);

	return NULL; /* <-- Shuts up Eclipse. */
}

/**
 * find_white - Returns the *white* node from @root's trie which best matches
 * @string.
 *
 * TODO fuse with the previous function?
 */
static struct rtrie_node *find_white(struct rtrie_node *root,
		struct rtrie_string *str)
{
	struct rtrie_node *node;
	struct rtrie_node *last_white;

	node = root;
	if (!node || !contains(&node->key, str))
		return NULL;

	last_white = NULL;
	do {
		if (node->color == COLOR_WHITE)
			last_white = node;

		if (node->left && contains(&node->left->key, str)) {
			node = node->left;
			continue;
		}

		if (node->right && contains(&node->right->key, str)) {
			node = node->right;
			continue;
		}

		return last_white;
	} while (true);

	return NULL; /* <-- Shuts up Eclipse. */
}

/**
 * @node must not be NULL.
 */
struct rtrie_node *get_parent(struct rtrie_node *root,
		struct rtrie_node *child)
{
	struct rtrie_node *node;

	node = root;
	if (!node || node == child || !contains(&node->key, &child->key))
		return NULL;

	do {
		if (node->left == child || node->right == child)
			return node;

		if (node->left && contains(&node->left->key, &child->key)) {
			node = node->left;
			continue;
		}

		if (node->right && contains(&node->right->key, &child->key)) {
			node = node->right;
			continue;
		}

		break;
	} while (true);

	return NULL;
}

struct rtrie_node **get_parent_ptr(struct rtrie_node **root,
		struct rtrie_node *parent,
		struct rtrie_node *node)
{
	if (!parent)
		return root;
	return (parent->left == node) ? &parent->left : &parent->right;
}

static void swap_nodes(struct rtrie_node **root, struct rtrie_node *old,
		struct rtrie_node *new)
{
	struct rtrie_node *parent;
	struct rtrie_node **parent_ptr;

	new->left = old->left;
	new->right = old->right;

	parent = get_parent(*root, old);
	parent_ptr = get_parent_ptr(root, parent, old);
	(*parent_ptr) = new;

	kfree(old);
}

static int add_to_root(struct rtrie_node **root, struct rtrie_node *new)
{
	struct rtrie_node *inode;
	struct rtrie_string key;

	if (!*root) {
		*root = new;
		return 0;
	}

	key.bytes = new->key.bytes;
	key.len = match(&(*root)->key, &new->key);

	inode = create_inode(&key, *root, new);
	if (!inode)
		return -ENOMEM;

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
	struct rtrie_string inode_prefix;

	unsigned int match_lr = match(&parent->left->key, &parent->right->key);
	unsigned int match_ln = match(&parent->left->key, &new->key);
	unsigned int match_rn = match(&parent->right->key, &new->key);

	if (match_lr > match_ln && match_lr > match_rn) {
		smallest_prefix = new;
		higher_prefix1 = parent->left;
		higher_prefix2 = parent->right;
		inode_prefix.len = match_ln;
	} else if (match_ln > match_lr && match_ln > match_rn) {
		smallest_prefix = parent->right;
		higher_prefix1 = new;
		higher_prefix2 = parent->left;
		inode_prefix.len = match_lr;
	} else if (match_rn > match_lr && match_rn > match_ln) {
		smallest_prefix = parent->left;
		higher_prefix1 = new;
		higher_prefix2 = parent->right;
		inode_prefix.len = match_lr;
	} else {
		/* TODO improve error msg. */
		WARN(true, "Inconsistent bwrtrie.");
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

	parent = find_longest_common_prefix(*root, &new->key);
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
		return 0;
	}
	if (!parent->right) {
		parent->right = new;
		return 0;
	}

	contains_left = contains(&new->key, &parent->left->key);
	contains_right = contains(&new->key, &parent->right->key);

	if (contains_left && contains_right) {
		if (parent->color == COLOR_BLACK) {
			swap_nodes(root, parent, new);
			return 0;
		}
		new->left = parent->left;
		new->right = parent->right;
		parent->left = NULL;
		parent->right = new;
		return 0;
	}

	if (contains_left) {
		new->left = parent->left;
		parent->left = new;
		return 0;
	}
	if (contains_right) {
		new->right = parent->right;
		parent->right = new;
		return 0;
	}

	return add_full_collision(parent, new);
}

void *rtrie_get(struct rtrie_node *root, struct rtrie_string *key)
{
	struct rtrie_node *node = find_white(root, key);
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
		parent = get_parent(*root, node);
		parent_ptr = get_parent_ptr(root, parent, node);

		if (node->left) {
			(*parent_ptr) = node->left;
			kfree(node);
			return 0;
		}

		if (node->right) {
			(*parent_ptr) = node->right;
			kfree(node);
			return 0;
		}

		(*parent_ptr) = NULL;
		kfree(node);
		node = parent;
	}

	return 0;
}

int rtrie_rm(struct rtrie_node **root, struct rtrie_string *key)
{
	struct rtrie_node *parent;
	struct rtrie_node **parent_ptr;
	struct rtrie_node *node;

	node = find_white(*root, key);
	if (!node)
		return -ESRCH;
	if (match(&node->key, key) != key->len)
		return -ESRCH;

	if (node->left && node->right) {
		node->color = COLOR_BLACK;
		return 0;
	}

	parent = get_parent(*root, node);
	parent_ptr = get_parent_ptr(root, parent, node);

	if (node->left) {
		(*parent_ptr) = node->left;
		kfree(node);
		return 0;
	}

	if (node->right) {
		(*parent_ptr) = node->right;
		kfree(node);
		return 0;
	}

	(*parent_ptr) = NULL;
	kfree(node);

	return prune_if_black(root, parent);
}

struct rtrie_node *__flush(struct rtrie_node **root,
		struct rtrie_node *node)
{
	struct rtrie_node *parent;
	struct rtrie_node **parent_ptr;

	parent = get_parent(*root, node);
	parent_ptr = get_parent_ptr(root, parent, node);
	(*parent_ptr) = NULL;

	kfree(node);
	return parent;
}

void rtrie_flush(struct rtrie_node **root)
{
	struct rtrie_node *node = *root;

	while (node) {
		if (node->left)
			node = node->left;
		else if (node->right)
			node = node->right;
		else
			node = __flush(root, node);
	}

	*root = NULL;
}

static void print_node(struct rtrie_node *node, char *side, unsigned int level)
{
	unsigned int i, j;
	unsigned int remainder;

	if (!node)
		return;

	for (i = 0; i < level; i++)
		printk("| ");

	for (i = 0; i < (node->key.len >> 3); i++)
		printk("%02x", node->key.bytes[i]);
	remainder = node->key.len & 7u;
	if (remainder) {
		printk(" ");
		for (j = 0; j < remainder; j++)
			printk("%u", (node->key.bytes[i] >> (7u - j)) & 1u);
	}

	printk("\n");

	print_node(node->left, "left", level + 1);
	print_node(node->right, "right", level + 1);
}

void rtrie_print(struct rtrie_node *root)
{
	printk(KERN_DEBUG "Printing trie!\n");
	if (root) {
		print_node(root, "root", 0);
	} else {
		printk("  (empty)\n");
	}
}
