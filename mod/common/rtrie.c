#include "nat64/mod/common/rtrie.h"
#include <linux/types.h> /* TODO this can be removed. */
#include <linux/slab.h>

static bool has_children(struct rtrie_node *node)
{
	/*
	 * As currently implemented, a fully-initialized node never has only
	 * one child.
	 */
	return node->left;
}

static bool is_leaf(struct rtrie_node *node)
{
	return !has_children(node);
}

static __u8 bits_to_bytes(__u8 bits)
{
	return (bits != 0) ? (((bits - 1) >> 3) + 1) : 0;
}

static struct rtrie_node *create_inode(__u8 *value, __u8 value_len)
{
	struct rtrie_node *inode;
	__u8 value_bytes;

	value_bytes = bits_to_bytes(value_len);
	inode = kmalloc(sizeof(*inode) + value_bytes, GFP_ATOMIC);
	if (!inode)
		return NULL;

	inode->left = NULL;
	inode->right = NULL;
	inode->parent = NULL;
	inode->string.bytes = (__u8 *) (inode + 1);
	inode->string.len = value_len;
	memcpy(inode->string.bytes, value, value_bytes);

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
	leaf->string.bytes = ((__u8 *) (leaf + 1)) + key_offset;
	leaf->string.len = key_len;
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

static bool rtree_node_equals(struct rtrie_node *n1, struct rtrie_node *n2)
{
	struct rtrie_string *s1 = &n1->string;
	struct rtrie_string *s2 = &n2->string;
	return (s1->len == s2->len) ? (match(s1, s2) == s1->len) : false;
}

/**
 * Returns the node from @root's trie which best matches @string, whether leaf
 * or inode.
 *
 * TODO test first bit doesn't match root
 * TODO test adding duplicate nodes
 */
static struct rtrie_node *find_longest_common_prefix(struct rtrie_node *root,
		struct rtrie_string *str, unsigned int *common_bits)
{
	struct rtrie_node *node = root;
	unsigned int node_match;
	unsigned int left_match;
	unsigned int right_match;

	node_match = match(&node->string, str);
	if (!node_match)
		return NULL;

	while (has_children(node)) {
		left_match = match(&node->left->string, str);
		right_match = match(&node->right->string, str);

		if (node_match == left_match && node_match == right_match) {
			break;
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

	*common_bits = node_match;
	return node;
}

static void rtrie_swap(struct rtrie_node **root, struct rtrie_node *old,
		struct rtrie_node *new)
{
	struct rtrie_node *parent = old->parent;

	if (!parent) {
		*root = new;
		return;
	}

	if (parent->left == old)
		parent->left = new;
	else
		parent->right = new;

	if (new)
		new->parent = parent;

	old->parent = NULL;
}

int rtrie_add(struct rtrie_node **root, void *content, size_t content_len,
		size_t key_offset, __u8 key_len)
{
	struct rtrie_node *sibling;
	struct rtrie_node *inode;
	struct rtrie_node *leaf;
	unsigned int common_bits;

	leaf = create_leaf(content, content_len, key_offset, key_len);
	if (!leaf)
		return -ENOMEM;

	if (!*root) {
		*root = leaf;
		return 0;
	}

	sibling = find_longest_common_prefix(*root, &leaf->string, &common_bits);
	if (!sibling) {
		sibling = *root;
		common_bits = 0;
	}
	if (is_leaf(sibling) && rtree_node_equals(sibling, leaf)) {
		kfree(leaf);
		return -EEXIST;
	}

	inode = create_inode(sibling->string.bytes, common_bits);
	if (!inode) {
		kfree(leaf);
		return -ENOMEM;
	}

	rtrie_swap(root, sibling, inode);
	sibling->parent = inode;
	leaf->parent = inode;
	inode->left = sibling;
	inode->right = leaf;

	return 0;
}

void *rtrie_get(struct rtrie_node *root, struct rtrie_string *key)
{
	struct rtrie_node *node;
	unsigned int common_bits;

	node = find_longest_common_prefix(root, key, &common_bits);

	if (!node)
		return NULL;
	if (has_children(node))
		return NULL; /* inodes aren't user entries. */

	return node + 1;
}

int rtrie_rm(struct rtrie_node **root, struct rtrie_string *key)
{
	/* TODO implement */
	/*
	struct rtrie_node *grandparent;
	struct rtrie_node *parent;
	struct rtrie_node *sibling;

	if (!node->parent) {
		*root = NULL;
		return;
	}
	*/

	/*
	 * Starting point:
	 *
	 * grandfather
	 *    |
	 *    +---- <whatever>
	 *    |
	 *    +---- parent
	 *             |
	 *             +---- sibling
	 *             |
	 *             +---- node
	 *
	 * Expected result:
	 *
	 * grandfather
	 *    |
	 *    +---- <whatever>
	 *    |
	 *    +---- sibling
	 */
	/*
	parent = node->parent;
	sibling = (parent->left == node) ? parent->right : parent->left;
	grandparent = parent->parent;

	if (grandparent) {
		if (grandparent->left == parent) {
			grandparent->left = sibling;
		} else {
			grandparent->right = sibling;
		}
	} else {
		*root = sibling;
	}
	*/
	return 0;
}

static struct rtrie_node *__flush(struct rtrie_node **root, struct rtrie_node *node)
{
	struct rtrie_node *parent = node->parent;
	rtrie_swap(root, node, NULL);
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

static void print_node(struct rtrie_node *node, unsigned int level)
{
	unsigned int i, j;
	unsigned int remainder;

	if (!node)
		return;

	for (i = 0; i < level; i++)
		printk("| ");

	for (i = 0; i < (node->string.len >> 3); i++)
		printk("%02x", node->string.bytes[i]);
	remainder = node->string.len & 7u;
	if (remainder) {
		printk(" ");
		for (j = 0; j < remainder; j++)
			printk("%u", (node->string.bytes[i] >> (7u - j)) & 1u);
	}

	printk("\n");

	print_node(node->left, level + 1);
	print_node(node->right, level + 1);
}

void rtrie_print(struct rtrie_node *root)
{
	printk(KERN_DEBUG "Printing trie!\n");
	if (root) {
		print_node(root, 0);
	} else {
		printk("  (empty)\n");
	}
}
