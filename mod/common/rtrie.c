#include "nat64/mod/common/rtrie.h"

void rtrie_node_init(struct rtrie_node *node, bool is_leaf)
{
	node->is_leaf = is_leaf;
	node->left = NULL;
	node->right = NULL;
	node->parent = NULL;
}

void rtrie_swap(struct rtrie_node **root, struct rtrie_node *old,
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

void add_common(struct rtrie_node **root, struct rtrie_node *node,
		struct rtrie_node *new_inode, struct rtrie_node *new_node)
{
	rtrie_swap(root, node, new_inode);

	node->parent = new_inode;
	new_node->parent = new_inode;
}

//#include "nat64/mod/common/types.h"

void rtrie_add_left(struct rtrie_node **root, struct rtrie_node *node,
		struct rtrie_node *new_inode, struct rtrie_node *new_node)
{
	add_common(root, node, new_inode, new_node);

	new_inode->left = new_node;
	new_inode->right = node;
}

void rtrie_add_right(struct rtrie_node **root, struct rtrie_node *node,
		struct rtrie_node *new_inode, struct rtrie_node *new_node)
{
	add_common(root, node, new_inode, new_node);

	new_inode->left = node;
	new_inode->right = new_node;
}

void rtrie_rm(struct rtrie_node **root, struct rtrie_node *node)
{
	struct rtrie_node *grandparent;
	struct rtrie_node *parent;
	struct rtrie_node *sibling;

	if (!node->parent) {
		*root = NULL;
		return;
	}

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
}
