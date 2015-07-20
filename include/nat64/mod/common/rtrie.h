#ifndef _JOOL_MOD_RTRIE_H
#define _JOOL_MOD_RTRIE_H

#include <linux/types.h>

struct rtrie_node {
	bool is_leaf;
	struct rtrie_node *left;
	struct rtrie_node *right;
	struct rtrie_node *parent;
};

void rtrie_node_init(struct rtrie_node *node, bool is_leaf);

void rtrie_swap(struct rtrie_node **root, struct rtrie_node *old,
		struct rtrie_node *new);
void rtrie_add_left(struct rtrie_node **root, struct rtrie_node *node,
		struct rtrie_node *new_inode, struct rtrie_node *new_node);
void rtrie_add_right(struct rtrie_node **root, struct rtrie_node *node,
		struct rtrie_node *new_inode, struct rtrie_node *new_node);
void rtrie_rm(struct rtrie_node **root, struct rtrie_node *node);

#endif /* _JOOL_MOD_RTRIE_H */
