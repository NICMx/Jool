#ifndef _JOOL_MOD_RBTREE_H
#define _JOOL_MOD_RBTREE_H

/**
 * @file
 * This is just some convenience additions to the kernel's Red-Black Tree
 * implementation.
 * I'm sorry it's a macro maze, but the alternative is a lot of redundant code.
 */

#include <linux/rbtree.h>

/**
 * rbtree_find - Stock search on a Red-Black tree.
 *
 * If you want to read a cleaner version of it, see
 * https://www.kernel.org/doc/Documentation/rbtree.txt
 */
#define rbtree_find(expected, root, compare_fn, type, hook_name) \
	({ \
		type *result = NULL; \
		struct rb_node *node; \
		\
		node = (root)->rb_node; \
		while (node) { \
			type *entry = rb_entry(node, type, hook_name); \
			int comparison = compare_fn(entry, expected); \
			\
			if (comparison < 0) { \
				node = node->rb_right; \
			} else if (comparison > 0) { \
				node = node->rb_left; \
			} else { \
				result = entry; \
				break; \
			} \
		} \
		\
		result; \
	})

/**
 * rbtree_add - Add a node to a Red-Black tree.
 *
 * Returns NULL on success. If there was a collision, it returns the in-tree
 * entry that caused it. There are no other possible outcomes.
 *
 * If you want to read a cleaner version of it, see
 * https://www.kernel.org/doc/Documentation/rbtree.txt
 */
#define rbtree_add(entry, key, root, compare_fn, type, hook_name) \
	({ \
		struct rb_node **new = &((root)->rb_node), *parent = NULL; \
		type *collision = NULL; \
		\
		/* Figure out where to put new node */ \
		while (*new) { \
			type *this = rb_entry(*new, type, hook_name); \
			int result = compare_fn(this, key); \
			\
			parent = *new; \
			if (result < 0) { \
				new = &((*new)->rb_right); \
			} else if (result > 0) { \
				new = &((*new)->rb_left); \
			} else { \
				collision = this; \
				break; \
			} \
		} \
		\
		/* Add new node and rebalance tree. */ \
		if (!collision) { \
			rb_link_node(&(entry)->hook_name, parent, new); \
			rb_insert_color(&(entry)->hook_name, root); \
		} \
		\
		collision; \
	})

/**
  * rbtree_find_node - Similar to rbtree_find(), except if it doesn't find the
  * node it returns the slot where it'd be placed so you can insert something in
  * there.
  */
#define rbtree_find_node(expected, root, compare_cb, type, hook_name, parent, \
		node) \
	({ \
		node = &((root)->rb_node); \
		parent = NULL; \
		\
		/* Figure out where to put new node */ \
		while (*node) { \
			type *entry = rb_entry(*node, type, hook_name); \
			int comparison = compare_cb(entry, expected); \
			\
			parent = *node; \
			if (comparison < 0) { \
				node = &((*node)->rb_right); \
			} else if (comparison > 0) { \
				node = &((*node)->rb_left); \
			} else { \
				break; \
			} \
		} \
	})

/**
 * Destroys all the nodes from "root"'s tree.
 */
void rbtree_clear(struct rb_root *root, void (*destructor)(struct rb_node *));

#endif /* _JOOL_MOD_RBTREE_H */
