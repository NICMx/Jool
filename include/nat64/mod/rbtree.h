#ifndef _JOOL_MOD_RBTREE_H
#define _JOOL_MOD_RBTREE_H

/**
 * @file
 * This is just some convenience additions to the kernel's Red-Black Tree data structure.
 * I'm sorry it looks rather convoluted, but the alternative is a lot of redundant code.
 * Constructive criticism would be very appreciated.
 *
 * @author Alberto Leiva
 * @author Daniel Hernandez
 */

#include "linux/rbtree.h"

/**
 * This is just a stock search on a Red-Black tree.
 *
 * I can't find a way to turn this into a function; if you want to read a cleaner version of it,
 * see https://www.kernel.org/doc/Documentation/rbtree.txt.
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
				node = node->rb_left; \
			} else if (comparison > 0) { \
				node = node->rb_right; \
			} else { \
				result = entry; \
				break; \
			} \
		} \
		\
		result; \
	})

/**
 * This is just a stock add a node to a Red-Black tree.
 *
 * I can't find a way to turn this into a function; if you want to read a cleaner version of it,
 * see https://www.kernel.org/doc/Documentation/rbtree.txt.
 */
#define rbtree_add(entry, field, root, compare_fn, type, hook_name) \
	({ \
		struct rb_node **new = &((root)->rb_node), *parent = NULL; \
		int error = 0; \
		\
		/* Figure out where to put new node */ \
		while (*new) { \
			type *this = rb_entry(*new, type, hook_name); \
			int result = compare_fn(this, &(entry)->field); \
			\
			parent = *new; \
			if (result < 0) { \
				new = &((*new)->rb_left); \
			} else if (result > 0) { \
				new = &((*new)->rb_right); \
			} else { \
				error = -EEXIST; \
				break; \
			} \
		} \
		\
		/* Add new node and rebalance tree. */ \
		if (!error) { \
			rb_link_node(&(entry)->hook_name, parent, new); \
			rb_insert_color(&(entry)->hook_name, root); \
		} \
		\
		error; \
	})

/**
  * Similar to rbtree_find(), except if it doesn't find the node it returns the slot where it'd be
  * placed so you can insert something in there.
  */
#define rbtree_find_node(expected, root, compare_cb, type, hook_name, parent, node) \
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
				node = &((*node)->rb_left); \
			} else if (comparison > 0) { \
				node = &((*node)->rb_right); \
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
