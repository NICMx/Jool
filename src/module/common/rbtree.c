#include "rbtree.h"
#include <linux/module.h>

void treeslot_init(struct tree_slot *slot,
		struct rb_root *root,
		struct rb_node *entry)
{
	slot->tree = root;
	slot->entry = entry;
	slot->parent = NULL;
	slot->rb_link = &root->rb_node;
}

void treeslot_commit(struct tree_slot *slot)
{
	rb_link_node(slot->entry, slot->parent, slot->rb_link);
	rb_insert_color(slot->entry, slot->tree);
}

/*
 * Safe postorder traversal.
 *
 * I know the kernel has something called rbtree_postorder_for_each_entry_safe.
 * It's just not available until Linux 3.12.
 */
void rbtree_foreach(struct rb_root *root, void (*cb)(struct rb_node *, void *),
		void *arg)
{
	struct rb_node *parent, *node;

	parent = NULL;
	node = root->rb_node;

	while (node) {
		/*
		 * Keep going down as much as possible.
		 * Left is always preferred.
		 */
		while (node->rb_left || node->rb_right) {
			parent = node;
			node = node->rb_left ? : node->rb_right;
		}

		/* We found a childless node; callback. */
		cb(node, arg);

		/*
		 * Keep going up, callbacking nodes until we find an unvisited
		 * sibling subtree.
		 */
		do {
			if (!parent)
				return;

			if (node == parent->rb_left) {
				if (parent->rb_right) {
					node = parent->rb_right;
					break;
				}
				cb(parent, arg);
			} else if (node == parent->rb_right) {
				cb(parent, arg);
			} else {
				WARN(true, "Bug: Parent got messed up during traversal");
				return;
			}

			node = parent;
			parent = rb_parent(node);
		} while (true);
	}
}

void rbtree_clear(struct rb_root *root,
		void (*destructor)(struct rb_node *, void *),
		void *arg)
{
	rbtree_foreach(root, destructor, arg);
	root->rb_node = NULL;
}
