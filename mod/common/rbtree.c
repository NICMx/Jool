#include "nat64/mod/common/rbtree.h"

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

void rbtree_clear(struct rb_root *root,
		void (*destructor)(struct rb_node *, void *),
		void *arg)
{
	/* ... using a postorder traversal. */
	struct rb_node *parent_hook, *current_hook;

	current_hook = rb_first(root);

	while (current_hook) {
		while (current_hook->rb_right) {
			current_hook = current_hook->rb_right;
			while (current_hook->rb_left)
				current_hook = current_hook->rb_left;
		}

		parent_hook = rb_parent(current_hook);

		if (parent_hook) {
			if (current_hook == parent_hook->rb_left)
				parent_hook->rb_left = NULL;
			else /* if (current_hook == parent_hook->rb_right) */
				parent_hook->rb_right = NULL;
		}
		destructor(current_hook, arg);

		current_hook = parent_hook;
	}

	(root)->rb_node = NULL;
}
