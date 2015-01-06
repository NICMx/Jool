#include "nat64/mod/common/rbtree.h"

void rbtree_clear(struct rb_root *root, void (*destructor)(struct rb_node *))
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
		destructor(current_hook);

		current_hook = parent_hook;
	}

	(root)->rb_node = NULL;
}
