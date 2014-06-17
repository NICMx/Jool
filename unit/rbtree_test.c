#include <linux/module.h>
#include <linux/slab.h>

#include "nat64/unit/unit_test.h"
#include "nat64/mod/rbtree.h"


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Alberto Leiva");
MODULE_DESCRIPTION("RB Tree module test");


/**
 * Actual data nodes we'll be inserting into the tree.
 */
struct node_thing {
	int i;
	struct rb_node hook;
};

/**
 * Returns a positive integer if thing->i < i.
 * Returns a negative integer if thing->i > i.
 * Returns zero if thing->i == i.
 */
static int compare(struct node_thing *thing, int *i)
{
	return (*i) - thing->i;
}

/**
 * Returns true if the "root" tree contains only the nodes marked as true in the "expecteds" array.
 */
static bool check_nodes(struct rb_root *root, bool expecteds[4])
{
	struct rb_node *node;
	bool visited[4] = { false };
	int i;

	node = rb_first(root);
	while (node) {
		struct node_thing *thing = rb_entry(node, struct node_thing, hook);
		if (!expecteds[thing->i]) {
			log_debug("I didn't expect node %d, but I found it.", thing->i);
			return false;
		}
		visited[thing->i] = true;
		node = rb_next(node);
	}

	for (i = 0; i < 4; i++) {
		if (expecteds[i] && !visited[i]) {
			log_debug("I expected node %d, but I didn't find it.", i);
			return false;
		}
	}

	return true;
}

static bool test_add_and_remove(void)
{
	struct rb_root root = RB_ROOT;
	struct node_thing nodes[4];
	bool expecteds[4];
	int i, error;
	bool success = true;

	for (i = 0; i < ARRAY_SIZE(nodes); i++) {
		nodes[i].i = i;
		rb_init_node(&nodes[i].hook);
		expecteds[i] = false;
	}

	error = rbtree_add(&nodes[1], i, &root, compare, struct node_thing, hook);
	success &= assert_equals_int(0, error, "result");
	expecteds[1] = true;
	success &= check_nodes(&root, expecteds);
	if (!success)
		return false;

	error = rbtree_add(&nodes[3], i, &root, compare, struct node_thing, hook);
	success &= assert_equals_int(0, error, "result");
	expecteds[3] = true;
	success &= check_nodes(&root, expecteds);
	if (!success)
		return false;

	error = rbtree_add(&nodes[0], i, &root, compare, struct node_thing, hook);
	success &= assert_equals_int(0, error, "result");
	expecteds[0] = true;
	success &= check_nodes(&root, expecteds);
	if (!success)
		return false;

	error = rbtree_add(&nodes[2], i, &root, compare, struct node_thing, hook);
	success &= assert_equals_int(0, error, "result");
	expecteds[2] = true;
	success &= check_nodes(&root, expecteds);

	rb_erase(&nodes[2].hook, &root);
	expecteds[2] = false;
	success &= check_nodes(&root, expecteds);

	return success;
}

int init_module(void)
{
	START_TESTS("RB Tree");

	CALL_TEST(test_add_and_remove(), "Add/Remove Test");
	/* TODO (test) test the get functions? */

	END_TESTS;
}

void cleanup_module(void)
{
	/* No code. */
}
