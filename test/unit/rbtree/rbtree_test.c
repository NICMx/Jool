#include <linux/module.h>
#include <linux/slab.h>

#include "nat64/unit/unit_test.h"
#include "nat64/mod/common/rbtree.h"


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
 * Returns > 0 if thing->i > i.
 * Returns < 0 if thing->i < i.
 * Returns zero if thing->i == i.
 */
static int compare(struct node_thing *thing, int i)
{
	return thing->i - i;
}

/**
 * Returns true if the @root tree contains only the nodes marked as true in the
 * @expecteds array.
 */
static bool check_nodes(struct rb_root *root, bool expecteds[4])
{
	struct node_thing *thing;
	struct rb_node *node;
	bool visited[4] = { false };
	int i, previous = -999;
	bool success = true;

	node = rb_first(root);
	while (node) {
		thing = rb_entry(node, struct node_thing, hook);
		success &= ASSERT_BOOL(true, previous <= thing->i,
				"Sort (%u %u)", previous, thing->i);
		visited[thing->i] = true;
		node = rb_next(node);
		previous = thing->i;
	}

	for (i = 0; i < 4; i++) {
		success &= ASSERT_BOOL(expecteds[i], visited[i],
				"Node %d visited", i);
	}

	return success;
}

static int add(struct rb_root *root, struct node_thing *node)
{
	return rbtree_add(node, node->i, root, compare, struct node_thing,
			hook);
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
		RB_CLEAR_NODE(&nodes[i].hook);
		expecteds[i] = false;
	}

	error = add(&root, &nodes[1]);
	success &= ASSERT_INT(0, error, "result");
	expecteds[1] = true;
	success &= check_nodes(&root, expecteds);
	if (!success)
		return false;

	error = add(&root, &nodes[3]);
	success &= ASSERT_INT(0, error, "result");
	expecteds[3] = true;
	success &= check_nodes(&root, expecteds);
	if (!success)
		return false;

	error = add(&root, &nodes[0]);
	success &= ASSERT_INT(0, error, "result");
	expecteds[0] = true;
	success &= check_nodes(&root, expecteds);
	if (!success)
		return false;

	error = add(&root, &nodes[2]);
	success &= ASSERT_INT(0, error, "result");
	expecteds[2] = true;
	success &= check_nodes(&root, expecteds);

	rb_erase(&nodes[2].hook, &root);
	expecteds[2] = false;
	success &= check_nodes(&root, expecteds);
	if (!success)
		return false;

	return success;
}

int init_module(void)
{
	START_TESTS("RB Tree");

	CALL_TEST(test_add_and_remove(), "Add/Remove Test");
	/*
	 * I'm lazy. The BIB and session modules already test the get functions
	 * and whatnot.
	 */

	END_TESTS;
}

void cleanup_module(void)
{
	/* No code. */
}
