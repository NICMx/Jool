#include <linux/module.h>
#include <linux/slab.h>

#include "nat64/mod/common/linux_version.h"
#if LINUX_VERSION_AT_LEAST(3, 7, 0, 0, 0)
#include <linux/rbtree_augmented.h>
#endif

#include "nat64/unit/unit_test.h"
#include "nat64/mod/common/rbtree.h"


MODULE_LICENSE(JOOL_LICENSE);
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

static struct node_thing *add(struct rb_root *root, struct node_thing *node)
{
	return rbtree_add(node, node->i, root, compare, struct node_thing,
			hook);
}

static bool test_add_and_remove(void)
{
	struct rb_root root = RB_ROOT;
	struct node_thing nodes[4];
	bool expecteds[4];
	int i;
	struct node_thing *exists;
	bool success = true;

	for (i = 0; i < ARRAY_SIZE(nodes); i++) {
		nodes[i].i = i;
		RB_CLEAR_NODE(&nodes[i].hook);
		expecteds[i] = false;
	}

	exists = add(&root, &nodes[1]);
	success &= ASSERT_PTR(NULL, exists, "exists 1");
	expecteds[1] = true;
	success &= check_nodes(&root, expecteds);
	if (!success)
		return false;

	exists = add(&root, &nodes[3]);
	success &= ASSERT_PTR(NULL, exists, "exists 2");
	expecteds[3] = true;
	success &= check_nodes(&root, expecteds);
	if (!success)
		return false;

	exists = add(&root, &nodes[0]);
	success &= ASSERT_PTR(NULL, exists, "exists 3");
	expecteds[0] = true;
	success &= check_nodes(&root, expecteds);
	if (!success)
		return false;

	exists = add(&root, &nodes[2]);
	success &= ASSERT_PTR(NULL, exists, "exists 4");
	expecteds[2] = true;
	success &= check_nodes(&root, expecteds);

	rb_erase(&nodes[2].hook, &root);
	expecteds[2] = false;
	success &= check_nodes(&root, expecteds);
	if (!success)
		return false;

	return success;
}

struct foreach_arg {
	int expected[16];
	int iteration;
	int success;
};

void cb(struct rb_node *node, void *void_arg)
{
	struct node_thing *thing;
	struct foreach_arg *arg = void_arg;

	if (!arg->success)
		return;

	arg->success = ASSERT_BOOL(true, arg->iteration < 16, "iteration count");
	if (!arg->success)
		return;

	thing = rb_entry(node, struct node_thing, hook);
	arg->success = ASSERT_INT(arg->expected[arg->iteration], thing->i,
			"iteration %u", arg->iteration);

	arg->iteration++;
}

struct node_thing fnodes[16];

static void define_node(int node, int parent, int left, int right)
{
	if (parent != -1)
		rb_set_parent(&fnodes[node].hook, &fnodes[parent].hook);
	if (left != -1)
		fnodes[node].hook.rb_left = &fnodes[left].hook;
	if (right != -1)
		fnodes[node].hook.rb_right = &fnodes[right].hook;
}

static bool test_foreach(void)
{
	struct rb_root root = RB_ROOT;
	struct foreach_arg arg;
	unsigned int i;

	/*
	 *          4
	 *        +-+-------+
	 *        3         8
	 *  +-----+       +-+-------+
	 *  0             7         c
	 *  +-+         +-+     +---+---+
	 *    1         6       a       e
	 *    +-+     +-+     +-+-+   +-+-+
	 *      2     5       9   b   d   f
	 *
	 * Hopefully that's all the combinations plus some noise.
	 */

	memset(&fnodes, 0, sizeof(fnodes));
	for (i = 0; i < ARRAY_SIZE(fnodes); i++)
		fnodes[i].i = i;

	/* I don't use rbtree_add() because it autobalances. */
	root.rb_node = &fnodes[4].hook;
	define_node(0, 3, -1, 1);
	define_node(1, 0, -1, 2);
	define_node(2, 1, -1, -1);
	define_node(3, 4, 0, -1);
	define_node(4, -1, 3, 8);
	define_node(5, 6, -1, -1);
	define_node(6, 7, 5, -1);
	define_node(7, 8, 6, -1);
	define_node(8, 4, 7, 12);
	define_node(9, 10, -1, -1);
	define_node(10, 12, 9, 11);
	define_node(11, 10, -1, -1);
	define_node(12, 8, 10, 14);
	define_node(13, 14, -1, -1);
	define_node(14, 12, 13, 15);
	define_node(15, 14, -1, -1);

	arg.expected[0] = 2;
	arg.expected[1] = 1;
	arg.expected[2] = 0;
	arg.expected[3] = 3;
	arg.expected[4] = 5;
	arg.expected[5] = 6;
	arg.expected[6] = 7;
	arg.expected[7] = 9;
	arg.expected[8] = 0xb;
	arg.expected[9] = 0xa;
	arg.expected[10] = 0xd;
	arg.expected[11] = 0xf;
	arg.expected[12] = 0xe;
	arg.expected[13] = 0xc;
	arg.expected[14] = 8;
	arg.expected[15] = 4;
	arg.iteration = 0;
	arg.success = true;
	rbtree_foreach(&root, cb, &arg);

	return arg.success;
}

int init_module(void)
{
	struct test_group test = {
		.name = "RB Tree",
	};

	if (test_group_begin(&test))
		return -EINVAL;

	test_group_test(&test, test_add_and_remove, "Add/Remove Test");
	test_group_test(&test, test_foreach, "Foreach Test");
	/*
	 * I'm lazy. The BIB and session modules already test the get functions
	 * and whatnot.
	 */

	return test_group_end(&test);
}

void cleanup_module(void)
{
	/* No code. */
}
