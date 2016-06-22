#include "nat64/mod/stateful/session/table4.h"

#include "nat64/mod/common/rbtree.h"

struct session_table4 {
	struct rb_root tree;
};

static struct session_entry *st4_entry(struct rb_node *node)
{
	return rb_entry(node, struct session_entry, tree4_hook);
}

struct session_table4 *st4_create(void)
{
	struct session_table4 *table;

	table = kmalloc(sizeof(struct session_table4), GFP_ATOMIC);
	if (!table)
		return NULL;
	table->tree.rb_node = NULL;
	return table;
}

/**
 * Does not destroy the nodes!
 * (Because they are shared with other indexes.)
 */
void st4_destroy(struct session_table4 *table)
{
	kfree(table);
}

static int compare_addr4(const struct ipv4_transport_addr *a1,
		const struct ipv4_transport_addr *a2)
{
	int gap;

	gap = ipv4_addr_cmp(&a1->l3, &a2->l3);
	if (gap)
		return gap;

	gap = ((int)a1->l4) - ((int)a2->l4);
	return gap;
}

static int compare_tuple_bib(const struct session_entry *session,
		const struct tuple *tuple4)
{
	return compare_addr4(&session->src4, &tuple4->dst.addr4);
}

static int compare_tuple_allow(const struct session_entry *session,
		const struct tuple *tuple4)
{
	return ipv4_addr_cmp(&session->dst4.l3, &tuple4->src.addr4.l3);
}

static int compare_tuple_session(const struct session_entry *session,
		const struct tuple *tuple4)
{
	return ((int)session->dst4.l4) - ((int)tuple4->src.addr4.l4);
}

static int compare_bib(const struct session_entry *a,
		const struct session_entry *b)
{
	return compare_addr4(&a->src4, &b->src4);
}

static int compare_allow(const struct session_entry *a,
		const struct session_entry *b)
{
	return ipv4_addr_cmp(&a->dst4.l3, &b->dst4.l3);
}

static int compare_session(const struct session_entry *a,
		const struct session_entry *b)
{
	return ((int)a->dst4.l4) - ((int)b->dst4.l4);
}

static int compare_src4(const struct session_entry *a,
		const struct ipv4_transport_addr *b)
{
	return compare_addr4(&a->src4, b);
}

static void session2bib(struct session_entry *session,
		struct bib_entry *bib)
{
	if (bib) {
		bib->ipv6 = session->src6;
		bib->ipv4 = session->src4;
		bib->l4_proto = session->l4_proto;
	}
}

struct session_entry *st4_find(struct session_table4 *table,
		struct tuple *tuple4)
{
	struct session_entry *result;
	bool allow;
	int error;

	error = st4_find_full(table, tuple4, NULL, &result, &allow);
	return error ? NULL : result;
}

#define rbtree_find4(tuple, tree, compare_cb) \
	rbtree_find(tuple, tree, compare_cb, struct session_entry, tree4_hook)

/**
 * @bib is optional.
 */
int st4_find_full(struct session_table4 *table, struct tuple *tuple4,
		struct bib_entry *bib, struct session_entry **session,
		bool *allow)
{
	struct session_entry *tmp;

	*allow = false;
	*session = NULL;

	tmp = rbtree_find4(tuple4, &table->tree, compare_tuple_bib);
	if (!tmp)
		return -ESRCH;
	session2bib(tmp, bib);

	/* We know tuple4.dst4 == tmp.src4 at this point. */

	if (tuple4->src.addr4.l3.s_addr != tmp->dst4.l3.s_addr) {
		tmp = rbtree_find4(tuple4, &tmp->tree4l2, compare_tuple_allow);
		if (!tmp)
			return 0; /* @bib is the closest thing we have. */
	}

	/*
	 * We know tuple4.dst4 == tmp.src4 and tuple4.src4.l3 == tmp.dst4.l3
	 * at this point.
	 */

	*allow = true;
	if (tuple4->src.addr4.l4 == tmp->dst4.l4) {
		*session = tmp;
		return 0;
	}

	*session = rbtree_find4(tuple4, &tmp->tree4l3, compare_tuple_session);
	return 0;
}

int st4_find_bib(struct session_table4 *table, struct tuple *tuple4,
		struct bib_entry *bib)
{
	struct session_entry *session;

	session = rbtree_find4(tuple4, &table->tree, compare_tuple_bib);
	if (!session)
		return -ESRCH;

	session2bib(session, bib);
	return 0;
}

#define add4(session, tree, compare_cb) \
	rbtree_add(session, session, tree, compare_cb, struct session_entry, \
			tree4_hook)

/**
 * If there's a collision, returns the colliding session.
 * If the add was successful, returns NULL.
 */
struct session_entry *st4_add(struct session_table4 *table,
		struct session_entry *session)
{
	struct session_entry *clash;

	clash = add4(session, &table->tree, compare_bib);
	if (!clash)
		return NULL;

	if (session->dst4.l3.s_addr != clash->dst4.l3.s_addr) {
		clash = add4(session, &clash->tree4l2, compare_allow);
		if (!clash)
			return NULL;
	}

	if (session->dst4.l4 == clash->dst4.l4)
		return clash;

	return add4(session, &clash->tree4l3, compare_session);
}

static struct rb_root *find_root(struct session_table4 *table,
		struct session_entry *session)
{
	struct session_entry *found;
	struct rb_root *root;

	found = rbtree_find4(session, &table->tree, compare_bib);
	if (unlikely(!found))
		return NULL;
	if (session == found)
		return &table->tree;

	if (session->dst4.l3.s_addr == found->dst4.l3.s_addr)
		return &found->tree4l3;

	root = &found->tree4l2;
	found = rbtree_find4(session, root, compare_allow);
	if (unlikely(!found))
		return NULL;
	return (session == found) ? root : &found->tree4l3;
}

/**
 * If @session does not belong to @table, you can kiss your kernel stability
 * goodbye.
 * Yes, there are some validations, but not everywhere.
 */
void st4_rm(struct session_table4 *table, struct session_entry *session)
{
	struct session_entry *replacement;
	struct rb_root *root;

	root = find_root(table, session);
	if (WARN(!root, "Trying to detach a treeless session"))
		return;

	if (!RB_EMPTY_ROOT(&session->tree4l3)) {
		replacement = st4_entry(session->tree4l3.rb_node);
		rb_erase(&replacement->tree4_hook, &session->tree4l3);
		rb_replace_node(&session->tree4_hook,
				&replacement->tree4_hook,
				root);
		/* Layer 3 nodes never carry subtrees. */
		replacement->tree4l2.rb_node = session->tree4l2.rb_node;
		replacement->tree4l3.rb_node = session->tree4l3.rb_node;
		return;
	}

	if (!RB_EMPTY_ROOT(&session->tree4l2)) {
		replacement = st4_entry(session->tree4l2.rb_node);
		rb_erase(&replacement->tree4_hook, &session->tree4l2);
		rb_replace_node(&session->tree4_hook,
				&replacement->tree4_hook,
				root);
		/* Layer 2 nodes never carry Layer 2 subtrees. */
		replacement->tree4l2.rb_node = session->tree4l2.rb_node;
		return;
	}

	rb_erase(&session->tree4_hook, root);
}

void st4_flush(struct session_table4 *table)
{
	table->tree.rb_node = NULL;
}

static void prune_l3(struct rb_node *node, void *arg)
{
	struct destructor_arg *destructor = arg;
	destructor->cb(st4_entry(node), destructor->arg);
}

static void prune_l2(struct rb_node *node, void *arg)
{
	struct destructor_arg *destructor = arg;
	struct session_entry *session = st4_entry(node);
	rbtree_clear(&session->tree4l3, prune_l3, destructor);
	destructor->cb(session, destructor->arg);
}

void st4_prune_src4(struct session_table4 *table,
		struct ipv4_transport_addr *src4,
		struct destructor_arg *destructor)
{
	struct session_entry *root;

	root = rbtree_find4(src4, &table->tree, compare_src4);
	if (!root)
		return;

	rbtree_clear(&root->tree4l2, prune_l2, destructor);
	rbtree_clear(&root->tree4l3, prune_l3, destructor);
	destructor->cb(root, destructor->arg);
}

static int compare_range(const struct session_entry *session,
		const struct ipv4_range *range)
{
	if (prefix4_contains(&range->prefix, &session->src4.l3)) {
		if (port_range_contains(&range->ports, session->src4.l4))
			return 0;
		return (session->src4.l4 < range->ports.min) ? -1 : 1;
	}

	return ipv4_addr_cmp(&session->src4.l3, &range->prefix.address);
}

void st4_prune_range(struct session_table4 *table,
		struct ipv4_range *range,
		struct destructor_arg *destructor)
{
	struct session_entry *session;
	struct rb_node *node;
	struct rb_node *prev;
	struct rb_node *next;

	session = rbtree_find4(range, &table->tree, compare_range);
	if (!session)
		return;

	node = &session->tree4_hook;
	prev = rb_prev(node);
	next = rb_next(node);

	destructor->cb(session, destructor->arg);

	while (prev) {
		node = prev;
		session = st4_entry(node);
		if (!range4_contains(range, &session->src4))
			break;
		prev = rb_prev(node);
		destructor->cb(session, destructor->arg);
	}

	while (next) {
		node = next;
		session = st4_entry(node);
		if (!range4_contains(range, &session->src4))
			break;
		next = rb_next(node);
		destructor->cb(session, destructor->arg);
	}
}

static void print_session(int level, int layer, char *type,
		struct session_entry *session)
{
	pr_info("");
	for (; level > 0; level--)
		pr_cont("    ");
	pr_cont("(%u) %s %pI4#%u -> %pI4#%u\n", layer, type,
			&session->src4.l3, session->src4.l4,
			&session->dst4.l3, session->dst4.l4);
}

static void print_node_l3(int level, char *type, struct rb_node *node)
{
	if (!node)
		return;

	print_session(level, 3, type, st4_entry(node));

	print_node_l3(level + 1, "L", node->rb_left);
	print_node_l3(level + 1, "R", node->rb_right);
}

static void print_node_l2(int level, char *type, struct rb_node *node)
{
	struct session_entry *session;

	if (!node)
		return;

	session = st4_entry(node);
	print_session(level, 2, type, session);

	print_node_l2(level + 1, "L", node->rb_left);
	print_node_l3(level + 1, "3", session->tree4l3.rb_node);
	print_node_l2(level + 1, "R", node->rb_right);
}

static void print_node_l1(int level, char *type, struct rb_node *node)
{
	struct session_entry *session;

	if (!node)
		return;

	session = st4_entry(node);
	print_session(level, 1, type, session);

	print_node_l1(level + 1, "L", node->rb_left);
	print_node_l2(level + 1, "2", session->tree4l2.rb_node);
	print_node_l3(level + 1, "3", session->tree4l3.rb_node);
	print_node_l1(level + 1, "R", node->rb_right);
}

/*
 * This function is recursive; don't use in production code!
 */
void st4_print(struct session_table4 *table)
{
	pr_info("------------------------------\n");
	print_node_l1(0, "T", table->tree.rb_node);
}
