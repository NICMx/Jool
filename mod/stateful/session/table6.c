#include "nat64/mod/stateful/session/table6.h"

#include <net/ipv6.h>
#include "nat64/mod/common/rbtree.h"

static struct session_entry *st6_entry(struct rb_node *node)
{
	return rb_entry(node, struct session_entry, tree6_hook);
}

static int compare_tuple6(const struct session_entry *session,
		const struct tuple *tuple6)
{
	int gap;

	gap = taddr6_compare(&session->dst6, &tuple6->dst.addr6);
	if (gap)
		return gap;

	gap = taddr6_compare(&session->src6, &tuple6->src.addr6);
	return gap;
}

struct session_entry *st6_find(struct session_table6 *table,
		struct tuple *tuple6)
{
	return rbtree_find(tuple6, table, compare_tuple6, struct session_entry,
			tree6_hook);
}

static int compare_session6(const struct session_entry *s1,
		const struct session_entry *s2)
{
	int gap;

	gap = taddr6_compare(&s1->dst6, &s2->dst6);
	if (gap)
		return gap;

	gap = taddr6_compare(&s1->src6, &s2->src6);
	return gap;
}

struct session_entry *st6_add(struct session_table6 *table,
		struct session_entry *session)
{
	return rbtree_add(session, session, table, compare_session6,
			struct session_entry, tree6_hook);
}

void st6_rm(struct session_table6 *table, struct session_entry *session)
{
	rb_erase(&session->tree6_hook, table);
}

void st6_flush(struct session_table6 *table)
{
	table->rb_node = NULL;
}

static int compare_offset(const struct session_entry *session,
		struct session_foreach_offset *offset)
{
	int gap;

	gap = taddr6_compare(&session->dst6, &offset->offset.dst);
	if (gap)
		return gap;

	gap = taddr6_compare(&session->src6, &offset->offset.src);
	return gap;
}

static struct rb_node *find_starting_point(struct session_table6 *table,
		struct session_foreach_offset *offset)
{
	struct rb_node **node, *parent;
	struct session_entry *session;

	/* If there's no offset, start from the beginning. */
	if (!offset)
		return rb_first(table);

	/* If offset is found, start from offset or offset's next. */
	rbtree_find_node(offset, table, compare_offset, struct session_entry,
			tree6_hook, parent, node);
	if (*node)
		return offset->include_offset ? (*node) : rb_next(*node);

	if (!parent)
		return NULL;

	/*
	 * If offset is not found, start from offset's next anyway.
	 * (If offset was meant to exist, it probably timed out and died while
	 * the caller wasn't holding the spinlock; it's nothing to worry about.)
	 */
	session = rb_entry(parent, struct session_entry, tree4_hook);
	return (compare_offset(session, offset) < 0) ? rb_next(parent) : parent;
}

int st6_foreach(struct session_table6 *table,
		struct session_foreach_func *func,
		struct session_foreach_offset *offset)
{
	struct rb_node *node, *next;
	struct session_entry *session;
	int error = 0;

	node = find_starting_point(table, offset);
	for (; node && !error; node = next) {
		next = rb_next(node);
		session = rb_entry(node, struct session_entry, tree6_hook);
		error = func->cb(session, func->arg);
	}

	return error;
}

void st6_prune_range(struct session_table6 *table,
		struct ipv6_prefix *prefix,
		struct destructor_arg *destructor)
{
	struct session_entry *session;
	struct rb_node *node, *next;

	/*
	 * We'll most likely end up flushing the entire tree anyway,
	 * so might as well do a full traversal.
	 * Don't worry; this operation is rare (operator-initiated).
	 */

	node = rb_first(table);
	while (node) {
		next = rb_next(node);

		session = st6_entry(node);
		if (prefix6_contains(prefix, &session->dst6.l3))
			destructor->cb(session, destructor->arg);

		node = next;
	}
}
