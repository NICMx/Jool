#include "nat64/mod/stateful/session/table64.h"

#include "nat64/mod/common/address.h"
#include "nat64/mod/common/rbtree.h"

static int compare64(const struct session_entry *s1,
		const struct session_entry *s2)
{
	int gap;

	gap = taddr6_compare(&s1->src6, &s2->src6);
	if (gap)
		return gap;

	gap = taddr4_compare(&s1->src4, &s2->src4);
	return gap;
}

struct session_entry *st64_add(struct session_table64 *table,
		struct session_entry *session)
{
	return rbtree_add(session, session, table, compare64,
			struct session_entry, tree64_hook);
}

void st64_rm(struct session_table64 *table, struct session_entry *session)
{
	rb_erase(&session->tree64_hook, table);
}
