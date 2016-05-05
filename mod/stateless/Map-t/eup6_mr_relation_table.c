#include "nat64/common/types.h"



static int compare6(const struct eup6_mr_relation_entry  *entry,
		const struct mapping_rule *rule)
{
	int gap = 0;

	gap = ipv6_addr_cmp(&entry->rule->v6_prefix.address,
			&rule->v6_prefix.address);

	return gap;
}


bool eup6_mr_relation_table_contains(struct eup6_mr_relation_table *table,
		struct mapping_rule *rule)
{
	struct eup6_mr_relation_entry *entry;

	entry = rbtree_find(rule, table->relation_entry, compare6,
			struct eup6_mr_relation_entry,	relation_hook);

	if (entry)
		return true;

	return false;
}
