#ifndef __EUP6_MR_RELATION_TABLE_H__
#define __EUP6_MR_RELATION_TABLE_H__

bool eup6_mr_relation_table_contains_rule(struct eup6_mr_relation_table *table,
		struct mapping_rule *rule);

bool eup6_mr_relation_table_contains_prefix(struct eup6_mr_relation_table *table,
		struct ipv6_prefix *enduser_prefix6);

int eup6_mr_relation_table_add(struct eup6_mr_relation_table *table,
		struct mapping_rule *rule, struct ipv6_prefix *enduser_prefix6)

int eup6_mr_relation_table_delete_by_prefix(struct eup6_mr_relation_table *table,
		struct ipv6_prefix *enduser_prefix6);

int eup6_mr_relation_table_delete_by_rule(struct eup6_mr_relation_table *table,
		struct mapping_rule *rule);

int eup6_mr_relation_table_get_by_prefix(struct eup6_mr_relation_table *table,
		struct ipv6_prefix *enduser_prefix6, struct eup6_mr_relation_entry *result);

int eup6_mr_relation_table_get_by_rule(struct eup6_mr_relation_table *table,
		struct mapping_rule *rule, struct eup6_mr_relation_entry *result);

#endif
