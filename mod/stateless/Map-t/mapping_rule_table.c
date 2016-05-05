int mapping_rule_table_get_longest_match6(struct mapping_rule_table *mr_table,
		struct ipv6_prefix *prefix6,
		struct mapping_rule *result)
{
	int error = 0;

	struct rtrie_key key6 = PREFIX_TO_KEY(prefix6);
	key6.len = prefix6->len;

	error = rtrie_get(&mr_table, key6, result);

	return  error;
}

int mapping_rule_table_get_exact_match6(struct mapping_rule_table *mr_table,
		struct ipv6_prefix *prefix6,
		struct mapping_rule *result)
{
	int error = 0;

	struct rtrie_key key6 = PREFIX_TO_KEY(prefix6);
	key6.len = prefix6->len;

	error = rtrie_get(&mr_table, key6, result);

	if (error)
		return error;

	return  result->v6_prefix.len == prefix6->len ? 0 : -ESRCH;
}


int mapping_rule_table_get_longest_match4(struct mapping_rule_table *mr_table,
		struct ipv4_prefix *prefix4,
		struct mapping_rule *result)
{
	int error = 0;

	struct rtrie_key key4 = PREFIX_TO_KEY(prefix4);
	key4.len = prefix4->len;

	error = rtrie_get(&mr_table, key4, result);

	return error;
}


int mapping_rule_table_get_exact_match4(struct mapping_rule_table *mr_table,
		struct ipv4_prefix *prefix4,
		struct mapping_rule *result)
{
	int error = 0;

	struct rtrie_key key4 = PREFIX_TO_KEY(prefix4);
	key4.len = prefix4->len;

	error = rtrie_get(&mr_table, key4, result);

	if (error)
		return error;

	return  result->v4_prefix.len == prefix4->len ? 0 : -ESRCH;
}

