


bool enduser_prefix6_table_contains(struct enduser_prefix6_table *table,
		struct ipv6_prefix *prefix)
{

	struct rtrie_key key6 = PREFIX_TO_KEY(prefix);
	key6.len = prefix->len;

	return rtrie_contains(&table->trie6, )
}
