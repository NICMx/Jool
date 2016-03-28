#include "nat64/mod/stateful/bib/db.h"

/*
 * In current BIB impersonator users, BIB is optional.
 * This is good, because BIB should not really be tested in unit tests other
 * than its own.
 * Therefore, these functions should never be called.
 */

struct bib_entry *bibentry_create(const struct ipv4_transport_addr *addr4,
		const struct ipv6_transport_addr *addr6,
		const bool is_static, const l4_protocol proto)
{
	WARN(true, "This function was called! The unit test is broken.");
	return NULL;
}

void bibentry_get_db(struct bib_entry *bib)
{
	WARN(true, "This function was called! The unit test is broken.");
}

int bibentry_put_db(struct bib_entry *bib)
{
	WARN(true, "This function was called! The unit test is broken.");
	return 1;
}

void bibentry_put_thread(struct bib_entry *bib, bool must_die)
{
	WARN(true, "This function was called! The unit test is broken.");
}

bool bibentry_equals(const struct bib_entry *b1, const struct bib_entry *b2)
{
	WARN(true, "This function was called! The unit test is broken.");
	return false;
}

int bibdb_find4(struct bib *db, const struct ipv4_transport_addr *addr,
		const l4_protocol proto, struct bib_entry **result)
{
	WARN(true, "This function was called! The unit test is broken.");
	return -EINVAL;
}

int bibdb_add(struct bib *db, struct bib_entry *entry, struct bib_entry **old)
{
	WARN(true, "This function was called! The unit test is broken.");
	return -EINVAL;
}
