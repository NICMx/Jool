#include "nat64/mod/stateful/bib/db.h"

/*
 * In current BIB impersonator users, BIB is optional.
 * This is good, because BIB should not really be tested in unit tests other
 * than its own.
 * Therefore, these functions should never be called.
 */

void bibentry_get(struct bib_entry *bib)
{
	log_err("This function was called! The unit test is broken.");
	BUG();
}

int bibentry_put(struct bib_entry *bib)
{
	log_err("This function was called! The unit test is broken.");
	BUG();
	return 1;
}

bool bibdb_contains4(struct bib *db, const struct ipv4_transport_addr *addr,
		const l4_protocol proto)
{
	log_err("This function was called! The unit test is broken.");
	BUG();
}
