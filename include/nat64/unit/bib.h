#ifndef _JOOL_UNIT_BIB_H
#define _JOOL_UNIT_BIB_H

#include "nat64/mod/stateful/bib_db.h"

/**
 * Asserts the BIB database contains exactly the "expected_bibs" entries.
 */
bool bib_assert(l4_protocol l4_proto, struct bib_entry **expected_bibs);
#define BIB_ASSERT(l4_proto, ...) bib_assert(l4_proto, (struct bib_entry*[]) { __VA_ARGS__ , NULL })
int bib_print(l4_protocol l4_proto);

struct bib_entry *bib_create_str(const unsigned char *addr6_str, u16 port6,
		const unsigned char *addr4_str, u16 port4,
		l4_protocol l4_proto);

struct bib_entry *bib_inject_str(const unsigned char *addr6_str, u16 port6,
		const unsigned char *addr4_str, u16 port4,
		l4_protocol l4_proto);
struct bib_entry *bib_inject(const struct in6_addr *addr6, u16 port6,
		const struct in_addr *addr4, u16 port4,
		l4_protocol l4_proto);


#endif /* _JOOL_UNIT_BIB_H */
