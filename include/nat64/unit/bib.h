#ifndef _JOOL_UNIT_BIB_H
#define _JOOL_UNIT_BIB_H

#include "nat64/mod/bib_db.h"


bool bib_assert(l4_protocol l4_proto, struct bib_entry **expected_bibs);
#define BIB_ASSERT(l4_proto, ...) bib_assert(l4_proto, (struct bib_entry*[]) { __VA_ARGS__ , NULL })
int bib_print(l4_protocol l4_proto);

bool bib_inject_str(unsigned char *addr4_str, u16 port4, unsigned char *addr6_str, u16 port6,
		l4_protocol l4_proto);
bool bib_inject(struct in_addr *addr4, u16 port4, struct in6_addr *addr6, u16 port6,
		l4_protocol l4_proto);


#endif /* _JOOL_UNIT_BIB_H */
