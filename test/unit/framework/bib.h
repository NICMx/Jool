#ifndef _JOOL_UNIT_BIB_H
#define _JOOL_UNIT_BIB_H

#include "nat64/mod/stateful/bib/db.h"

int bib_inject(struct bib *db, char *addr6, u16 port6, char *addr4, u16 port4,
		l4_protocol proto, struct bib_entry *entry);

#endif /* _JOOL_UNIT_BIB_H */
