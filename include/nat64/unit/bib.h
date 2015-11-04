#ifndef _JOOL_UNIT_BIB_H
#define _JOOL_UNIT_BIB_H

#include "nat64/mod/stateful/bib/db.h"

int bib_print(l4_protocol l4_proto);

struct bib_entry *bib_inject(char *addr6, u16 port6, char *addr4, u16 port4,
		l4_protocol l4_proto);

#endif /* _JOOL_UNIT_BIB_H */
