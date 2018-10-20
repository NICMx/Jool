#ifndef _JOOL_USR_BIB_H
#define _JOOL_USR_BIB_H

#include "common/config.h"
#include "common/types.h"

typedef int (*bib_foreach_cb)(struct bib_entry_usr *entry, void *args);

int bib_foreach(char *iname, l4_protocol proto, bib_foreach_cb cb, void *args);
int bib_add(char *iname,
		struct ipv6_transport_addr *a6,
		struct ipv4_transport_addr *a4,
		l4_protocol proto);
int bib_rm(char *iname,
		struct ipv6_transport_addr *a6,
		struct ipv4_transport_addr *a4,
		l4_protocol proto);

#endif /* _JOOL_USR_BIB_H */
