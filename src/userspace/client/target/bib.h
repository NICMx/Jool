#ifndef _JOOL_USR_BIB_H
#define _JOOL_USR_BIB_H

#include "types.h"
#include "userspace-types.h"


int bib_display(display_flags flags);
int bib_add(display_flags flags,
		struct ipv6_transport_addr *ipv6,
		struct ipv4_transport_addr *ipv4);
int bib_remove(display_flags flags,
		struct ipv6_transport_addr *addr6,
		struct ipv4_transport_addr *addr4);


#endif /* _JOOL_USR_BIB_H */
