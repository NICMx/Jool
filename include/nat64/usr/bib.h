#ifndef _JOOL_USR_BIB_H
#define _JOOL_USR_BIB_H

#include "nat64/common/types.h"


int bib_display(bool use_tcp, bool use_udp, bool use_icmp, bool numeric_hostname, bool csv_format);
int bib_count(bool use_tcp, bool use_udp, bool use_icmp);

int bib_add(bool use_tcp, bool use_udp, bool use_icmp,
		struct ipv6_transport_addr *ipv6,
		struct ipv4_transport_addr *ipv4);
int bib_remove(bool use_tcp, bool use_udp, bool use_icmp,
		struct ipv6_transport_addr *addr6,
		struct ipv4_transport_addr *addr4);


#endif /* _JOOL_USR_BIB_H */
