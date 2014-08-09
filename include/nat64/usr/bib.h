#ifndef _JOOL_USR_BIB_H
#define _JOOL_USR_BIB_H

#include "nat64/comm/types.h"


int bib_display(bool use_tcp, bool use_udp, bool use_icmp, bool numeric_hostname, bool csv_format);
int bib_count(bool use_tcp, bool use_udp, bool use_icmp);

int bib_add(bool use_tcp, bool use_udp, bool use_icmp,
		struct ipv6_tuple_address *ipv6,
		struct ipv4_tuple_address *ipv4);
int bib_remove(bool use_tcp, bool use_udp, bool use_icmp,
		bool addr6_set, struct ipv6_tuple_address *addr6,
		bool addr4_set, struct ipv4_tuple_address *addr4);


#endif /* _JOOL_USR_BIB_H */
