#ifndef _JOOL_USR_DNS_H
#define _JOOL_USR_DNS_H

#include "common/types.h"

void print_addr6(struct ipv6_transport_addr *addr6, bool numeric,
		char *separator, __u8 l4_proto);
void print_addr4(struct ipv4_transport_addr *addr4, bool numeric,
		char *separator, __u8 l4_proto);


#endif /* _JOOL_USR_DNS_H */
