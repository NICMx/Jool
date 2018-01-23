#ifndef _JOOL_USR_DNS_H
#define _JOOL_USR_DNS_H


#include "types.h"
#include "userspace-types.h"

void print_addr6(struct ipv6_transport_addr *addr6, display_flags flags,
		char *separator, __u8 l4_proto);
void print_addr4(struct ipv4_transport_addr *addr4, display_flags flags,
		char *separator, __u8 l4_proto);


#endif /* _JOOL_USR_DNS_H */
