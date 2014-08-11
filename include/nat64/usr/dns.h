#ifndef _JOOL_USR_DNS_H
#define _JOOL_USR_DNS_H


#include "nat64/comm/types.h"

void print_ipv6_tuple(struct ipv6_tuple_address *tuple, bool numeric_hostname, char *separator,
		__u8 l4_proto);
void print_ipv4_tuple(struct ipv4_tuple_address *tuple, bool numeric_hostname, char *separator,
		__u8 l4_proto);


#endif /* _JOOL_USR_DNS_H */
