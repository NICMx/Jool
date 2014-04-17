#ifndef _DNS_H
#define _DNS_H


#include "nat64/comm/types.h"

void print_ipv6_tuple(struct ipv6_tuple_address *tuple, bool numeric_hostname);
void print_ipv4_tuple(struct ipv4_tuple_address *tuple, bool numeric_hostname);


#endif /* _DNS_H */
