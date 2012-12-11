#ifndef _NF_NAT64_RFC6052_H
#define _NF_NAT64_RFC6052_H

#include <linux/udp.h>
#include <linux/types.h>
#include <linux/in6.h>


struct in_addr nat64_extract_ipv4(struct in6_addr *addr, int prefix);
struct in6_addr nat64_append_ipv4(struct in6_addr *addr, struct in_addr *addr4, int prefix);


#endif /* _NF_NAT64_RFC6052_H */

