#ifndef _NF_NAT64_RFC6052_H
#define _NF_NAT64_RFC6052_H

/**
 * @file
 * The algorithm defined in RFC 6052 (http://tools.ietf.org/html/rfc6052).
 *
 * @author Ramiro Nava
 * @author Alberto Leiva  <- maintenance
 */

#include <linux/types.h>
#include <linux/in.h>
#include <linux/in6.h>
#include "nat64/comm/types.h"


bool addr_6to4(struct in6_addr *src, struct ipv6_prefix *prefix, struct in_addr *dst);
bool addr_4to6(struct in_addr *src, struct ipv6_prefix *prefix, struct in6_addr *dst);


#endif /* _NF_NAT64_RFC6052_H */
