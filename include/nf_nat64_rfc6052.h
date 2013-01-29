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
#include "nf_nat64_types.h"


bool nat64_extract_ipv4(struct in6_addr *src, struct ipv6_prefix *prefix, struct in_addr *dst);
bool nat64_append_ipv4(struct in_addr *src, struct ipv6_prefix *prefix, struct in6_addr *dst);


#endif /* _NF_NAT64_RFC6052_H */

