#ifndef _NF_NAT64_RFC6052_H
#define _NF_NAT64_RFC6052_H

#include <linux/udp.h>

/**
 * Julius Kriukas's code. Extracts an ipv4 from an ipv6 addr based on the prefix.
 * A modification was made in case 32.
 */
__be32 nat64_extract_ipv4(struct in6_addr addr, int prefix);

#endif

