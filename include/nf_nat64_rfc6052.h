#ifndef _NF_NAT64_RFC6052_H
#define _NF_NAT64_RFC6052_H

/**
 * @file
 * Our implementation of RFC6052. Implements IPv4-IPv6 address translation.
 */

#include <linux/udp.h>

/**
 * Extracts an ipv4 from an ipv6 addr based on the prefix.
 *
 * Heavily based off Julius Kriukas's code.
 *
 * @param addr IPv6 address to be translated.
 * @param prefix length of the prefix the IPv6 address was built with.
 * @return the IPv4 version of the "addr" address using the "prefix" prefix.
 * @see RFC 6052 section 2.3.
 */
__be32 nat64_extract_ipv4(struct in6_addr addr, int prefix);

#endif /* _NF_NAT64_RFC6052_H */
