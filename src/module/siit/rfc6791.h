#ifndef _JOOL_MOD_RFC6791_H
#define _JOOL_MOD_RFC6791_H

/**
 * This is RFC 6791's pool of addresses.
 *
 * "The recommended approach to source selection is to use a single (or
 * small pool of) public IPv4 address as the source address of the
 * translated ICMP message and leverage the ICMP extension [RFC5837] to
 * include the IPv6 address as an Interface IP Address Sub-Object."
 *
 * The ICMP extension thing has not been implemented yet.
 */

#include "xlation.h"

int rfc6791_find4(struct xlation *state, __be32 *result);
/**
 * The EAM can potentially create situations where the 6791 situation happens in
 * the 4->6 direction. Hence, we had to mirror rfc6791_find4().
 */
int rfc6791_find6(struct xlation *state, struct in6_addr *result);

#endif /* _JOOL_MOD_RFC6791_H */
