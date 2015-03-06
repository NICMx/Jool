#ifndef _JOOL_MOD_RFC6791_H
#define _JOOL_MOD_RFC6791_H

/**
 * @file
 * This is RFC 6791's pool of addresses.
 *
 * "The recommended approach to source selection is to use a single (or
 * small pool of) public IPv4 address as the source address of the
 * translated ICMP message and leverage the ICMP extension [RFC5837] to
 * include the IPv6 address as an Interface IP Address Sub-Object."
 *
 * The ICMP extension thing has not been implemented yet.
 *
 * @author Alberto Leiva
 */

#include "nat64/mod/common/types.h"

int rfc6791_init(char *pref_strs[], int pref_count);
void rfc6791_destroy(void);

int rfc6791_add(struct ipv4_prefix *prefix);
int rfc6791_remove(struct ipv4_prefix *prefix);
int rfc6791_flush(void);
int rfc6791_get(struct in_addr *result, __be32 *daddr);

int rfc6791_for_each(int (*func)(struct ipv4_prefix *, void *), void *arg);
int rfc6791_count(__u64 *result);
bool rfc6791_is_empty(void);

#endif /* _JOOL_MOD_RFC6791_H */
