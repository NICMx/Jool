#ifndef _JOOL_MOD_POOL4_H
#define _JOOL_MOD_POOL4_H

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

int pool4_init(char *pref_strs[], int pref_count);
void pool4_destroy(void);

int pool4_add(struct ipv4_prefix *prefix);
int pool4_remove(struct ipv4_prefix *prefix);
int pool4_flush(void);
int pool4_get(struct in_addr *result);

int pool4_for_each(int (*func)(struct ipv4_prefix *, void *), void *arg);
int pool4_count(__u64 *result);
bool pool4_is_empty(void);

#endif /* _JOOL_MOD_POOL4_H */
