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
 */

#include "nat64/mod/common/translation_state.h"
#include "nat64/mod/stateless/pool.h"

int rfc6791_init(struct addr4_pool **pool);
void rfc6791_get(struct addr4_pool *pool);
void rfc6791_put(struct addr4_pool *pool);

int rfc6791_add(struct addr4_pool *pool, struct ipv4_prefix *prefix, bool force);
int rfc6791_rm(struct addr4_pool *pool, struct ipv4_prefix *prefix);
int rfc6791_flush(struct addr4_pool *pool);
int rfc6791_find(struct xlation *state, __be32 *result);

int rfc6791_for_each(struct addr4_pool *pool,
		int (*func)(struct ipv4_prefix *, void *), void *arg,
		struct ipv4_prefix *offset);
int rfc6791_count(struct addr4_pool *pool, __u64 *result);
bool rfc6791_is_empty(struct addr4_pool *pool);

#endif /* _JOOL_MOD_RFC6791_H */
