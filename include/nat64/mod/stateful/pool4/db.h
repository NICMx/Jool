#ifndef _JOOL_MOD_POOL4_DB_H
#define _JOOL_MOD_POOL4_DB_H

/*
 * @file
 * The pool of IPv4 addresses. Stateful NAT64 Jool uses this to figure out
 * which packets should be translated.
 *
 * @author Alberto Leiva
 */

#include "nat64/mod/stateful/pool4/entry.h"

/*
 * Write functions (Caller must prevent concurrence)
 */

int pool4db_init(unsigned int capacity, char *pref_strs[], int pref_count);
void pool4db_destroy(void);

int pool4db_add(const __u32 mark, enum l4_protocol proto,
		struct ipv4_prefix *prefix, struct port_range *ports);
int pool4db_rm(const __u32 mark, enum l4_protocol proto,
		struct ipv4_prefix *prefix, struct port_range *ports);
int pool4db_flush(void);

/*
 * Read functions (Legal to use anywhere)
 */

bool pool4db_contains(enum l4_protocol proto, struct ipv4_transport_addr *addr);
bool pool4db_is_empty(void);
void pool4db_count(__u32 *tables, __u64 *samples, __u64 *taddrs);

int pool4db_foreach_sample(int (*cb)(struct pool4_sample *, void *), void *arg,
		struct pool4_sample *offset);
int pool4db_foreach_taddr4(const __u32 mark, enum l4_protocol proto,
		int (*func)(struct ipv4_transport_addr *, void *), void *arg,
		unsigned int offset);

#endif /* _JOOL_MOD_POOL4_DB_H */
