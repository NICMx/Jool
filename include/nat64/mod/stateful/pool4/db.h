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

int pool4db_add(const __u32 mark, struct ipv4_prefix *prefix,
		struct port_range *ports);
int pool4db_rm(const __u32 mark, struct ipv4_prefix *prefix,
		struct port_range *ports);
int pool4db_flush(const __u32 mark);

/*
 * Read functions (Legal to use anywhere)
 */

bool pool4db_contains(const __u32 mark, struct ipv4_transport_addr *addr);
bool pool4db_contains_all(struct ipv4_transport_addr *addr);
bool pool4db_is_empty(void);

int pool4db_foreach_sample(const __u32 mark,
		int (*func)(struct pool4_sample *, void *), void *arg,
		struct pool4_sample *offset);
int pool4db_foreach_taddr4(const __u32 mark,
		int (*func)(struct ipv4_transport_addr *, void *), void *arg,
		unsigned int offset);

#endif /* _JOOL_MOD_POOL4_DB_H */
