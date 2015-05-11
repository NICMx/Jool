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
 * Write functions - You *MUST* hold the configuration mutex or ensure you're
 * the only thread calling these.
 */

int pool4db_init(void);
void pool4db_destroy(void);

int pool4db_add(const __u32 mark, const struct pool4_sample *sample);
int pool4db_rm(const __u32 mark, const struct pool4_sample *sample);

/*
 * Read functions - Legal to use anywhere.
 */

int pool4db_foreach_port(const __u32 mark,
		int (*func)(struct ipv4_transport_addr *, void *), void *args,
		unsigned int offset);

#endif /* _JOOL_MOD_POOL4_DB_H */
