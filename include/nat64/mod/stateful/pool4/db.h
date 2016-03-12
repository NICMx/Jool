#ifndef _JOOL_MOD_POOL4_DB_H
#define _JOOL_MOD_POOL4_DB_H

/*
 * @file
 * The pool of IPv4 addresses. Stateful NAT64 Jool uses this to figure out
 * which packets should be translated.
 */

#include <linux/net.h>
#include "nat64/common/types.h"
#include "nat64/mod/common/config.h"
#include "nat64/mod/stateful/pool4/entry.h"

struct pool4;

/*
 * Write functions (Caller must prevent concurrence)
 */

int pool4db_init(struct pool4 **pool, unsigned int capacity);
void pool4db_get(struct pool4 *pool);
void pool4db_put(struct pool4 *pool);

int pool4db_add(struct pool4 *pool, const __u32 mark, enum l4_protocol proto,
		struct ipv4_prefix *prefix, struct port_range *ports);
int pool4db_add_usr(struct pool4 *pool, struct pool4_entry_usr *entry);
int pool4db_add_str(struct pool4 *pool, char *prefix_strs[], int prefix_count);
int pool4db_rm(struct pool4 *pool, const __u32 mark, enum l4_protocol proto,
		struct ipv4_prefix *prefix, struct port_range *ports);
int pool4db_rm_usr(struct pool4 *pool, struct pool4_entry_usr *entry);
int pool4db_flush(struct pool4 *pool);

/*
 * Read functions (Legal to use anywhere)
 */

bool pool4db_contains(struct pool4 *pool, struct net *ns,
		enum l4_protocol proto, struct ipv4_transport_addr *addr);
bool pool4db_is_empty(struct pool4 *pool);
void pool4db_count(struct pool4 *pool, __u32 *tables, __u64 *samples,
		__u64 *taddrs);

int pool4db_foreach_sample(struct pool4 *pool,
		int (*cb)(struct pool4_sample *, void *), void *arg,
		struct pool4_sample *offset);
int pool4db_foreach_taddr4(struct pool4 *pool, struct net *ns,
		struct in_addr *daddr, __u8 tos, __u8 proto, __u32 mark,
		int (*func)(struct ipv4_transport_addr *, void *), void *arg,
		unsigned int offset);

#endif /* _JOOL_MOD_POOL4_DB_H */
