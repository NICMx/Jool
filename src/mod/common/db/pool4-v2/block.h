#ifndef SRC_MOD_COMMON_DB_POOL4_V2_BLOCK_H_
#define SRC_MOD_COMMON_DB_POOL4_V2_BLOCK_H_

#include "common/types.h"

struct p4blocks;

/* Constructors, destructors */
struct p4blocks *p4block_init(void);
void p4block_get(struct p4blocks *);
void p4block_put(struct p4blocks *);

/* Userspace client */
int p4block_add(struct p4blocks *, struct p4block *);
int p4block_rm(struct p4blocks *, struct p4block *);
void p4block_print(struct p4blocks *, const char *);

/* Translation */
int p4block_find(struct p4blocks *, struct in6_addr *, struct p4block *);
bool p4block_contains(struct p4blocks *, struct ipv4_transport_addr const *);
void p4block_expire(struct p4blocks *, u64 time_limit);

/* Testing */
void p4block_cheat(struct p4blocks *blocks);

#endif /* SRC_MOD_COMMON_DB_POOL4_V2_BLOCK_H_ */
