#ifndef _JOOL_MOD_EAM_H
#define _JOOL_MOD_EAM_H

#include <linux/rbtree.h>
#include "nat64/common/config.h"
#include "nat64/common/types.h"

int eamt_init(void);
void eamt_destroy(void);

/* Safe-to-use-anywhere functions */

int eamt_xlat_4to6(struct in_addr *addr4, struct in6_addr *result);
int eamt_xlat_6to4(struct in6_addr *addr6, struct in_addr *result);

bool eamt_contains6(struct in6_addr *addr);
bool eamt_contains4(__be32 addr);

bool eamt_is_empty(void);

/* Do-not-use-when-you-can't-sleep-functions */

int eamt_add(struct ipv6_prefix *prefix6, struct ipv4_prefix *prefix4,
		bool force);
int eamt_rm(struct ipv6_prefix *prefix6, struct ipv4_prefix *prefix4);
void eamt_flush(void);

int eamt_count(__u64 *count);
int eamt_foreach(int (*cb)(struct eamt_entry *, void *), void *arg,
		struct ipv4_prefix *offset);

#endif /* _JOOL_MOD_EAM_H */
