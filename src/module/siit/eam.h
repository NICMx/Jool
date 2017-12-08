#ifndef _JOOL_MOD_EAM_H
#define _JOOL_MOD_EAM_H

#include <linux/kref.h>
#include <linux/rbtree.h>
#include "config.h"
#include "types.h"
#include "rtrie.h"

struct eam_table;

int eamt_init(struct eam_table **eamt);
void eamt_get(struct eam_table *eamt);
void eamt_put(struct eam_table *eamt);

/* Safe-to-use-during-packet-translation functions */

int eamt_xlat_4to6(struct eam_table *eamt, struct in_addr *addr4,
		struct in6_addr *result);
int eamt_xlat_6to4(struct eam_table *eamt, struct in6_addr *addr6,
		struct in_addr *result);

bool eamt_contains6(struct eam_table *eamt, struct in6_addr *addr);
bool eamt_contains4(struct eam_table *eamt, __be32 addr);

bool eamt_is_empty(struct eam_table *eamt);

/* Do-not-use-when-you-can't-sleep-functions */

int eamt_add(struct eam_table *eamt, struct ipv6_prefix *prefix6,
		struct ipv4_prefix *prefix4, bool force);
int eamt_rm(struct eam_table *eamt, struct ipv6_prefix *prefix6,
		struct ipv4_prefix *prefix4);
void eamt_flush(struct eam_table *eamt);

int eamt_count(struct eam_table *eamt, __u64 *count);
int eamt_foreach(struct eam_table *eamt,
		int (*cb)(struct eamt_entry *, void *), void *arg,
		struct ipv4_prefix *offset);

void eamt_print_refcount(struct eam_table *eamt);

#endif /* _JOOL_MOD_EAM_H */
