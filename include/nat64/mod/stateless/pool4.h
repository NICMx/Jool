#ifndef _JOOL_MOD_POOL4_H
#define _JOOL_MOD_POOL4_H

/**
 * @file
 * Stateless Jool's "main" pool of IPv4 addresses. Jool will refuse to translate these addresses.
 *
 * Not to be confused with stateful Jool's "pool4"; this is called "pool4" in the code for dumb
 * historic reasons. The name we actually show the user is "blacklist".
 *
 * @author Alberto Leiva
 * @author Daniel Hdz Felix
 */

#include "nat64/mod/common/types.h"

int pool4_init(char *pref_strs[], int pref_count);
void pool4_destroy(void);

int pool4_add(struct ipv4_prefix *prefix);
int pool4_remove(struct ipv4_prefix *prefix);
int pool4_flush(void);
bool pool4_contains(__be32 addr);

int pool4_for_each(int (*func)(struct ipv4_prefix *, void *), void *arg);
int pool4_count(__u64 *result);
bool pool4_is_empty(void);

#endif /* _JOOL_MOD_POOL4_H */
