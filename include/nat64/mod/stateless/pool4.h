#ifndef _JOOL_MOD_POOL4_H
#define _JOOL_MOD_POOL4_H

/**
 * @file
 * Stateless Jool's "main" pool of IPv4 addresses. Jool will refuse to translate these addresses.
 *
 * Not to be confused with stateful Jool's "pool4"; this is called "pool4" in the code for dumb
 * historic reasons. The name we actually show the user is "blacklist".
 *
 * TODO change names.
 *
 * @author Alberto Leiva
 * @author Daniel Hdz Felix
 */

#include "nat64/mod/common/types.h"

int blacklist_init(char *pref_strs[], int pref_count);
void blacklist_destroy(void);

int blacklist_add(struct ipv4_prefix *prefix);
int blacklist_remove(struct ipv4_prefix *prefix);
int blacklist_flush(void);
bool blacklist_contains(__be32 addr);

int blacklist_for_each(int (*func)(struct ipv4_prefix *, void *), void *arg,
		struct ipv4_prefix *offset);
int blacklist_count(__u64 *result);
bool blacklist_is_empty(void);

#endif /* _JOOL_MOD_POOL4_H */
