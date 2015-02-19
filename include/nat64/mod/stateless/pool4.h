#ifndef _JOOL_MOD_POOL4_H
#define _JOOL_MOD_POOL4_H

/**
 * @file
 * This is the pool of IPv4 addresses.
 *
 * Here are the accepted IPv4 addresses for translation.
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
