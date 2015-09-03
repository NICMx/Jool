#ifndef _JOOL_MOD_BLACKLIST4_H
#define _JOOL_MOD_BLACKLIST4_H

/**
 * @file
 * Pool of banned IPv4 addresses; Jool will refuse to translate these addresses.
 *
 * @author Alberto Leiva
 * @author Daniel Hdz Felix
 */

#include "nat64/mod/common/types.h"

int blacklist_init(char *pref_strs[], int pref_count);
void blacklist_destroy(void);

int blacklist_add(struct ipv4_prefix *prefix);
int blacklist_rm(struct ipv4_prefix *prefix);
int blacklist_flush(void);
bool blacklist_contains(__be32 addr);

int blacklist_for_each(int (*func)(struct ipv4_prefix *, void *), void *arg,
		struct ipv4_prefix *offset);
int blacklist_count(__u64 *result);
bool blacklist_is_empty(void);

#endif /* _JOOL_MOD_BLACKLIST4_H */
