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

void blacklist_replace(struct list_head *pool);

int blacklist_for_each(int (*func)(struct ipv4_prefix *, void *), void *arg,
		struct ipv4_prefix *offset);
int blacklist_count(__u64 *result);
bool blacklist_is_empty(void);

struct list_head * blacklist_config_init_db(void);
int blacklist_config_add(struct list_head * db, struct ipv4_prefix * entry);
int blacklist_switch_database(struct list_head * db);

#endif /* _JOOL_MOD_BLACKLIST4_H */
