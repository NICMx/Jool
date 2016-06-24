#ifndef _JOOL_MOD_SESSION_TABLE64_H
#define _JOOL_MOD_SESSION_TABLE64_H

#include <linux/rbtree.h>
#include "nat64/mod/stateful/session/entry.h"

#define session_table64 rb_root

struct session_entry *st64_add(struct session_table64 *table,
		struct session_entry *session);
void st64_rm(struct session_table64 *table, struct session_entry *session);

#endif /* _JOOL_MOD_SESSION_TABLE64_H */
