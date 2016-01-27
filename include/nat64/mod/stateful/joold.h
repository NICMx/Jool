#ifndef _JOOL_MOD_JOOLD_H
#define _JOOL_MOD_JOOLD_H

#include "nat64/mod/common/namespace.h"
#include "nat64/mod/stateful/session/entry.h"

int joold_init(void);
void joold_destroy(void);

int joold_sync_entries(struct xlator *jool, void *data, __u32 size);
int joold_add_session_element(struct session_entry *entry);
void joold_update_config(unsigned long period);
void joold_start(void);
void joold_stop(void);

#endif
