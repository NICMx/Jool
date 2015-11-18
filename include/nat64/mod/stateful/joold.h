#ifndef _JOOL_MOD_JOOLD_H
#define _JOOL_MOD_JOOLD_H

#include "nat64/mod/stateful/session/entry.h"

int joold_init(int sender_sock_family, int sych_period);
int joold_destroy(void);
int joold_sync_entires(__u8 * data, __u32 size);
int joold_add_session_element(struct session_entry *entry);


#endif
