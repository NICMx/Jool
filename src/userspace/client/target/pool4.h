#ifndef _JOOL_USR_POOL4_H
#define _JOOL_USR_POOL4_H

#include "nl-protocol.h"
#include "userspace-types.h"


int pool4_display(display_flags flags);
int pool4_add(struct pool4_entry_usr *entry, bool force);
int pool4_update(struct pool4_update *args);
int pool4_rm(struct pool4_entry_usr *entry, bool quick);
int pool4_flush(bool quick);


#endif /* _JOOL_USR_POOL4_H */
