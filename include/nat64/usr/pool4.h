#ifndef _JOOL_USR_POOL4_H
#define _JOOL_USR_POOL4_H

#include "nat64/common/config.h"
#include "nat64/usr/types.h"


int pool4_display(char *iname, display_flags flags);
int pool4_count(char *iname);
int pool4_add(char *iname, struct pool4_entry_usr *entry, bool force);
int pool4_update(char *iname, struct pool4_update *args);
int pool4_rm(char *iname, struct pool4_entry_usr *entry, bool quick);
int pool4_flush(char *iname, bool quick);


#endif /* _JOOL_USR_POOL4_H */
