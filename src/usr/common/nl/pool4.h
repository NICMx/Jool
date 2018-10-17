#ifndef _JOOL_USR_POOL4_H
#define _JOOL_USR_POOL4_H

#include "common/config.h"
#include "usr/common/types.h"

typedef int (*pool4_foreach_cb)(struct pool4_sample *sample, void *args);

int pool4_foreach(char *instance, l4_protocol proto,
		pool4_foreach_cb cb, void *args);
int pool4_add(char *instance, struct pool4_entry_usr *entry);
int pool4_rm(char *instance, struct pool4_entry_usr *entry, bool quick);
int pool4_flush(char *instance, bool quick);

#endif /* _JOOL_USR_POOL4_H */
