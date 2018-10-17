#ifndef _JOOL_USR_POOL_H
#define _JOOL_USR_POOL_H

#include "common/config.h"
#include "usr/common/types.h"

typedef int (*pool_foreach_cb)(struct ipv4_prefix *entry, void *args);

int pool_foreach(char *iname, enum config_mode mode,
		pool_foreach_cb cb, void *_args);
int pool_add(char *iname, enum config_mode mode, struct ipv4_prefix *addrs,
		bool force);
int pool_rm(char *iname, enum config_mode mode, struct ipv4_prefix *addrs);
int pool_flush(char *iname, enum config_mode mode);


#endif /* _JOOL_USR_POOL_H */
