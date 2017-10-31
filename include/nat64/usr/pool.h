#ifndef _JOOL_USR_POOL_H
#define _JOOL_USR_POOL_H

#include "nat64/common/config.h"
#include "nat64/usr/types.h"


int pool_display(enum config_mode mode, display_flags flags);
int pool_count(enum config_mode mode);
int pool_add(enum config_mode mode, struct ipv4_prefix *addrs, bool force);
int pool_rm(enum config_mode mode, struct ipv4_prefix *addrs);
int pool_flush(enum config_mode mode);


#endif /* _JOOL_USR_POOL_H */
