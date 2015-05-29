#ifndef _JOOL_USR_POOL4_H
#define _JOOL_USR_POOL4_H

#include "nat64/common/config.h"


int pool4_display(enum config_mode mode);
int pool4_count(enum config_mode mode);
int pool4_add(enum config_mode mode, __u32 mark, struct ipv4_prefix *addrs,
		struct port_range *ports);
int pool4_remove(enum config_mode mode, __u32 mark, struct ipv4_prefix *addrs,
		struct port_range *ports, bool quick);
int pool4_flush(enum config_mode mode, bool quick);


#endif /* _JOOL_USR_POOL4_H */
