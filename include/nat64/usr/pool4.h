#ifndef _JOOL_USR_POOL4_H
#define _JOOL_USR_POOL4_H

#include "nat64/common/config.h"


int pool4_display(bool csv);
int pool4_count(void);
int pool4_add(__u32 mark, bool tcp, bool udp, bool icmp,
		struct ipv4_prefix *addrs, struct port_range *ports,
		bool force);
int pool4_rm(__u32 mark, bool tcp, bool udp, bool icmp,
		struct ipv4_prefix *addrs, struct port_range *ports,
		bool quick);
int pool4_flush(bool quick);


#endif /* _JOOL_USR_POOL4_H */
