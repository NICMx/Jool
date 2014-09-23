#ifndef _JOOL_UNIT_TYPES_H
#define _JOOL_UNIT_TYPES_H

#include "nat64/mod/types.h"


int init_ipv4_tuple(struct tuple *tuple4, unsigned char *src_addr, __u16 src_port,
		unsigned char *dst_addr, __u16 dst_port, l4_protocol l4_proto);
int init_ipv6_tuple(struct tuple *tuple6, unsigned char *src_addr, __u16 src_port,
		unsigned char *dst_addr, __u16 dst_port, l4_protocol l4_proto);


#endif /* _JOOL_UNIT_TYPES_H */
