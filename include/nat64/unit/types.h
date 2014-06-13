#ifndef _JOOL_UNIT_TYPES_H
#define _JOOL_UNIT_TYPES_H

#include "nat64/mod/types.h"


int init_pair6(struct ipv6_pair *pair6, unsigned char *remote_addr, u16 remote_id,
		unsigned char *local_addr, u16 local_id);
int init_pair4(struct ipv4_pair *pair4, unsigned char *remote_addr, u16 remote_id,
		unsigned char *local_addr, u16 local_id);

int init_ipv4_tuple(struct tuple *tuple, unsigned char *src_addr, __u16 src_port,
		unsigned char *dst_addr, __u16 dst_port, l4_protocol l4_proto);
int init_ipv6_tuple(struct tuple *tuple, unsigned char *src_addr, __u16 src_port,
		unsigned char *dst_addr, __u16 dst_port, l4_protocol l4_proto);

int init_ipv4_tuple_from_pair(struct tuple *tuple, struct ipv4_pair *pair4, l4_protocol l4_proto);
int init_ipv6_tuple_from_pair(struct tuple *tuple, struct ipv6_pair *pair6, l4_protocol l4_proto);


#endif /* _JOOL_UNIT_TYPES_H */
