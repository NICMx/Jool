#ifndef _NF_NAT64_FRAGMENT_DB_H
#define _NF_NAT64_FRAGMENT_DB_H


#include "nat64/mod/packet.h"

int fragdb_init(void);
verdict fragment_arrives_ipv4(struct sk_buff *skb, struct packet **result);
void fragdb_destroy(void);


#endif /* _NF_NAT64_FRAGMENT_DB_H */
