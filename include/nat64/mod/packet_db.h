#ifndef _NF_NAT64_PACKET_DB_H
#define _NF_NAT64_PACKET_DB_H

#include "nat64/mod/packet.h"


/* TODO llama al init y al destroy. */
int pktdb_init(void);
enum verdict pkt_from_skb(struct sk_buff *skb, struct packet **pkt);
void pktdb_destroy(void);


#endif /* _NF_NAT64_PACKET_DB_H */
