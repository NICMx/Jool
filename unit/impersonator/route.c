#include "nat64/mod/common/route.h"
#include "nat64/mod/common/types.h"

struct dst_entry *route4(struct packet *pkt)
{
	log_debug("Pretending I'm routing an IPv4 packet.");
	return NULL;
}

struct dst_entry *route6(struct packet *pkt)
{
	log_debug("Pretending I'm routing an IPv6 packet.");
	return NULL;
}

struct dst_entry *route(struct packet *pkt)
{
	log_debug("Pretending I'm routing a packet.");
	return NULL;
}
