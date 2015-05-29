#include "nat64/mod/common/route.h"
#include "nat64/mod/common/types.h"

int route4(struct packet *pkt)
{
	log_debug("Pretending I'm routing an IPv4 packet.");
	return 0;
}

int route6(struct packet *pkt)
{
	log_debug("Pretending I'm routing an IPv6 packet.");
	return 0;
}

int route(struct packet *pkt)
{
	log_debug("Pretending I'm routing a packet.");
	return 0;
}
