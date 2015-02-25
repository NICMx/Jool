#include "nat64/mod/common/route.h"
#include "nat64/mod/common/types.h"

int route4(struct packet *pkt)
{
	log_debug("I'm pretending I'm sending an IPv4 packet.");
	return 0;
}

int route6(struct packet *pkt)
{
	log_debug("I'm pretending I'm sending an IPv6 packet.");
	return 0;
}

int route(struct packet *pkt)
{
	log_debug("I'm pretending I'm sending a packet.");
	return 0;
}
