#include "nat64/mod/common/handling_hairpinning.h"

#include "nat64/mod/common/send_packet.h"
#include "nat64/mod/common/rfc6145/core.h"


bool is_hairpin(struct packet *pkt)
{
	return pkt_is_hairpin(pkt);
}

verdict handling_hairpinning(struct packet *in, struct tuple *tuple)
{
	struct packet out;
	verdict result;

	log_debug("Packet is a hairpin. U-turning...");

	result = translating_the_packet(NULL, in, &out);
	if (result != VERDICT_CONTINUE)
		return result;
	result = sendpkt_send(in, &out);
	if (result != VERDICT_CONTINUE)
		return result;

	log_debug("Done hairpinning.");
	return VERDICT_CONTINUE;
}
