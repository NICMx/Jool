#include "nat64/mod/common/icmp_wrapper.h"
#include "nat64/mod/common/types.h"

static int sent = 0;

void icmp64_send(struct packet *pkt, icmp_error_code code, __u32 info)
{
	log_debug("Pretending I'm sending an ICMP error.");
	sent++;
}

int icmp64_pop(void)
{
	int result = sent;
	sent = 0;
	return result;
}
