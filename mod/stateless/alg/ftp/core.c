#include "nat64/mod/common/alg/ftp/core.h"

void xlat_eprt_into_port(struct packet *pkt)
{
	if (eprt.addr is IPv6 && eprt.addr == original_pkt.src_addr)
		port(pkt.src_addr, pkt.src_port);

	/* else do nothing. */
}
