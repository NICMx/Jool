#include "nat64/mod/common/alg/ftp/core.h"

void xlat_eprt_into_port(struct packet *pkt)
{
	if (eprt.addr is IPv6 && eprt.addr == original_pkt.src_addr) {
		addr, port = pool4_allocate_same_address(pkt.src_addr);
		bib = bibdb_add(eprt.addr, eprt.port, addr, port);
		port(pkt, addr, port);
	}
}
