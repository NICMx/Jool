#include "nf_nat64_rfc6052.h"

__be32 nat64_extract_ipv4(struct in6_addr addr, int prefix)
{
	switch(prefix) {
		case 32:
			return addr.s6_addr32[1];
		case 40:
			return 0;	//FIXME
		case 48:
			return 0;	//FIXME
		case 56:
			return 0;	//FIXME
		case 64:
			return 0;	//FIXME
		case 96:
			return addr.s6_addr32[3];
		default:
			return 0;
	}
}

