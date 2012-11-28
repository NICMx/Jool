#include "nf_nat64_types.h"
#include "nf_nat64_config.h"
#include "nf_nat64_handling_hairpinning.h"


bool nat64_got_hairpin(struct nf_conntrack_tuple *outgoing) {
	bool res = false;
	if (outgoing->l3_protocol == NFPROTO_IPV6) {
		// TODO (later) esto no debería ser un query a pool?
		if (ntohl(outgoing->dst.u3.in.s_addr) >= ntohl(config.ipv4_pool_range_first.s_addr) &&
			ntohl(outgoing->dst.u3.in.s_addr) <= ntohl(config.ipv4_pool_range_last.s_addr)) {
			res = true;
		} 
 	} 
	return res;
}
