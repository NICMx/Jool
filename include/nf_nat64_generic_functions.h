/*
 * BEGIN: Generic Auxiliary Functions
 */

#ifndef _NF_NAT64_GENERIC_FUNCTIONS_H
#define _NF_NAT64_GENERIC_FUNCTIONS_H

#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/nf_conntrack_l3proto.h>
#include <net/netfilter/nf_conntrack_l4proto.h>
#include <net/netfilter/ipv4/nf_conntrack_ipv4.h>

/*
 * Function that receives a tuple and prints it.
 */
static inline void nat64_print_tuple(const struct nf_conntrack_tuple *t)
{
	pr_debug("NAT64: print_tuple -> l3 proto = %d", t->src.l3num);
	switch(t->src.l3num) {
		case NFPROTO_IPV4:
			pr_debug("NAT64: tuple %p: %u %pI4:%hu -> %pI4:%hu",
				t, t->dst.protonum,
				&t->src.u3.ip, ntohs(t->src.u.all),
				&t->dst.u3.ip, ntohs(t->dst.u.all));
		break;
		case NFPROTO_IPV6:
			pr_debug("NAT64: tuple %p: %u %pI6: %hu -> %pI6:%hu",
				t, t->dst.protonum,
				&t->src.u3.all, t->src.u.all,
				&t->dst.u3.all, t->dst.u.all);
		break;
		default:
			pr_debug("NAT64: Not IPv4 or IPv6?");
	}
}
/*
 * END: Generic Auxiliary Functions
 */
 #endif
