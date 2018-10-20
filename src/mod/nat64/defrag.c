#include "mod/common/defrag.h"

#include <net/netfilter/ipv4/nf_defrag_ipv4.h>
#include <net/netfilter/ipv6/nf_defrag_ipv6.h>
#include "mod/common/linux_version.h"

void defrag_enable(struct net *ns)
{
#if LINUX_VERSION_AT_LEAST(4, 10, 0, 9999, 0)
	nf_defrag_ipv4_enable(ns);
	nf_defrag_ipv6_enable(ns);
#else
	nf_defrag_ipv4_enable();
	nf_defrag_ipv6_enable();
#endif
}
