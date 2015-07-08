#ifndef _JOOL_MOD_NF_HOOK_H
#define _JOOL_MOD_NF_HOOK_H

#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>

#define NF_IP_PRI_JOOL (NF_IP_PRI_NAT_DST + 25)
#define NF_IP6_PRI_JOOL (NF_IP6_PRI_NAT_DST + 25)

#endif /* _JOOL_MOD_NF_HOOK_H */
