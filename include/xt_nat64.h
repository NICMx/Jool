#ifndef _XT_NAT64_H
#define _XT_NAT64_H

#include <linux/module.h>

/**
 * @file
 * Module main. Both the entry point and the general structure can be found here.
 */

/*
 * Flags that indicate the information needed for the NAT64 device.
 *
 * TODO no debería estar en libxt_nat64.h?
 */
enum
{
	XT_NAT64_IP_SRC = 1 << 0, //
	XT_NAT64_IP_DST = 1 << 1, //
	XT_NAT64_IPV6_DST = 1 << 2, //
	XT_NAT64_OUT_DEV = 1 << 3,
};

/**
 * TODO no debería estar en libxt_nat64.h?
 */
struct xt_nat64_tginfo
{
	union nf_inet_addr ipdst, ipdst_mask;
	union nf_inet_addr ipsrc, ipsrc_mask;
	union nf_inet_addr ip6dst, ip6dst_mask;
	__u16 l4proto;
	char out_dev[IFNAMSIZ];
	char out_dev_mask[IFNAMSIZ];
	__u8 flags;
};

/**
 * Transport layer protocols allowed by the NAT64 implementation when the
 * network protocol is IPv4.
 */
#define NAT64_IP_ALLWD_PROTOS (IPPROTO_TCP | IPPROTO_UDP | IPPROTO_ICMP)
/**
 * Transport layer protocols allowed by the NAT64 implementation when the
 * network protocol is IPv6.
 */
#define NAT64_IPV6_ALLWD_PROTOS (IPPROTO_TCP | IPPROTO_UDP | IPPROTO_ICMPV6)


#endif /* _XT_NAT64_H */
