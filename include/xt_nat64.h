#ifndef _LINUX_NETFILTER_XT_NAT64_H
#define _LINUX_NETFILTER_XT_NAT64_H
#include <linux/in.h>
#include <linux/in6.h>

/*
 * Flags that indicate the information needed for the NAT64 device.
 */
enum {
	XT_NAT64_IP_SRC = 1 << 0,
	XT_NAT64_IP_DST = 1 << 1,
	XT_NAT64_IPV6_DST = 1 << 2,
};

struct xt_nat64_tginfo {
	union nf_inet_addr ipdst, ipdst_mask;
	union nf_inet_addr ipsrc, ipsrc_mask;
	union nf_inet_addr ip6dst, ip6dst_mask;
	__u16 l4proto;
	__u8 flags;
};

/*
 * Constants that hold the allowed L4 protocols that are allowed by the NAT64
 * implementation.
 */
#define NAT64_IP_ALLWD_PROTOS (IPPROTO_TCP | IPPROTO_UDP | IPPROTO_ICMP)
#define NAT64_IPV6_ALLWD_PROTOS (IPPROTO_TCP | IPPROTO_UDP | IPPROTO_ICMPV6) 
#endif /* _LINUX_NETFILTER_XT_NAT64_H */
