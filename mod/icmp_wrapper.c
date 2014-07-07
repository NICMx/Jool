#include "nat64/mod/icmp_wrapper.h"

#include <linux/version.h>
#include <net/icmp.h>
#include <linux/icmpv6.h>

static void icmp4_send(struct sk_buff *skb, icmp_error_code error, __be32 info)
{
	int type, code;

	switch (error) {
	case ICMPERR_ADDR_UNREACHABLE:
		type = ICMP_DEST_UNREACH;
		code = ICMP_HOST_UNREACH;
		break;
	case ICMPERR_PORT_UNREACHABLE:
		type = ICMP_DEST_UNREACH;
		code = ICMP_PORT_UNREACH;
		break;
	case ICMPERR_PROTO_UNREACHABLE:
		type = ICMP_DEST_UNREACH;
		code = ICMP_PROT_UNREACH;
		break;
	case ICMPERR_HOP_LIMIT:
		type = ICMP_TIME_EXCEEDED;
		code = ICMP_EXC_TTL;
		break;
	case ICMPERR_FRAG_NEEDED:
		type = ICMP_DEST_UNREACH;
		code = ICMP_FRAG_NEEDED;
		break;
	case ICMPERR_FILTER:
		type = ICMP_DEST_UNREACH;
		code = ICMP_PKT_FILTERED;
		break;
	case ICMPERR_SRC_ROUTE:
		type = ICMP_DEST_UNREACH;
		code = ICMP_SR_FAILED;
		break;
	default:
		return; /* Not supported or needed. */
	}

	skb_clear_cb(skb);
	icmp_send(skb, type, code, info);
}

static void icmp6_send(struct sk_buff *skb, icmp_error_code error, __be32 info)
{
	int type, code;

	switch (error) {
	case ICMPERR_ADDR_UNREACHABLE:
		type = ICMPV6_DEST_UNREACH;
		code = ICMPV6_ADDR_UNREACH;
		break;
	case ICMPERR_PROTO_UNREACHABLE:
		type = ICMPV6_PARAMPROB;
		code = ICMPV6_UNK_NEXTHDR;
		break;
	case ICMPERR_HOP_LIMIT:
		type = ICMPV6_TIME_EXCEED;
		code = ICMPV6_EXC_HOPLIMIT;
		break;
	case ICMPERR_FILTER:
		type = ICMPV6_DEST_UNREACH;
		code = ICMPV6_ADM_PROHIBITED;
		break;
	case ICMPERR_HDR_FIELD:
		type = ICMPV6_PARAMPROB;
		code = ICMPV6_HDR_FIELD;
		break;
	default:
		return; /* Not supported or needed. */
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 12, 0) || KERNEL_VERSION(3, 13, 0) <= LINUX_VERSION_CODE
	skb_clear_cb(skb);
	icmpv6_send(skb, type, code, info);
#else
#warning "You're compiling in kernel 3.12. See https://github.com/NICMx/NAT64/issues/90"
#endif
}

void icmp64_send(struct sk_buff *skb, icmp_error_code error, __be32 info)
{
	struct sk_buff *original_skb = skb_original_skb(skb);

	if (!original_skb || !original_skb->dev)
		return;

	switch (ntohs(original_skb->protocol)) {
	case ETH_P_IP:
		icmp4_send(original_skb, error, info);
		break;
	case ETH_P_IPV6:
		icmp6_send(original_skb, error, info);
		break;
	}
}
