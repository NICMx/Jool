#include "nat64/mod/icmp_wrapper.h"
#include "nat64/mod/types.h"

#include <linux/version.h>
#include <net/icmp.h>
#include <linux/icmpv6.h>

static char *icmp_error_to_string(icmp_error_code error) {
	switch (error) {
	case ICMPERR_SILENT:
		return "ICMPERR_SILENT";
		break;
	case ICMPERR_ADDR_UNREACHABLE:
		return "ICMPERR_ADDR_UNREACHABLE";
		break;
	case ICMPERR_PORT_UNREACHABLE:
		return "ICMPERR_PORT_UNREACHABLE";
		break;
	case ICMPERR_PROTO_UNREACHABLE:
		return "ICMPERR_PROTO_UNREACHABLE";
		break;
	case ICMPERR_HOP_LIMIT:
		return "ICMPERR_HOP_LIMIT";
		break;
	case ICMPERR_FRAG_NEEDED:
		return "ICMPERR_FRAG_NEEDED";
		break;
	case ICMPERR_HDR_FIELD:
		return "ICMPERR_HDR_FIELD";
		break;
	case ICMPERR_SRC_ROUTE:
		return "ICMPERR_SRC_ROUTE";
		break;
	case ICMPERR_FILTER:
		return "ICMPERR_FILTER";
		break;
	}

	return "Unknown";
}

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
	log_debug("Sending ICMPv4 error: %s, type: %d, code: %d.", icmp_error_to_string(error), type,
			code);
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
	case ICMPERR_PORT_UNREACHABLE:
		type = ICMPV6_DEST_UNREACH;
		code = ICMPV6_PORT_UNREACH;
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
	case ICMPERR_FRAG_NEEDED:
		type = ICMPV6_PKT_TOOBIG;
		code = 0; /* No code. */
		break;
	default:
		return; /* Not supported or needed. */
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 12, 0) || KERNEL_VERSION(3, 13, 0) <= LINUX_VERSION_CODE
	skb_clear_cb(skb);
	log_debug("Sending ICMPv6 error: %s, type: %d, code: %d", icmp_error_to_string(error), type,
			code);
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
