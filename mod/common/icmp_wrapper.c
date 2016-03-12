#include "nat64/mod/common/icmp_wrapper.h"

#include <linux/icmpv6.h>
#include <linux/version.h>
#include <net/icmp.h>
#include "nat64/common/types.h"
#include "nat64/mod/common/route.h"

static char *icmp_error_to_string(icmp_error_code error) {
	switch (error) {
	case ICMPERR_SILENT:
		return "ICMPERR_SILENT";
	case ICMPERR_ADDR_UNREACHABLE:
		return "ICMPERR_ADDR_UNREACHABLE";
	case ICMPERR_PORT_UNREACHABLE:
		return "ICMPERR_PORT_UNREACHABLE";
	case ICMPERR_PROTO_UNREACHABLE:
		return "ICMPERR_PROTO_UNREACHABLE";
	case ICMPERR_HOP_LIMIT:
		return "ICMPERR_HOP_LIMIT";
	case ICMPERR_FRAG_NEEDED:
		return "ICMPERR_FRAG_NEEDED";
	case ICMPERR_HDR_FIELD:
		return "ICMPERR_HDR_FIELD";
	case ICMPERR_SRC_ROUTE:
		return "ICMPERR_SRC_ROUTE";
	case ICMPERR_FILTER:
		return "ICMPERR_FILTER";
	}

	return "Unknown";
}

static void icmp4_send(struct sk_buff *skb, icmp_error_code error, __u32 info)
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

	log_debug("Sending ICMPv4 error: %s, type: %d, code: %d.", icmp_error_to_string(error), type,
			code);
	icmp_send(skb, type, code, cpu_to_be32(info));
}

static void icmp6_send(struct sk_buff *skb, icmp_error_code error, __u32 info)
{
	int type, code;

	switch (error) {
	case ICMPERR_ADDR_UNREACHABLE:
		type = ICMPV6_DEST_UNREACH;
		code = ICMPV6_ADDR_UNREACH;
		break;
	case ICMPERR_PORT_UNREACHABLE:
	case ICMPERR_PROTO_UNREACHABLE: /* See RFC6146, determine incoming tuple step. */
		type = ICMPV6_DEST_UNREACH;
		code = ICMPV6_PORT_UNREACH;
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

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 12, 0) || LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0)
	log_debug("Sending ICMPv6 error: %s, type: %d, code: %d", icmp_error_to_string(error), type,
			code);
	icmpv6_send(skb, type, code, info);
#else
#warning "You're compiling in kernel 3.12. See https://github.com/NICMx/Jool/issues/90"
#endif
}

void icmp64_send(struct packet *pkt, icmp_error_code error, __u32 info)
{
	struct sk_buff *skb;
	int err;

	if (unlikely(!pkt))
		return;
	pkt = pkt_original_pkt(pkt);
	if (unlikely(!pkt))
		return;
	skb = pkt->skb;
	if (unlikely(!skb) || !skb->dev)
		return;

	/* Send the error. */
	switch (ntohs(skb->protocol)) {
	case ETH_P_IP:
		err = route4_input(pkt);
		if (err) {
			log_debug("Can't send an ICMPv4 Error: %d", err);
			return;
		}
		icmp4_send(skb, error, info);
		break;
	case ETH_P_IPV6:
		icmp6_send(skb, error, info);
		break;
	}
}
