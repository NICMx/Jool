#include "icmp-wrapper.h"

#include <linux/icmpv6.h>
#include <linux/version.h>
#include <net/icmp.h>

static char *icmp_error_to_string(icmp_error_code error)
{
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

static void icmp64_send4(struct sk_buff *skb, icmp_error_code error, __u32 info)
{
	int type, code;

	/*
	 * Just going to leave this here:
	 *
	 * icmp_send() *NEEDS* the skb to contain some sort of valid dst.
	 * I don't know why. We're trying to answer to a misdirected packet.
	 * Why would an established destination be mandatory for that?
	 *
	 * The rationale for this has been lost to time. The quirk is already
	 * present in the first git commit of Linux and I can't find the old
	 * BitKeeper repository.
	 *
	 * If the packet doesn't have a dst, icmp_send() bails immediately
	 * and that turns the whole thing into a no-op. It's fucking bullshit.
	 *
	 * Now, ever since Jool became a device driver this hasn't been a
	 * problem, probably. By the time the skb reaches the device it already
	 * has a destination, and it's probably perfect for icmp_send()'s
	 * purposes.
	 *
	 * But if you commit to the generic framework project, this might once
	 * again become a topic.
	 *
	 * Old Netfilter Jool used to solve this by "in-routing" the packet.
	 * (A call to ip_route_input().) Other frameworks might require other
	 * kinds of magic, such as a call to rt_dst_alloc() or something like
	 * that.
	 */

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

	log_debug("Sending ICMPv4 error: %s, type: %d, code: %d.",
			icmp_error_to_string(error), type, code);
	icmp_send(skb, type, code, cpu_to_be32(info));
}

static void icmp64_send6(struct sk_buff *skb, icmp_error_code error, __u32 info)
{
	int type, code;

	switch (error) {
	case ICMPERR_ADDR_UNREACHABLE:
		type = ICMPV6_DEST_UNREACH;
		code = ICMPV6_ADDR_UNREACH;
		break;
	case ICMPERR_PORT_UNREACHABLE:
	case ICMPERR_PROTO_UNREACHABLE:
		/*
		 * "If the incoming packet is an IPv6 packet that contains a
		 * protocol other than TCP, UDP, or ICMPv6 in the last Next
		 * Header, then the packet SHOULD be discarded and, if the
		 * security policy permits, the NAT64 SHOULD send an ICMPv6
		 * Destination Unreachable error message with Code 4 (Port
		 * Unreachable) to the source address of the received packet."
		 * - RFC 6146
		 *
		 * Yes, it's strange that we're complaining about ports when the
		 * problem was the protocol, but on the other hand, RFC 2463
		 * does not reserve "Protocol Unreachable" like RFC 792. On top
		 * of that, RFC 6146 even states the code (4). It doesn't seem
		 * to be a typo.
		 */
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

	/*
	 * RHELs 7.0 and 7.1 behave just like kernel 3.11, while 7.2 behaves
	 * like 3.13. Lucky us ;p
	 */
#if defined RHEL_VERSION_CODE \
		|| LINUX_VERSION_CODE < KERNEL_VERSION(3, 12, 0) \
		|| LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0)
	log_debug("Sending ICMPv6 error: %s, type: %d, code: %d",
			icmp_error_to_string(error), type, code);
	icmpv6_send(skb, type, code, info);
#else
#warning "You're compiling in kernel 3.12. See https://github.com/NICMx/Jool/issues/90"
#endif
}

void icmp64_send(struct packet *pkt, icmp_error_code error, __u32 info)
{
	icmp64_send_skb(pkt_original_pkt(pkt)->skb, error, info);
}

void icmp64_send_skb(struct sk_buff *skb, icmp_error_code error, __u32 info)
{
	if (unlikely(!skb))
		return;

	switch (ntohs(skb->protocol)) {
	case ETH_P_IP:
		icmp64_send4(skb, error, info);
		break;
	case ETH_P_IPV6:
		icmp64_send6(skb, error, info);
		break;
	}
}
