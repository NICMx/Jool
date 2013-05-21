#ifndef _NF_NAT64_PACKET_H
#define _NF_NAT64_PACKET_H

#include <linux/skbuff.h>
#include <linux/netfilter.h>

/**
 * @file
 * Validations over network and transport headers. The rest of the module tends to assume these
 * have been performed already, so it's a mandatory second step (first being linearization).
 *
 * Some of the functions from the kernel (eg. ip_rcv()) already cover the network header
 * validations, so they might seem unnecesary. But the kernel does change sporadically, so I'd
 * rather keep them JIC.
 *
 * On the other hand, the transport header checks are a must, since the packet hasn't reached the
 * kernel's transport layer when the module kicks in.
 */


enum verdict {
	/** No problems thus far, processing of the packet can continue. */
	VER_CONTINUE = -1,
	/** Packet is not meant for translation. Please hand it to the local host. */
	VER_ACCEPT = NF_ACCEPT,
	/** Packet is invalid and should be dropped. */
	VER_DROP = NF_DROP
};

/**
 * Validates the lengths and checksums of skb's IPv4 and transport headers.
 *
 * @param skb packet to validate.
 * @return validation result.
 */
enum verdict validate_skb_ipv4(struct sk_buff *skb);

/**
 * Validates the lengths and checksums of skb's IPv6 and transport headers.
 *
 * @param skb packet to validate.
 * @return validation result.
 */
enum verdict validate_skb_ipv6(struct sk_buff *skb);


#endif /* _NF_NAT64_PACKET_H */
