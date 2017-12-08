#ifndef _JOOL_MOD_TYPES_H
#define _JOOL_MOD_TYPES_H

/**
 * @file
 * Kernel-specific core data types and routines.
 */

#include "nat64/common/types.h"
#include <linux/netfilter.h>
#include <linux/kernel.h>
#include "nat64/common/xlat.h"
#include "nat64/mod/common/address.h"
#include "nat64/mod/common/error_pool.h"

/**
 * An indicator of what a function expects its caller to do with the packet being translated.
 */
typedef enum verdict {
	/** "No problems thus far, processing of the packet can continue." */
	VERDICT_CONTINUE = -1,
	/**
	 * "Packet is invalid and should be silently dropped."
	 * (Or "packet is invalid and I already sent a ICMP error, so just kill it".)
	 */
	VERDICT_DROP = NF_DROP,
	/**
	 * "Packet is not supposed to be NAT64'd. Return it to Netfilter so the kernel does something
	 * else with it."
	 */
	VERDICT_ACCEPT = NF_ACCEPT,
	/**
	 * "I need to keep the packet for a while. Do not free, access or modify it."
	 *
	 * The packet being stored is THE ORIGINAL PACKET.
	 * The "original packet" will be different from the "incoming packet" in hairpinning.
	 * Therefore, if your stealing/storing code doesn't include skb_original_skb(), then YOU HAVE
	 * A KERNEL PANIC.
	 */
	VERDICT_STOLEN = NF_STOLEN,
} verdict;

/**
 * A tuple is sort of a summary of a packet; it is a quick accesor for several of its key elements.
 *
 * Keep in mind that the tuple's values do not always come from places you'd normally expect.
 * Unless you know ICMP errors are not involved, if the RFC says "the tuple's source address",
 * then you *MUST* extract the address from the tuple, not from the packet.
 * Conversely, if it says "the packet's source address", then *DO NOT* extract it from the tuple
 * for convenience. See comments inside for more info.
 */
struct tuple {
	/**
	 * Most of the time, this is the packet's _source_ address and layer-4 identifier. When the
	 * packet contains a inner packet, this is the inner packet's _destination_ address and l4 id.
	 */
	union transport_addr src;

	/**
	 * Most of the time, this is the packet's _destination_ address and layer-4 identifier. When
	 * the packet contains a inner packet, this is the inner packet's _source_ address and l4 id.
	 */
	union transport_addr dst;

	/**
	 * The packet's network protocol. This is the sure way to know which of the above union
	 * elements should be used.
	 */
	l3_protocol l3_proto;
	/**
	 * The packet's transport protocol that counts.
	 *
	 * Most of the time, this is the packet's simple l4-protocol. When the packet contains a inner
	 * packet, this is the inner packet's l4-protocol.
	 *
	 * This dictates whether this is a 5-tuple or a 3-tuple (see is_3_tuple()/is_5_tuple()).
	 */
	l4_protocol l4_proto;

/**
 * By the way: There's code that depends on src.<x>.l4_id containing the same value as
 * dst.<x>.l4_id when l4_proto == L4PROTO_ICMP (i. e. 3-tuples).
 */
#define icmp4_id src.addr4.l4
#define icmp6_id src.addr6.l4
};

/**
 * Returns true if "tuple" represents a '3-tuple' (address-address-ICMP id), as defined by the RFC.
 */
static inline bool is_3_tuple(struct tuple *tuple)
{
	return (tuple->l4_proto == L4PROTO_ICMP);
}

/**
 * Returns true if "tuple" represents a '5-tuple' (address-port-address-port-transport protocol),
 * as defined by the RFC.
 */
static inline bool is_5_tuple(struct tuple *tuple)
{
	return !is_3_tuple(tuple);
}

/**
 * Prints "tuple" pretty in the log.
 */
void log_tuple(struct tuple *tuple);

/**
 * @{
 * Returns true if "type" (which is assumed to have been extracted from a ICMP header) represents
 * a packet involved in a ping.
 */
bool is_icmp6_info(__u8 type);
bool is_icmp4_info(__u8 type);
/**
 * @}
 */

/**
 * @{
 * Returns true if "type" (which is assumed to have been extracted from a ICMP header) represents
 * a packet which is an error response.
 */
bool is_icmp6_error(__u8 type);
bool is_icmp4_error(__u8 type);
/**
 * @}
 */

#endif /* _JOOL_MOD_TYPES_H */
