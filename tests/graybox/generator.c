#include "generator.h"

enum l3type {
	L3TYPE_IPV4,
	L3TYPE_IPv6,
	L3TYPE_OTHER
};

enum l4type {
	L4TYPE_UDP,
	L4TYPE_TCP,
	L4TYPE_ICMP_INFO,
	/** Inner packet was not truncated (we need to validate checksum on these). */
	L4TYPE_ICMP_ERR_COMPLETE,
	L4TYPE_ICMP_ERR_TRUNCATED,
	L4TYPE_OTHER
};

enum csum_status {
	CSUM_CORRECT,
	CSUM_WRONG,
	CSUM_ZERO
};

enum addr_type {
	/** Packet's destination address belongs to the respective pool. */
	ADDRTYPE_JOOL,
	/** Packet's destination address does not belong to the respective pool. */
	ADDRTYPE_LOST,
	/**
	 * Packet's IPv6 destination address contains a pool4 address as suffix.
	 * Applies to IPv6 packets only.
	 */
	ADDRTYPE_HAIRPIN
};

union pkt_id {
	__u32 full;
	/** See enum l3type. */
	__u32 l3type : 2,
	/** See enum l4type. */
		l4type : 3,
	/**
	 * Zero means "no fragment header". One means "atomic fragment".
	 * Two means "two fragments", three means "three fragments".
	 * Zero and one are the same thing in IPv4.
	 */
		frag_count : 2,
	/**
	 * See enum csum_status.
	 * This is always the layer-4 checksum.
	 */
		csum_status : 2,
	/** See enum addr_type. */
		addr_type : 2;

	/* I'll probably use the rest of the bits as error conditions in the future. */
};

int create_skb(__u64 id, struct sk_buff *skb)
{
	union pkt_id pid;
	pid.full = id;

	if (pid.is_frag) {
		send_pkt();
	}
}
