#ifndef _XT_NAT64_MODULE_COMM_H
#define _XT_NAT64_MODULE_COMM_H

/**
 * @file
 * Elements usable both by the kernel module and the userspace application.
 * Example from:
 * http://stackoverflow.com/questions/862964/who-can-give-me-the-latest-netlink-programming-samples
 *
 * @author Miguel Gonzalez
 * @author Alberto Leiva  <- maintenance
 */

#include <linux/types.h>
#include "nat64/comm/types.h"


//#define MSG_TYPE_CONF (0x10 + 2)  ///< Netlink socket packet ID, configuration
//#define MSG_TYPE_ROUTE (0x10 + 3)  ///< Netlink socket packet ID, static routes 
#define MSG_TYPE_NAT64 (0x10 + 2)  ///< Netlink socket packet ID, configuration

#define MSG_SETCFG      0x11
#define MSG_GETCFG      0x12

enum config_mode {
	MODE_POOL6 = 1,
	MODE_POOL4,
	MODE_BIB,
	MODE_SESSION,
	MODE_FILTERING,
	MODE_TRANSLATE,
};

enum config_operation {
	/* The following apply when mode is pool6, pool4, BIB or session. */
	OP_DISPLAY,
	OP_ADD,
	OP_REMOVE,

	/* The following apply when mode is filtering or translate. */
	#define SKB_HEAD_ROOM_MASK		(1 << 0)
	#define SKB_TAIL_ROOM_MASK		(1 << 1)
	#define RESET_TCLASS_MASK		(1 << 2)
	#define RESET_TOS_MASK			(1 << 3)
	#define NEW_TOS_MASK			(1 << 4)
	#define DF_ALWAYS_ON_MASK		(1 << 5)
	#define BUILD_IPV4_ID_MASK		(1 << 6)
	#define LOWER_MTU_FAIL_MASK		(1 << 7)
	#define IPV6_NEXTHOP_MTU_MASK	(1 << 8)
	#define IPV4_NEXTHOP_MTU_MASK	(1 << 9)
	#define MTU_PLATEAUS_MASK		(1 << 10)

	#define DROP_BY_ADDR_MASK		(1 << 0)
	#define DROP_ICMP6_INFO_MASK	(1 << 1)
	#define DROP_EXTERNAL_TCP_MASK	(1 << 2)
	#define UDP_TIMEOUT_MASK		(1 << 3)
	#define ICMP_TIMEOUT_MASK		(1 << 4)
	#define TCP_EST_TIMEOUT_MASK	(1 << 5)
	#define TCP_TRANS_TIMEOUT_MASK 	(1 << 6)
};

/**
 * A BIB entry, from the eyes of userspace ("us" stands for userspace).
 *
 * It's a stripped version of "struct bib_entry" and only used when BIBs need to travel to
 * userspace. For anything else, use "struct bib_entry" from bib.h.
 *
 * See bib.h for the fields' doc.
 */
struct bib_entry_us {
	struct ipv4_tuple_address ipv4;
	struct ipv6_tuple_address ipv6;
};

/**
 * A session entry, from the eyes of userspace ("us" stands for userspace).
 *
 * It's a stripped version of "struct session_entry" and only used when sessions need to travel to
 * userspace. For anything else, use "struct session_entry" from session.h.
 *
 * See session.h for the fields' doc.
 */
struct session_entry_us {
	struct ipv6_pair ipv6;
	struct ipv4_pair ipv4;
	bool is_static;
	unsigned int dying_time;
	u_int8_t l4_proto;
};

/**
 * Configuration for the "Filtering and Updating" module.
 */
struct filtering_config {
	/** Use Address-Dependent Filtering? */
	bool drop_by_addr;
	/** Filter ICMPv6 Informational packets */
	bool drop_icmp6_info;
	/** Drop externally initiated TCP connections? (IPv4 initiated) */
	bool drop_external_tcp;
	/** Current timeout values */
	struct timeouts {
		unsigned int udp;
		unsigned int icmp;
		unsigned int tcp_est;
		unsigned int tcp_trans;
	} to;
};

/**
 * Configuration for the "Translate the packet" module.
 */
struct translate_config {
	/**
	 * Extra bytes the translator will allocate at the head of the packets it generates. These are
	 * meant to be used by other Netfilter modules for futher alien functionality (Eg. Add
	 * additional headers withoug having to reallocate the packet).
	 * Can be negative, if the user wants to compensate for the "LL_MAX_HEADER" constant.
	 * (LL_MAX_HEADER = the kernel's reserved head room + l2 header's length.)
	 *
	 * TODO (later) LL_MAX_HEADER is probably intended for this very purpose, so these two values
	 * are probably redundant.
	 */
	__u16 skb_head_room;
	/**
	 * Extra bytes the translator will allocate at the tail of the packets it generates. See
	 * "skb_head_room".
	 */
	__u16 skb_tail_room;

	/**
	 * "true" if the Traffic Class field of the translated IPv6 header should always be set to zero.
	 * Otherwise it will be copied from the IPv4 header's TOS field.
	 */
	bool reset_traffic_class;
	/**
	 * "true" if the Type of Service (TOS) field of the translated IPv4 header should always be set
	 * to "new_tos".
	 * Otherwise it will be copied from the IPv6 header's Traffic Class field.
	 */
	bool reset_tos;
	/**
	 * If "reset_tos" is "true", this is the value the translator will always write in the TOS field
	 * of the translated IPv4 headers.
	 * If "reset_tos" is "false", then this doesn't do anything.
	 */
	__u8 new_tos;
	/**
	 * If "true", the translator will always set the translated IPv4 header's Don't Fragment (DF)
	 * flag to one.
	 * Otherwise the flag will be set depending on the packet's length.
	 */
	bool df_always_on;
	/**
	 * Whether the translated IPv4 header's Identification field should be computed (Either from the
	 * IPv6 fragment header's Identification field or deduced from the packet's length).
	 * Otherwise it will always be set to zero.
	 */
	bool build_ipv4_id;
	/**
	 * "true" if the value for the MTU field of outgoing ICMPv6 fragmentation needed packets should
	 * be set to no less than 1280, regardless of MTU plateaus and whatnot.
	 * See RFC 6145 section 6, second approach.
	 */
	bool lower_mtu_fail;

	// TODO (info) how can we compute these automatically?
	__u16 ipv6_nexthop_mtu;
	__u16 ipv4_nexthop_mtu;

	/** Length of the mtu_plateaus array. */
	__u16 mtu_plateau_count;
	/**
	 * If the translator detects the source of the incoming packet does not implement RFC 1191,
	 * these are the plateau values used to determine a likely path MTU for outgoing ICMPv6
	 * fragmentation needed packets.
	 * The translator is supposed to pick the greatest plateau value that is less than the incoming
	 * packet's Total Length field.
	 * Default value is { 65535, 32000, 17914, 8166, 4352, 2002, 1492, 1006, 508, 296, 68 }.
	 */
	__u16 *mtu_plateaus;
};


struct request_hdr {
	__u32 length;
	__u16 mode;
	__u32 operation;
};

union request_pool6 {
	struct {
		// Nothing needed here ATM.
	} display;
	struct {
		struct ipv6_prefix prefix;
	} update;
};

union request_pool4 {
	struct {
		// Nothing needed there ATM.
	} display;
	struct {
		__u8 l4_proto;
		struct in_addr addr;
	} update;
};

union request_bib {
	struct {
		u_int8_t l4_proto;
	} display;
};

struct request_session {
	__u8 l4_proto;
	union {
		struct {
			// Nothing needed here.
		} display;
		struct {
			struct ipv6_pair pair6;
			struct ipv4_pair pair4;
		} add;
		struct {
			__u16 l3_proto;
			union {
				struct ipv6_pair pair6;
				struct ipv4_pair pair4;
			};
		} remove;
	};
};

// Because of the somewhat intrusive nature of the netlink header, response header structures are
// not really neccesary.


int serialize_translate_config(struct translate_config *config,
		unsigned char **buffer_out, __u16 *buffer_len_out);
int deserialize_translate_config(void *buffer, __u16 buffer_len,
		struct translate_config *target_out);

#endif
