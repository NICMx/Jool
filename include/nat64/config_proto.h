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
#include "nat64/types.h"


//#define MSG_TYPE_CONF (0x10 + 2)  ///< Netlink socket packet ID, configuration
//#define MSG_TYPE_ROUTE (0x10 + 3)  ///< Netlink socket packet ID, static routes 
#define MSG_TYPE_NAT64 (0x10 + 2)  ///< Netlink socket packet ID, configuration


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
	#define BIB_MASK (1 << 0)
	#define SESSION_MASK (1 << 1)
	#define IPV6_MASK (1 << 2)
	#define IPV4_MASK (1 << 3)
	#define HAIR_MASK (1 << 4)
	#define PHR_MASK (1 << 5)
	#define PTR_MASK (1 << 6)
	#define OIPV6_MASK (1 << 7)
	#define OIPV4_MASK (1 << 8)
	#define IPV4_TRAFFIC_MASK (1 << 9)
	#define DF_ALWAYS_MASK (1 << 10)
	#define GEN_IPV4_MASK (1 << 11)
	#define IMP_MTU_FAIL_MASK (1 << 12)
	#define IPV6_NEXTHOP_MASK (1 << 13)
	#define IPV4_NEXTHOP_MASK (1 << 14)
	#define MTU_PLATEAUS_MASK (1 << 15)

	#define ADDRESS_DEPENDENT_FILTER_MASK	(1 << 0)
	#define FILTER_INFO_MASK				(1 << 1)
	#define DROP_TCP_MASK					(1 << 2)
	#define UDP_TIMEOUT_MASK				(1 << 3)
	#define ICMP_TIMEOUT_MASK				(1 << 4)
	#define TCP_EST_TIMEOUT_MASK			(1 << 5)
	#define TCP_TRANS_TIMEOUT_MASK 			(1 << 6)
};

enum response_code {
	RESPONSE_SUCCESS = 0,
	RESPONSE_UNKNOWN_MODE,
	RESPONSE_UNKNOWN_OP,
	RESPONSE_UNKNOWN_L3PROTO,
	RESPONSE_UNKNOWN_L4PROTO,
	RESPONSE_NOT_FOUND,
	RESPONSE_ALLOC_FAILED,
	RESPONSE_CONNECT_FAILED,
	RESPONSE_SEND_FAILED,
	RESPONSE_PARSE_FAIL,
	RESPONSE_INVALID_VALUE,
	RESPONSE_MISSING_PARAM,
	RESPONSE_UNKNOWN_ERROR,
};

/**
 * A BIB entry, from the eyes of userspace ("us" stands for userspace).
 *
 * It's a stripped version of "struct bib_entry" and only used when BIBs need to travel to
 * userspace. For anything else, use "struct bib_entry" from *_bib.h.
 *
 * See *_bib.h for the fields' doc.
 */
struct bib_entry_us {
	struct ipv4_tuple_address ipv4;
	struct ipv6_tuple_address ipv6;
};

/**
 * A session entry, from the eyes of userspace ("us" stands for userspace).
 *
 * It's a stripped version of "struct session_entry" and only used when sessions need to travel to
 * userspace. For anything else, use "struct session_entry" from *_session.h.
 *
 * See *_session.h for the fields' doc.
 */
struct session_entry_us {
	struct ipv6_pair ipv6;
	struct ipv4_pair ipv4;
	bool is_static;
	unsigned int dying_time;
	u_int8_t l4protocol;
};

/**
 * Configuration for the "Filtering and Updating" module.
 */
struct filtering_config {
	/** Use Address-Dependent Filtering? */
	bool address_dependent_filtering;
	/** Filter ICMPv6 Informational packets */
	bool filter_informational_icmpv6;
	/** Drop externally initiated TCP connections? (IPv4 initiated) */
	bool drop_externally_initiated_tcp_connections;
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
	 * The user's reserved head room in bytes. Default should be 0.
	 * Can be negative, if the user wants to compensate for the LL_MAX_HEADER constant.
	 * (LL_MAX_HEADER = the kernel's reserved head room + l2 header's length.)
	 */
	__u16 packet_head_room;
	/** I suggest default = 32 bytes. */
	__u16 packet_tail_room;

	bool override_ipv6_traffic_class;
	/** Default should be false. */
	bool override_ipv4_traffic_class;
	__u8 ipv4_traffic_class;
	/** Default should be true. */
	bool df_always_set;

	/** Default should be false. */
	bool generate_ipv4_id;

	/** Default should be true; in fact I don't see why anyone would want it to be false. */
	bool improve_mtu_failure_rate;
	// TODO (info) how can we compute these automatically?
	__u16 ipv6_nexthop_mtu;
	__u16 ipv4_nexthop_mtu;

	/** Length of the mtu_plateaus array. */
	__u16 mtu_plateau_count;
	/** Default values are { 65535, 32000, 17914, 8166, 4352, 2002, 1492, 1006, 508, 296, 68 }. */
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

/**
 * Because the payload is sometimes a variable-length array, and as such I cannot make a struct
 * that can contain it without using pointers, a pointer to a header is actually a pointer to the
 * entire response.
 */
struct response_hdr {
	__u32 length;
	__u8 result_code;
};


bool serialize_translate_config(struct translate_config *config, unsigned char **buffer_out,
		__u16 *buffer_len_out);
bool deserialize_translate_config(void *buffer, __u16 buffer_len,
		struct translate_config *target_out);

#endif
