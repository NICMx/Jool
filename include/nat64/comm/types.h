#ifndef _NF_NAT64_TYPES_H
#define _NF_NAT64_TYPES_H

/**
 * @file
 * The NAT64's core data types. Structures used all over the code.
 *
 * Both the kernel module and the userspace application can see this file.
 *
 * @author Miguel Gonzalez
 * @author Ramiro Nava
 * @author Roberto Aceves
 * @author Alberto Leiva
 */

#include <linux/types.h>
#ifdef __KERNEL__
	#include <linux/in.h>
	#include <linux/in6.h>
#else
	#include <stdbool.h>
	#include <arpa/inet.h>
#endif
#include <linux/netfilter.h>
#include "nat64/comm/nat64.h"


/**
 * Logging utilities, meant for standarization of error messages.
 */
#ifdef __KERNEL__
	#define log_error(func, id, text, ...) func("%s: ERR%d (%s): " text "\n", MODULE_NAME, id, \
			__func__, ##__VA_ARGS__)
	#define log_informational(func, text, ...) func(text "\n", ##__VA_ARGS__)
#else
	#define log_error(func, id, text, ...) printf("ERR%d: " text "\n", id, ##__VA_ARGS__)
	#define log_informational(func, text, ...) printf(text "\n", ##__VA_ARGS__)
#endif

/** Messages to help us walk through a run. */
#define log_debug(text, ...)	log_informational(pr_debug, text, ##__VA_ARGS__)
/** "I'm dropping the packet and it's perfectly normal." */
#define log_info(text, ...)		log_informational(pr_info, text, ##__VA_ARGS__)
/** "I'm dropping the packet because it's corrupted." (i. e. nothing's wrong with the NAT64) */
#define log_warning(text, ...)	log_informational(pr_warning, text, ##__VA_ARGS__)
/** "I'm dropping the packet because the config's flipped out or a kmalloc failed." */
#define log_err(id, text, ...)	log_error(pr_err, id, text, ##__VA_ARGS__)
/** "I'm dropping the packet because I detected a programming error." */
#define log_crit(id, text, ...)	log_error(pr_crit, id, text, ##__VA_ARGS__)

/**
 * Truth be told, I do not really have any use for these; I wish they would go away.
 * The error messages that come along during error log entries are much more informative.
 * So, sorry if I don't feel like documenting them.
 */
enum error_code {
	/* General */
	ERR_SUCCESS = 0,
	ERR_NULL = 1,
	ERR_L4PROTO = 2,
	ERR_L3PROTO = 3,
	ERR_ALLOC_FAILED = 4,
	ERR_UNKNOWN_ERROR = 5,
	ERR_ILLEGAL_NONE = 6,

	/* Config */
	ERR_NETLINK = 1000,
	ERR_MTU_LIST_EMPTY = 1001,
	ERR_MTU_LIST_ZEROES = 1002,
	ERR_UDP_TO_RANGE = 1003,
	ERR_TCPEST_TO_RANGE = 1004,
	ERR_TCPTRANS_TO_RANGE = 1005,
	ERR_PARSE_BOOL = 1006,
	ERR_PARSE_INT = 1007,
	ERR_INT_OUT_OF_BOUNDS = 1008,
	ERR_PARSE_INTARRAY = 1009,
	ERR_PARSE_ADDR4 = 1010,
	ERR_PARSE_ADDR6 = 1011,
	ERR_PARSE_ADDR4_PORT = 1012,
	ERR_PARSE_ADDR6_PORT = 1013,
	ERR_PARSE_PREFIX = 1014,
	ERR_UNKNOWN_OP = 1015,
	ERR_MISSING_PARAM = 1016,
	ERR_EMPTY_COMMAND = 1017,
	ERR_PREF_LEN_RANGE = 1018,
	ERR_POOL6_NOT_FOUND = 1019,
	ERR_POOL4_NOT_FOUND = 1020,
	ERR_POOL4_REINSERT = 1021,
	ERR_BIB_NOT_FOUND = 1022,
	ERR_BIB_REINSERT = 1023,
	ERR_FRAGMENTATION_TO_RANGE = 1024,

	/* IPv6 header iterator */
	ERR_INVALID_ITERATOR = 2000,
	ERR_MISSING_FRAG_HEADER = 2001,

	/* Pool6 */
	ERR_POOL6_EMPTY = 2200,
	/* Pool4 */
	ERR_POOL4_EMPTY = 2300,
	/* BIB */
	ERR_INCOMPLETE_INDEX_BIB = 2400,
	/* Session */
	ERR_SESSION_NOT_FOUND = 2500,
	ERR_SESSION_BIBLESS = 2501,
	ERR_INCOMPLETE_REMOVE = 2502,

	/* Incoming */
	ERR_CONNTRACK = 4000,
	/* Filtering */
	ERR_EXTRACT_FAILED = 4100,
	ERR_APPEND_FAILED = 4101,
	ERR_ADD_BIB_FAILED = 4102,
	ERR_ADD_SESSION_FAILED = 4103,
	ERR_INVALID_STATE = 4104,
	/* Outgoing */
	ERR_MISSING_BIB = 4200,
	/* Translate */
	ERR_INNER_PACKET = 4300,
	/* Hairpinning */
	/* Send packet */
	ERR_ROUTE_FAILED = 4500,
	ERR_SEND_FAILED = 4501,
};

/**
 * Returns nonzero if "status" is an error, returns zero if "status" represents success.
 *
 * This exists because if find stuff like this very baffling:
 * 		if (function_call()) {
 * 			log_err("Oh noes error");
 * 			return error;
 * 		}
 *
 * My common sense dictates that it should be like this:
 * 		if (!function_call()) {
 * 			log_err("Oh noes error");
 * 			return error;
 * 		}
 *
 * Or at least this:
 * 		if (is_error(function_call())) {
 * 			log_err("Oh noes error");
 * 			return error;
 * 		}
 */
static inline bool is_error(int status)
{
	/* https://dl.dropboxusercontent.com/u/95836775/Jool/genius.jpg */
	return status;
}

/**
 * An indicator of what a function expects its caller to do with the packet being translated.
 */
typedef enum verdict {
	/** "No problems thus far, processing of the packet can continue." */
	VER_CONTINUE = -1,
	/** "Packet is not meant for translation. Please hand it to the local host." */
	VER_ACCEPT = NF_ACCEPT,
	/**
	 * "Packet is invalid and should be silently dropped."
	 * (Or "packet is invalid and I already sent a ICMP error, so just kill it".)
	 */
	VER_DROP = NF_DROP,
	/*
	 * "Packet is a fragment, and I need more information to be able to translate it, so I'll keep
	 * it for a while. Do not free, access or modify it."
	 */
	VER_STOLEN = NF_STOLEN,
} verdict;

/**
 * Network (layer 3) protocols Jool is supposed to support.
 * We do not use PF_INET, PF_INET6, AF_INET or AF_INET6 because I want the compiler to pester me
 * during defaultless switch'es. Also, the zero-based index is convenient in the Translate Packet
 * module.
 */
typedef enum l3_protocol {
	/** RFC 2460. */
	L3PROTO_IPV6 = 0,
	/** RFC 791. */
	L3PROTO_IPV4 = 1,
#define L3_PROTO_COUNT 2
} l3_protocol;

/**
 * Returns a string version of "proto".
 * For debugging purposes really, but maybe we should use it more often during error messages.
 */
char *l3proto_to_string(l3_protocol proto);

/**
 * Transport (layer 4) protocols Jool is supposed to support.
 * We do not use IPPROTO_TCP and friends because I want the compiler to pester me during
 * defaultless switch'es. Also, the zero-based index is convenient in the Translate Packet module.
 * And lastly, L4PROTO_NONE is great at simplifying things.
 */
typedef enum l4_protocol {
	/**
	 * The packet has no layer-4 header. This happens if the packet is a fragment whose fragment
	 * offset is not zero.
	 * The packet still has a layer-4 protocol, of course, but the point is that the code should
	 * not attempt to extract a layer-4 header from it.
	 */
	L4PROTO_NONE = 0,
	/** The packet has a TCP header after the layer-3 headers. */
	L4PROTO_TCP = 1,
	/** The packet has a UDP header after the layer-3 headers. */
	L4PROTO_UDP = 2,
	/**
	 * The packet has a ICMP header after the layer-3 headers. Whether the header is ICMPv4 or
	 * ICMPv6 never matters.
	 * We know that ICMP is not a transport protocol, but for all intents and purposes, it behaves
	 * exactly like one in NAT64.
	 */
	L4PROTO_ICMP = 3,
#define L4_PROTO_COUNT 4
} l4_protocol;

/**
 * Returns a string version of "proto".
 * For debugging purposes really, but maybe we should use it more often during error messages.
 */
char *l4proto_to_string(l4_protocol proto);

/**
 * A layer-3 (IPv4) identifier attached to a layer-4 identifier (TCP port, UDP port or ICMP id).
 * Because they're paired all the time in this project.
 */
struct ipv4_tuple_address {
	/** The layer-3 identifier. */
	struct in_addr address;
	/** The layer-4 identifier (Either the port (TCP or UDP) or the ICMP id). */
	__u16 l4_id;
};

/**
 * A layer-3 (IPv6) identifier attached to a layer-4 identifier (TCP port, UDP port or ICMPv6 id).
 * Because they're paired all the time in this project.
 */
struct ipv6_tuple_address {
	/** The layer-3 identifier. */
	struct in6_addr address;
	/** The layer-4 identifier (Either the port (TCP or UDP) or the ICMP id). */
	__u16 l4_id;
};

/**
 * The IPv4 side of a connection: A remote node in some IPv4 network and the NAT64.
 */
struct ipv4_pair {
	/** The IPv4 node's address and port being used in the connection. */
	struct ipv4_tuple_address remote;
	/** Jool's address and port being used in the connection. */
	struct ipv4_tuple_address local;
};

/**
 * The IPv6 side of a connection: A remote node in some IPv6 network and the NAT64.
 */
struct ipv6_pair {
	/** The NAT64's address and port being used in the connection. */
	struct ipv6_tuple_address local;
	/** Jool's address and port being used in the connection. */
	struct ipv6_tuple_address remote;
};

/**
 * A member of the IPv6 pool; the network component of a IPv6 address.
 */
struct ipv6_prefix {
	/** IPv6 prefix. */
	struct in6_addr address;
	/** Number of bits from "address" which represent the network. */
	__u8 len;
};

struct tuple_addr {
	union {
		struct in_addr ipv4;
		struct in6_addr ipv6;
	} addr;
	__u16 l4_id;
};

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
	struct tuple_addr src;
	/**
	 * Most of the time, this is the packet's _destination_ address and layer-4 identifier. When
	 * the packet contains a inner packet, this is the inner packet's _source_ address and l4 id.
	 */
	struct tuple_addr dst;
	/** The packet's network protocol. */
	l3_protocol l3_proto;
	/**
	 * The packet's transport protocol that counts.
	 *
	 * Most of the time, this is the packet's simple l4-protocol. When the packet contains a inner
	 * packet, this is the inner packet's l4-protocol.
	 * Also, keep in mind that tuples represent whole packets, not fragments. If a packet's
	 * fragment offset is not zero, then its layer 4 protocol will be L4PROTO_NONE, but its tuple's
	 * l4_proto will be something else.
	 */
	l4_protocol l4_proto;

/**
 * By the way: There's code that depends on src.l4_id containing the same value as dst.l4_id when
 * l4_proto == L4PROTO_ICMP (i. e. 3-tuples).
 */
#define icmp_id src.l4_id
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
 * Returns "true" if the first parameter is the same as the second one, even if they are pointers
 * to different places in memory.
 *
 * @param a struct you want to compare to "b".
 * @param b struct you want to compare to "a".
 * @return (*addr_1) === (*addr_2), with null checks as appropriate.
 */
bool ipv4_addr_equals(struct in_addr *a, struct in_addr *b);
bool ipv6_addr_equals(struct in6_addr *a, struct in6_addr *b);
bool ipv4_tuple_addr_equals(struct ipv4_tuple_address *a, struct ipv4_tuple_address *b);
bool ipv6_tuple_addr_equals(struct ipv6_tuple_address *a, struct ipv6_tuple_address *b);
bool ipv6_prefix_equals(struct ipv6_prefix *a, struct ipv6_prefix *b);
/**
 * @}
 */

/**
 * The kernel has a ipv6_addr_cmp(), but not a ipv4_addr_cmp().
 * Of course, that is because in_addrs are, to most intents and purposes, 32-bit integer values.
 * But the absence of ipv4_addr_cmp() does makes things look asymmetric.
 * So, booya.
 */
static inline int ipv4_addr_cmp(const struct in_addr *a1, const struct in_addr *a2)
{
	return memcmp(a1, a2, sizeof(struct in_addr));
}

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


#endif
