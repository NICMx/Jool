#ifndef _JOOL_COMM_TYPES_H
#define _JOOL_COMM_TYPES_H

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
	#include <string.h>
	#include <arpa/inet.h>
#endif
#include "nat64/comm/nat64.h"


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


#endif /* _JOOL_COMM_TYPES_H */
