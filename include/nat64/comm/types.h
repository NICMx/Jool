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
#ifdef BENCHMARK
		#include <linux/time.h>
#endif
#else
	#include <stdbool.h>
	#include <string.h>
	#include <arpa/inet.h>
#ifdef BENCHMARK
		#include <time.h>
#endif
#endif
#include "nat64/comm/nat64.h"

/**
 * Returns nonzero if "status" is an error, returns zero if "status" represents success.
 *
 * This exists because if find stuff like this very baffling:
 * 		if (function_call())
 * 			log_err("Oh noes error");
 *
 * My common sense dictates that it should be like this:
 * 		if (!function_call())
 * 			log_err("Oh noes error");
 *
 * Or at least this:
 * 		if (is_error(function_call()))
 * 			log_err("Oh noes error");
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
 * Transport (layer 4) protocols Jool is supposed to support.
 * We do not use IPPROTO_TCP and friends because I want the compiler to pester me during
 * defaultless switch'es. Also, the zero-based index is convenient in the Translate Packet module.
 */
typedef enum l4_protocol {
	/** Signals the presence of a TCP header. */
	L4PROTO_TCP = 0,
	/** Signals the presence of a UDP header. */
	L4PROTO_UDP = 1,
	/**
	 * Signals the presence of a ICMP header. Whether the header is ICMPv4 or ICMPv6 never matters.
	 * We know that ICMP is not a transport protocol, but for all intents and purposes, it behaves
	 * exactly like one in NAT64.
	 */
	L4PROTO_ICMP = 2,
#define L4_PROTO_COUNT 3
} l4_protocol;

/**
 * A layer-3 (IPv4) identifier attached to a layer-4 identifier (TCP port, UDP port or ICMP id).
 * Because they're paired all the time in this project.
 */
struct ipv4_transport_addr {
	/** The layer-3 identifier. */
	struct in_addr l3;
	/** The layer-4 identifier (Either the port (TCP or UDP) or the ICMP id). */
	__u16 l4;
};

/**
 * A layer-3 (IPv6) identifier attached to a layer-4 identifier (TCP port, UDP port or ICMPv6 id).
 * Because they're paired all the time in this project.
 */
struct ipv6_transport_addr {
	/** The layer-3 identifier. */
	struct in6_addr l3;
	/** The layer-4 identifier (Either the port (TCP or UDP) or the ICMP id). */
	__u16 l4;
};

/**
 * The network component of a IPv4 address.
 */
struct ipv4_prefix {
	/** IPv4 prefix. */
	struct in_addr address;
	/** Number of bits from "address" which represent the network. */
	__u8 len;
};

/**
 * The network component of a IPv6 address.
 */
struct ipv6_prefix {
	/** IPv6 prefix. */
	struct in6_addr address;
	/** Number of bits from "address" which represent the network. */
	__u8 len;
};

#endif /* _JOOL_COMM_TYPES_H */
