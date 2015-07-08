#ifndef _JOOL_COMMON_TYPES_H
#define _JOOL_COMMON_TYPES_H

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
	#include <arpa/inet.h>
#ifdef BENCHMARK
		#include <time.h>
#endif
#endif

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
	/**
	 * Stateless Jool should try to translate other protocols in a best effort basis.
	 * It will just copy layer 4 as is, and hope there's nothing to update.
	 * Because of checksumming nonsense and whatnot, this might usually fail, but whatever.
	 */
	L4PROTO_OTHER = 3,
#define L4_PROTO_COUNT 4
} l4_protocol;

__u8 l4_proto_to_nexthdr(l4_protocol proto);

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

struct port_range {
	__u16 min;
	__u16 max;
};

struct pool4_sample {
	__u32 mark;
	struct in_addr addr;
	struct port_range range;
};

bool port_range_equals(const struct port_range *r1,
		const struct port_range *r2);
bool port_range_touches(const struct port_range *r1,
		const struct port_range *r2);
bool port_range_contains(const struct port_range *range, __u16 port);
unsigned int port_range_count(const struct port_range *range);

#endif /* _JOOL_COMMON_TYPES_H */
