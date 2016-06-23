#ifndef _JOOL_COMMON_TYPES_H
#define _JOOL_COMMON_TYPES_H

/**
 * @file
 * The NAT64's core data types. Structures used all over the code.
 *
 * Both the kernel module and the userspace application can see this file.
 */

#include <linux/types.h>
#ifdef __KERNEL__
	#include <linux/in.h>
	#include <linux/in6.h>
#else
	#include <stdbool.h>
	#include <arpa/inet.h>
#endif

#ifdef __KERNEL__

/*
 * Why include kernel.h? because printk.h depends on it in some old kernels.
 * (3.2-3.9 it seems.)
 */
#include <linux/kernel.h>
#include <linux/printk.h>
#include "nat64/common/xlat.h"
#include "nat64/mod/common/error_pool.h"

/**
 * Messages to help us walk through a run. Also covers normal packet drops
 * (bad checksums, bogus addresses, etc) and some failed memory allocations
 * (because the kernel already prints those).
 */
#define log_debug(text, ...) pr_debug(text "\n", ##__VA_ARGS__)
/**
 * Responses to events triggered by the user, which might not show signs of life
 * elsehow.
 */
#define log_info(text, ...) pr_info(text "\n", ##__VA_ARGS__)
/**
 * "I'm not going to translate this because the config's not right."
 * These rate limit themselves so the log doesn't get too flooded.
 */
#define log_warn_once(text, ...) \
	do { \
		static bool __logged = false; \
		static unsigned long __last_log; \
		\
		if (!__logged || __last_log < jiffies - msecs_to_jiffies(60 * 1000)) { \
			pr_warn("%s WARNING (%s): " text "\n", \
					xlat_get_name(), __func__, \
					##__VA_ARGS__); \
			__logged = true; \
			__last_log = jiffies; \
		} \
	} while (0)
/**
 * "Your configuration cannot be applied, user."
 * log_warn_once() signals errors while processing packets. log_err() signals
 * errors while processing user requests.
 * I the code found a **programming** error, use WARN() or its variations
 * instead.
 */
#define log_err(text, ...) \
	do { \
		char __error_message[512]; \
		pr_err("%s ERROR (%s): " text "\n", xlat_get_name(), __func__, \
				##__VA_ARGS__); \
		sprintf(__error_message, text "\n", ##__VA_ARGS__); \
		error_pool_add_message(__error_message); \
	} while (0)

#ifdef UNIT_TESTING
#undef log_err
#define log_err(text, ...) pr_err("%s ERROR (%s): " text "\n", \
		xlat_get_name(), __func__, ##__VA_ARGS__)
#endif

#else

#include <stdio.h>

#define log_debug(text, ...) printf(text "\n", ##__VA_ARGS__)
#define log_info(text, ...) log_debug(text, ##__VA_ARGS__)
#define log_err(text, ...) fprintf(stderr, text "\n", ##__VA_ARGS__)

#endif

/**
 * Network (layer 3) protocols Jool is supposed to support.
 * We do not use PF_INET, PF_INET6, AF_INET or AF_INET6 because I want the
 * compiler to pester me during defaultless `switch`s. Also, the zero-based
 * index is convenient in the Translate Packet module.
 */
typedef enum l3_protocol {
	/** RFC 2460. */
	L3PROTO_IPV6 = 0,
	/** RFC 791. */
	L3PROTO_IPV4 = 1,
} l3_protocol;

/**
 * Transport (layer 4) protocols Jool is supposed to support.
 * We do not use IPPROTO_TCP and friends because I want the compiler to pester
 * me during defaultless `switch`s. Also, the zero-based index is convenient in
 * the Translate Packet module.
 */
typedef enum l4_protocol {
	/** Signals the presence of a TCP header. */
	L4PROTO_TCP = 0,
	/** Signals the presence of a UDP header. */
	L4PROTO_UDP = 1,
	/**
	 * Signals the presence of a ICMP header. Whether the header is ICMPv4
	 * or ICMPv6 never matters.
	 * We know that ICMP is not a transport protocol, but for all intents
	 * and purposes, it behaves exactly like one in IP translation.
	 */
	L4PROTO_ICMP = 2,
	/**
	 * SIIT Jool should try to translate other protocols in a best effort
	 * basis.
	 * It will just copy layer 4 as is, and hope there's nothing to update.
	 * Because of checksumming nonsense and whatnot, this might usually
	 * fail, but whatever.
	 */
	L4PROTO_OTHER = 3,
#define L4_PROTO_COUNT 4
} l4_protocol;

__u8 l4_proto_to_nexthdr(l4_protocol proto);
l4_protocol str_to_l4proto(char *str);

/**
 * A layer-3 (IPv4) identifier attached to a layer-4 identifier.
 * Because they're paired all the time in this project.
 */
struct ipv4_transport_addr {
	/** The layer-3 identifier. */
	struct in_addr l3;
	/** The layer-4 identifier (Either the TCP/UDP port or the ICMP id). */
	__u16 l4;
};

/**
 * A layer-3 (IPv6) identifier attached to a layer-4 identifier.
 * Because they're paired all the time in this project.
 */
struct ipv6_transport_addr {
	/** The layer-3 identifier. */
	struct in6_addr l3;
	/** The layer-4 identifier (Either the TCP/UDP port or the ICMP id). */
	__u16 l4;
};

struct taddr6_tuple {
	struct ipv6_transport_addr src;
	struct ipv6_transport_addr dst;
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
	/** IPv6 prefix. The suffix is most of the time assumed to be zero. */
	struct in6_addr address;
	/** Number of bits from "address" which represent the network. */
	__u8 len;
};

struct port_range {
	__u16 min;
	__u16 max;
};

struct ipv4_range {
	struct ipv4_prefix prefix;
	struct port_range ports;
};

struct pool4_sample {
	__u32 mark;
	__u8 proto;
	struct in_addr addr;
	struct port_range range;
};

bool port_range_equals(const struct port_range *r1,
		const struct port_range *r2);
bool port_range_touches(const struct port_range *r1,
		const struct port_range *r2);
bool port_range_contains(const struct port_range *range, __u16 port);
unsigned int port_range_count(const struct port_range *range);

bool range4_contains(struct ipv4_range *range,
		struct ipv4_transport_addr *addr);

#endif /* _JOOL_COMMON_TYPES_H */
