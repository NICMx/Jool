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
 * @author Robert Aceves
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
#include "nat64.h"


/**
 * Logging utilities, meant for standarization of error messages.
 */
#ifdef __KERNEL__
	#define log_error(func, id, text, ...) func("%s: ERR%d (%s): " text "\n", MODULE_NAME, id, \
			__func__, ##__VA_ARGS__)
	#define log_informational(func, text, ...) func(text "\n", ##__VA_ARGS__)
#else
	#define log_error(func, id, text, ...) printf("ERR%d: " text "\n", id, ##__VA_ARGS__)
	#define log_informational(func, text, ...) func(text "\n", ##__VA_ARGS__)
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

enum error_code {
	/* General */
	ERR_NULL,
	ERR_L4PROTO,
	ERR_L3PROTO,
	ERR_TRANSLATION_MODE,
	ERR_ALLOC_FAILED,
	ERR_NOT_FOUND,
	ERR_UNKNOWN_RCODE,
	ERR_UNKNOWN_ERROR,

	/* Config */
	ERR_NETLINK,
	ERR_MTU_LIST_EMPTY,
	ERR_MTU_LIST_ZEROES,
	ERR_SR_BIB_INSERT_FAILED,
	ERR_SR_SESSION_INSERT_FAILED,
	ERR_UDP_TO_RANGE,
	ERR_TCPEST_TO_RANGE,
	ERR_TCPTRANS_TO_RANGE,
	/* RFC6052 */
	ERR_PREF_LEN,
	/* Hash table */
	ERR_WRONG_SIZE,

	/* Pool4 */
	ERR_POOL4_EMPTY,
	ERR_POOL4_ADDR,
	ERR_POOL4_INCOMPLETE_INDEX,
	/* Pool6 */
	ERR_POOL6_EMPTY,
	ERR_POOL6_DRAINED,
	ERR_POOL6_PREF,
	ERR_POOL6_PREF_LEN,

	ERR_ITERATOR_IS_LYING,
	
	/* BIB */
	ERR_INCOMPLETE_INDEX_BIB,
	/* Session */
	ERR_SESSION_NOT_FOUND,
	ERR_SESSION_BIBLESS,
	ERR_INCOMPLETE_REMOVE,

	/* Incoming */
	ERR_PROTO_LOAD_FAILURE,
	ERR_CONNTRACK,
	/* Filtering */
	ERR_ADD_BIB_FAILED,
	ERR_EXTRACT_FAILED,
	ERR_APPEND_FAILED,
	ERR_ADD_SESSION_FAILED,
	ERR_STRAY_IPV4_PACKET,
	ERR_INVALID_STATE,
	/* Outgoing */
	ERR_MISSING_BIB,
	/* Translate */
	ERR_INNER_PACKET,
	/* Send packet */
	ERR_ROUTE_FAILED,
	ERR_SEND_FAILED,
};

/**
 * Accesors for somewhat more readability of nf_conntrack_tuples.
 * Useful only in kernelspace (I think).
 */
// TODO (later) capitalize.
#define ipv4_src_addr 	src.u3.in
#define ipv6_src_addr	src.u3.in6
#define ipv4_dst_addr	dst.u3.in
#define ipv6_dst_addr	dst.u3.in6
#define icmp_id			src.u.icmp.id
#define src_port		src.u.all
#define dst_port		dst.u.all
#define L3_PROTOCOL		src.l3num
#define L4_PROTOCOL		dst.protonum


/** Direction of the translation. */
enum translation_mode {
	/** We're translating a IPv4 packet into a IPv6 packet. */
	IPV4_TO_IPV6,
	/** We're translating a IPv6 packet into a IPv4 packet. */
	IPV6_TO_IPV4,
};

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
	struct in6_addr address;
	__u16 l4_id;
};

/**
 * The IPv4 side of a connection: A remote node in some IPv4 network and the NAT64.
 */
struct ipv4_pair {
	/** The IPv4 node's address and port being used in the connection. */
	struct ipv4_tuple_address remote;
	/** The NAT64's address and port being used in the connection. */
	struct ipv4_tuple_address local;
};

/**
 * The IPv6 side of a connection: A remote node in some IPv6 network and the NAT64.
 */
struct ipv6_pair {
	/** The IPv6 node's address and port being used in the connection. */
	struct ipv6_tuple_address local;
	/** The NAT64's address and port being used in the connection. */
	struct ipv6_tuple_address remote;
};

/**
 * Struct to handle valid IPv6 prefixes specified as configuration parameters.
 */
struct ipv6_prefix {
	/** IPv6 prefix. */
	struct in6_addr address;
	/** Number of bits from "addr" which represent the network. */
	__u8 len;
};

/**
 * All of these functions return "true" if the first parameter is the same as the second one, even
 * if they are pointers to different places in memory.
 *
 * @param addr_1 struct you want to compare to "addr_2".
 * @param addr_2 struct you want to compare to "addr_1".
 * @return (*addr_1) === (*addr_2).
 */
bool ipv4_addr_equals(struct in_addr *addr_1, struct in_addr *addr_2);
bool ipv6_addr_equals(struct in6_addr *addr_1, struct in6_addr *addr_2);
bool ipv4_tuple_addr_equals(struct ipv4_tuple_address *addr_1, struct ipv4_tuple_address *addr_2);
bool ipv6_tuple_addr_equals(struct ipv6_tuple_address *addr_1, struct ipv6_tuple_address *addr_2);
bool ipv4_pair_equals(struct ipv4_pair *pair_1, struct ipv4_pair *pair_2);
bool ipv6_pair_equals(struct ipv6_pair *pair_1, struct ipv6_pair *pair_2);
bool ipv6_prefix_equals(struct ipv6_prefix *expected, struct ipv6_prefix *actual);

/**
 * All of these functions compute a 16-bit hash identifier out of the parameter and return it.
 *
 * @param addr object you want a hash from.
 * @return hash code of "addr".
 */
__u16 ipv4_tuple_addr_hashcode(struct ipv4_tuple_address *addr);
__u16 ipv6_tuple_addr_hashcode(struct ipv6_tuple_address *addr);
__u16 ipv4_pair_hashcode(struct ipv4_pair *pair);
__u16 ipv6_pair_hashcode(struct ipv6_pair *pair);

bool is_icmp6_info(__u8 type);
bool is_icmp_info(__u8 type);

/**
 * Converts "str" to a IPv4 address. Stores the result in "result".
 *
 * Useful mainly in code common to kernelspace and userspace, since their conversion functions
 * differ, but meant to be used everywhere to strip the parameters from in_pton() we don't want.
 */
bool str_to_addr4(const char *str, struct in_addr *result);
/**
 * Converts "str" to a IPv6 address. Stores the result in "result".
 *
 * Useful mainly in code common to kernelspace and userspace, since their conversion functions
 * differ, but meant to be used everywhere to strip the parameters from in6_pton() we don't want.
 */
bool str_to_addr6(const char *str, struct in6_addr *result);


#endif
