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

enum error_code {
	/* General */
	ERR_SUCCESS = 0,
	ERR_NULL = 1,
	ERR_L4PROTO = 2,
	ERR_L3PROTO = 3,
	ERR_ALLOC_FAILED = 4,
	ERR_UNKNOWN_ERROR = 5,

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

	/* IPv6 header iterator */
	ERR_INVALID_ITERATOR = 2000,

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


enum l3_proto {
	L3PROTO_IPV6 = 0,
	L3PROTO_IPV4 = 1,
#define L3_PROTO_COUNT 2
};

char *l3proto_to_string(enum l3_proto proto);

enum l4_proto {
	L4PROTO_NONE = 0,
	L4PROTO_TCP = 1,
	L4PROTO_UDP = 2,
	L4PROTO_ICMP = 3,
#define L4_PROTO_COUNT 4
};

char *l4proto_to_string(enum l4_proto proto);

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

struct tuple_addr {
	union {
		struct in_addr ipv4;
		struct in6_addr ipv6;
	} addr;
	__u16 l4_id;
};

struct tuple {
	struct tuple_addr src;
	struct tuple_addr dst;
	u_int16_t l3_proto;
	u_int8_t l4_proto;
#define icmp_id src.l4_id
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
bool is_icmp6_error(__u8 type);
bool is_icmp4_info(__u8 type);
bool is_icmp4_error(__u8 type);

void log_tuple(struct tuple *tuple);


#endif
