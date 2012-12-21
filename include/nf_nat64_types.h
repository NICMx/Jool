#ifndef _NF_NAT64_TYPES_H
#define _NF_NAT64_TYPES_H

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
#include "libxt_NAT64.h"


/**
 * Logging utilities, meant for standarization of error messages.
 */
#ifdef __KERNEL__
	#define log_nat64(func, text, ...) func(MODULE_NAME "-%s: " text "\n", __func__, ##__VA_ARGS__);
#else
	#define log_nat64(func, text, ...) printf("%s: " text "\n", __func__, ##__VA_ARGS__);
#endif

#define log_debug(text, ...)	log_nat64(pr_debug, text, ##__VA_ARGS__)
#define log_info(text, ...)		log_nat64(pr_info, text, ##__VA_ARGS__)
#define log_warning(text, ...)	log_nat64(pr_warning, text, ##__VA_ARGS__)
#define log_err(text, ...)		log_nat64(pr_err, text, ##__VA_ARGS__)
#define log_crit(text, ...)		log_nat64(pr_crit, text, ##__VA_ARGS__)

/**
 * Accesors for somewhat more readability of nf_conntrack_tuples.
 * Useful only in kernelspace (I think).
 */
// TODO (info) capitalize.
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
enum translation_mode
{
	/** We're translating a IPv4 packet into a IPv6 packet. */
	IPV4_TO_IPV6,
	/** We're translating a IPv6 packet into a IPv4 packet. */
	IPV6_TO_IPV4,
};

/** TODO (warning) realmente queda alguna razón para tener esto? */
union port_or_id
{
	// TODO (optimization) no se pueden cambiar a __u?
	__be16 port;
	__be16 id;
};

/**
 * A layer-3 (IPv4) identifier attached to a layer-4 identifier (TCP port, UDP port or ICMP id).
 * Because they're paired all the time in this project.
 */
struct ipv4_tuple_address
{
	/** The layer-3 identifier. */
	struct in_addr address;
	/** The layer-4 identifier. */
	union port_or_id pi;
};

/**
 * A layer-3 (IPv6) identifier attached to a layer-4 identifier (TCP port, UDP port or ICMPv6 id).
 * Because they're paired all the time in this project.
 */
struct ipv6_tuple_address
{
	struct in6_addr address;
	union port_or_id pi;
};

/** A "tuple address" is the identifier of an endpoint of a connection. */
// TODO me parece que la existencia de esto no está justificada.
union tuple_address {
	struct ipv4_tuple_address ipv4;
	struct ipv6_tuple_address ipv6;
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

/**
 * All of these functions compute a 16-bit hash identifier out of the parameter and return it.
 *
 * @param addr object you want a hash from.
 * @return hash code of "addr".
 */
__u16 ipv4_addr_hashcode(struct in_addr *addr);
//__u16 ipv6_addr_hashcode(struct in6_addr *addr);
__u16 ipv4_tuple_addr_hashcode(struct ipv4_tuple_address *addr);
__u16 ipv6_tuple_addr_hashcode(struct ipv6_tuple_address *addr);
__u16 ipv4_pair_hashcode(struct ipv4_pair *pair);
__u16 ipv6_pair_hashcode(struct ipv6_pair *pair);

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
