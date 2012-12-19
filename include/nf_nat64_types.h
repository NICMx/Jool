#ifndef _NF_NAT64_TYPES_H
#define _NF_NAT64_TYPES_H

/**
 * @file
 * The NAT64's core data types. Structures used all over the code.
 *
 * Both the kernel module and the userspace application can see this file.
 */

#include <linux/kernel.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

#include "libxt_NAT64.h"


/**
 * Logging utilities, meant for standarization of error messages.
 * Useful only in kernelspace.
 */
#define log_debug(text, ...) pr_debug(MODULE_NAME "-%s: " text "\n", __func__, ##__VA_ARGS__)
#define log_info(text, ...) pr_info(MODULE_NAME "-%s: " text "\n", __func__, ##__VA_ARGS__)
#define log_warning(text, ...) pr_warning(MODULE_NAME "-%s: " text "\n", __func__, ##__VA_ARGS__)
#define log_err(text, ...) pr_err(MODULE_NAME "-%s: " text "\n", __func__, ##__VA_ARGS__)
#define log_crit(text, ...) pr_crit(MODULE_NAME "-%s: " text "\n", __func__, ##__VA_ARGS__)

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
#define l3_protocol		src.l3num
#define l4_protocol		dst.protonum


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
 * A row, intended to be part of one of the BIB tables.
 * A binding between a transport address from the IPv4 network to one from the IPv6 network.
 *
 * This'd normally be part of *_bib.h, but we need to be able to see it from userspace.
 */
struct bib_entry
{
	/** The address from the IPv4 network. */
	struct ipv4_tuple_address ipv4;
	/** The address from the IPv6 network. */
	struct ipv6_tuple_address ipv6;

	/** Session entries related to this BIB. */
	struct list_head session_entries;
};

/**
 * A row, intended to be part of one of the session tables.
 * The mapping between the connections, as perceived by both sides (IPv4 vs IPv6).
 *
 * This'd normally be part of *_session.h, but we need to be able to see it from userspace.
 */
struct session_entry
{
	/** IPv6 version of the connection. */
	struct ipv6_pair ipv6;
	/** IPv4 version of the connection. */
	struct ipv4_pair ipv4;

	/** Should the session never expire? */
	bool is_static;
	/**
	 * Millisecond (from the epoch) this session should expire in, if still inactive.
	 */
	unsigned int dying_time;

	/**
	 * Owner bib of this session. Used for quick access during removal.
	 * (when the session dies, the BIB might have to die too.)
	 */
	struct bib_entry *bib;
	/**
	 * Chains this session with the rest from the same BIB (see bib_entry.session_entries).
	 * Used by the BIB to know whether it should commit suicide or not.
	 */
	struct list_head entries_from_bib;
	/**
	 * Chains this session with the rest (see all_sessions, defined in nf_nat_session.h).
	 * Used for iterating while looking for expired sessions.
	 */
	struct list_head all_sessions;
	/**
	 * Transport protocol of the table this entry is in.
	 * Used to know which table the session should be removed from when expired.
	 */
	u_int8_t l4protocol;
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
