#ifndef _NF_NAT64_TYPES_H
#define _NF_NAT64_TYPES_H

#include <linux/kernel.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

/** A tuple's type identifier. See RFC 6146 section 3.4. */
enum tuple_type
{
	TUPLE_5, /** "This is a tuple containing 5 key elements". Used by UDP, TCP and ICMP errors. */
	TUPLE_3, /** "This is a tuple containing 3 key elements". Used by ICMP queries. */
};

/** A hopefully easy to read indicator of what we're doing with the incoming packet. */
enum translation_mode
{
	FROM_4_TO_6, /** The module is currently translating a IPv4 packet into a IPv6 packet. */
	FROM_6_TO_4, /** The module is currently translating a IPv6 packet into a IPv4 packet. */
};

/** A generic IP address. Knowing whether it's a IPv4 or a IPv6 address is the developer's responsibility. */
union address
{
	struct in_addr ipv4; /** Use this when you know this structure is holding an IPv4 address. */
	struct in6_addr ipv6; /** Use this when you know this structure is holding an IPv6 address. */
};

bool ipv4_addr_equals(struct in_addr *addr_1, struct in_addr *addr_2);
bool ipv6_addr_equals(struct in6_addr *addr_1, struct in6_addr *addr_2);
__u16 ipv4_addr_hash_code(struct in_addr *addr);
//__u16 ipv6_addr_hash_code(struct in6_addr *addr);

union port_or_id
{
	// TODO (optimization) no se pueden cambiar a __u?
	__be16 port;
	__be16 id;
};

struct ipv4_tuple_address
{
	struct in_addr address;
	union port_or_id pi;
};

bool ipv4_tuple_address_equals(struct ipv4_tuple_address *addr_1, struct ipv4_tuple_address *addr_2);
__u16 ipv4_tuple_address_hash_code(struct ipv4_tuple_address *addr);

struct ipv6_tuple_address
{
	struct in6_addr address;
	union port_or_id pi;
};

bool ipv6_tuple_address_equals(struct ipv6_tuple_address *addr_1, struct ipv6_tuple_address *addr_2);
__u16 ipv6_tuple_address_hash_code(struct ipv6_tuple_address *addr);

/** A "tuple address" is the identifier of an endpoint of a connection. */
union tuple_address {
	struct ipv4_tuple_address ipv4;
	struct ipv6_tuple_address ipv6;
};

struct ipv4_pair {
	struct ipv4_tuple_address remote;
	struct ipv4_tuple_address local;
};

struct ipv6_pair {
	struct ipv6_tuple_address local;
	struct ipv6_tuple_address remote;
};

bool ipv4_pair_equals(struct ipv4_pair *pair_1, struct ipv4_pair *pair_2);
bool ipv6_pair_equals(struct ipv6_pair *pair_1, struct ipv6_pair *pair_2);
__u16 ipv4_pair_hash_code(struct ipv4_pair *pair);
__u16 ipv6_pair_hash_code(struct ipv6_pair *pair);

/** Accesors for the nf_conntrack_tuple struct. */
#define ipv4_src_addr 	src.u3.in
#define ipv6_src_addr	src.u3.in6
#define ipv4_dst_addr	dst.u3.in
#define ipv6_dst_addr	dst.u3.in6
#define icmp_id			src.u.icmp.id
#define src_port		src.u.all
#define dst_port		dst.u.all
#define l3_protocol		src.l3num
#define l4_protocol		dst.protonum

#define icmp4_unused un.gateway


#endif
