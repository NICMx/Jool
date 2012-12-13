#ifndef _NAT64_H_
#define _NAT64_H_

#define _USER_SPACE_

#include <stdio.h>
#include <argp.h>
#include <arpa/inet.h>
#include <linux/types.h>
#include <string.h>
#include <netlink/netlink.h>
#include <netlink/socket.h>
#include <netlink/msg.h>
#include <netlink/attr.h>
#include "xt_nat64_module_comm.h" // config struct & defaults
#include "nat64_config_validation.h"

struct list_head {
	struct list_head *next, *prev;
};

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

struct ipv6_tuple_address
{
	struct in6_addr address;
	union port_or_id pi;
};

struct ipv4_pair {
	struct ipv4_tuple_address remote;
	struct ipv4_tuple_address local;
};

struct ipv6_pair {
	struct ipv6_tuple_address local;
	struct ipv6_tuple_address remote;
};

/**
 * A row, intended to be part of one of the BIB tables.
 * A binding between a transport address from the IPv4 network to one from the IPv6 network.
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

// Assert we compile with libnl version >= 3.0
#if !defined(LIBNL_VER_NUM) 
	#error "You MUST install LIBNL library (at least version 3)."
#endif
#if LIBNL_VER_NUM < LIBNL_VER(3,0)
	#error "Unsupported LIBNL library version number (< 3.0)."
#endif


#endif
