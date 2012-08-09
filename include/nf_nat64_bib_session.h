#ifndef _NF_NAT64_BIB_SESSION_H
#define _NF_NAT64_BIB_SESSION_H

/**
 * @file
 * Low-level management of the Binding Information Bases (BIB) and the Session Tables (ST).
 * Most (if not everything) from this module was retrieved from the Lithuania project (by Julius Kriukas).
 */

#include <net/tcp.h>
#include <linux/inet.h>
#include <linux/in6.h>
#include "nf_nat64_ipv4_pool.h"

/** Minimum allowable session lifetime for UDP bindings, in seconds. TODO we still don't use it. */
#define UDP_MIN_ (2 * 60)
/**
 * Defined in the RFC as the minimum allowable default value for the session lifetime of UDP bindings,
 * in seconds. We use it as the actual default value.
 */
#define UDP_DEFAULT_ (5 * 60)
/**
 * Transitory connection idle timeout.
 * In other words, the timeout of several states in the TCP state machine. In seconds.
 */
#define TCP_TRANS_ (4 * 60)
/**
 * Established connection idle timeout.
 * In other words, the timeout of several states in the TCP state machine. In seconds.
 */
#define TCP_EST_ (2 * 60 * 60)
/** Timeout of several types of new STEs created during the CLOSED state of the TCP state machine. */
#define TCP_INCOMING_SYN_ (6)
/** Default time interval fragments are allowed to arrive in. In seconds. TODO we still don't use it. */
#define FRAGMENT_MIN_ (2)
/** Default session lifetime for ICMP bindings, in seconds. */
#define ICMP_DEFAULT_ (1 * 60)

/**
 * expiry_type enumeration count.
 *
 * @see expiry_type
 */
#define	NUM_EXPIRY_QUEUES 5

/**
 * Indexes of the different currently implemented lifetimes.
 * Use them to interact with the expiry_base array.
 *
 * @see expiry_base
 */
enum expiry_type
{
	UDP_DEFAULT = 0, //
	TCP_TRANS, //
	TCP_EST, //
	TCP_INCOMING_SYN, //
	ICMP_DEFAULT
};

/**
 * States from the TCP state machine (RFC 6146 section 3.5.2).
 */
enum state_type
{
	CLOSED = 0, //
	V6_SYN_RCV, //
	V4_SYN_RCV, //
	FOUR_MIN, //
	ESTABLISHED, //
	V6_FIN_RCV, //
	V4_FIN_RCV, //
	V6_FIN_V4_FIN
};

/**
 * A list of session table rows and the time they're supposed to live.
 */
struct expiry_q
{
	/** The ST rows whose expiration timeout is "timeout". */
	struct list_head queue;
	/** Time the entries from "queue" are going to live. */
	int timeout;
};

/**
 * Row from a Binding Information Base (BIB) table.
 */
struct nat64_bib_entry
{
	/** Collection used to access the elements of the BIB by IPv6 address (See hash6). */
	struct hlist_node byremote;
	/** Collection used to access the elements of the BIB by IPv4 address (See hash4). */
	struct hlist_node bylocal;

	/** The layer 4 protocol this binding belongs to. Normally either IPPROTO_TCP, IPPROTO_UDP or IPPROTO_ICMP. */
	int type;

	/** X' address. Address from the IPv6 side. */
	struct in6_addr remote6_addr;
	/** T address. Address from the IPv4 side. Always one of the IPv4 addresses assigned to the NAT64. */
	__be32 local4_addr;
	/**
	 * If type is TCP or UDP, this is the port from the IPv6 side.
	 * If type is ICMP, this is the ICMP identifier from the IPv6 side.
	 */
	__be16 remote6_port;
	/**
	 * If type is TCP or UDP, this is the port from the IPv4 side.
	 * If type is ICMP, this is the ICMP identifier from the IPv4 side.
	 */
	__be16 local4_port;

	/** Rows from the ST related to this BIB. */
	struct list_head sessions;
};

/**
 * Row from a Session table (ST).
 */
struct nat64_st_entry
{
	/** Links this ST entry to the rest from the same BIB (see nat64_bib_entry.sessions). */
	struct list_head list;
	/** Links this ST entry to the rest from the same expiration type (see expiry_q.queue). */
	struct list_head byexpiry;

	/** X' address. Address of the IPv6 node. */
	struct in6_addr remote6_addr;
	/** Y' address. Address the IPv6 node thinks the IPv4 node has. */
	struct in6_addr embedded6_addr;

	/** Time this session should be removed from memory. */
	unsigned long expires;
	/** If this is a TCP session entry, this is the state the entry is in in the TCP state machine. */
	int state;

	/** T address. Address the IPv4 node thinks the IPv6 node has. */
	__be32 local4_addr;
	/** Z address. Address of the IPv4 node. */
	__be32 remote4_addr;

	/** x port. Port being used by the IPv6 node. */
	__be16 remote6_port;
	/** y port. Port the IPv6 node thinks the IPv4 node is listening in. */
	__be16 embedded6_port;
	/** z port. Port being used by the IPv4 node. */
	__be16 remote4_port;
	/** t port. Port the IPv4 node thinks the IPv6 node is listening in. */
	__be16 local4_port;
};

/**
 * Initializes this module. Call once before addressing the remaining functions.
 */
int nat64_create_bib_session_memory(void);
/**
 * Terminates this module. Please call once at the end of the program so memory can be released.
 */
int nat64_destroy_bib_session_memory(void);

//int nat64_tcp_timeout_fsm(struct nat64_st_entry *session);
/**
 * Updates the state of the "session" using the new packet described by the "tcph" packet header.
 *
 * @param session row from the session table that needs to be updated.
 * @param the new packet, coming from the IPv4 side, belonging to the "session" session, that will dictate how the
 * 			session has to be updated.
 */
void nat64_tcp4_fsm(struct nat64_st_entry *session, struct tcphdr *tcph);
/**
 * Updates the state of the "session" session using the new packet described by the "tcph" packet header.
 *
 * @param session row from the session table that needs to be updated.
 * @param the new packet, coming from the IPv6 side, belonging to the "session" session, that will dictate how the
 * 			session has to be updated.
 */
void nat64_tcp6_fsm(struct nat64_st_entry *session, struct tcphdr *tcph);

/**
 * BIB entry constructor. Creates a BIB row that belongs to the "type" protocol, whose IPv6 transport address is
 * "remote6_addr":"remote_port", and whose IPv4 transport address is "local4_addr":"local4_port".
 *
 * @param remote6_addr IPv6 IP address of the new BIB entry.
 * @param remote6_port IPv6 port of the new BIB entry.
 * @param local4_addr IPv4 IP address of the new BIB entry.
 * @param local4_port IPv4 port of the new BIB entry.
 * @param type whether the row will belong to the TCP table (IPPROTO_TCP), the UDP table (IPPROTO_UDP)
 * 			or the ICMP table (IPPROTO_ICMP).
 * @return the resulting BIB entry.
 */
struct nat64_bib_entry *nat64_bib_create(struct in6_addr *remote6_addr, __be16 remote6_port, __be32 local4_addr,
        __be16 local4_port, int type);
/**
 * BIB entry constructor. Creates a BIB row that belongs to the "type" layer 4 protocol, whose IPv6 transport address
 * is "remote6_addr":"remote_port", and whose IPv4 transport address is "local4_addr":"local4_port".
 *
 * @param remote6_addr IPv6 IP address of the new BIB entry.
 * @param remote6_port IPv6 port of the new BIB entry.
 * @param local4_addr IPv4 IP address of the new BIB entry.
 * @param local4_port IPv4 port of the new BIB entry.
 * @param type whether the row will belong to the TCP table (IPPROTO_TCP), the UDP table (IPPROTO_UDP)
 * 			or the ICMP table (IPPROTO_ICMP).
 * @return the resulting BIB entry.
 *
 * TODO oye, la mayoría de estas funciones son demasiado parecidas.
 */
struct nat64_bib_entry *nat64_bib_create_tcp(struct in6_addr *remote6_addr, __be16 remote6_port, __be32 local4_addr,
        __be16 local4_port, int type);
struct nat64_bib_entry *nat64_bib_session_create_tcp(struct in6_addr *saddr, struct in6_addr *in6_daddr, __be32 daddr,
        __be16 sport, __be16 dport, int protocol, enum expiry_type type);
struct nat64_bib_entry *nat64_bib_session_create_icmp(struct in6_addr *saddr, struct in6_addr *in6_daddr, __be32 daddr,
        __be16 sport, __be16 dport, int protocol, enum expiry_type type);
struct nat64_bib_entry *nat64_bib_session_create(struct in6_addr *saddr, struct in6_addr *in6_daddr, __be32 daddr,
        __be16 sport, __be16 dport, int protocol, enum expiry_type type);

/**
 * Session table entry constructor. Creates a session table row linked to the "bib" row, filling the remaining
 * information from the remaining parameters.
 *
 * @param bib binding information between the Nat64 and the IPv6 node.
 * @param in6_daddr IPv6 address of the IPv4 node.
 * @param addr IPv4 address of the IPv4 node.
 * @param port Port the IPv4 node is listening in.
 * @param type Id of the time the session should expire in.
 * @return the resulting session table entry.
 *
 * TODO Estas tres tambien son iguales...
 */
struct nat64_st_entry *nat64_session_create(struct nat64_bib_entry *bib, struct in6_addr *in6_daddr, __be32 addr,
        __be16 port, enum expiry_type type);
struct nat64_st_entry *nat64_session_create_tcp(struct nat64_bib_entry *bib, struct in6_addr *in6_daddr, __be32 addr,
        __be16 port, enum expiry_type type);
struct nat64_st_entry *nat64_session_create_icmp(struct nat64_bib_entry *bib, struct in6_addr *in6_daddr, __be32 addr,
        __be16 port, enum expiry_type type);

/**
 * Returns the row from the "type" BIB table whose transport address is "remote_addr":"remote_port".
 *
 * @param remote_addr IPv6 address to be looked up on the BIB table.
 * @param remote_port port to be looked up on the BIB table.
 * @param type whether the row should be looked up on the TCP table (IPPROTO_TCP), the UDP table (IPPROTO_UDP)
 * 			or the ICMP table (IPPROTO_ICMP).
 * @return row from the "type" BIB table whose transport address is "remote_addr":"remote_port".
 */
struct nat64_bib_entry *nat64_bib_ipv6_lookup(struct in6_addr *remote_addr, __be16 remote_port, int type);
/**
 * Returns the row from the "type" BIB table whose transport address is "local_addr":"local_port".
 *
 * @param remote_addr IPv4 address to be looked up on the BIB table.
 * @param remote_port port to be looked up on the BIB table.
 * @param type whether the row should be looked up on the TCP table (IPPROTO_TCP), the UDP table (IPPROTO_UDP)
 * 			or the ICMP table (IPPROTO_ICMP).
 * @return row from the "type" BIB table whose transport address is "remote_addr":"remote_port".
 *
 * TODO no se parece demasiado a la anterior?
 */
struct nat64_bib_entry *nat64_bib_ipv4_lookup(__be32 local_addr, __be16 local_port, int type);
/**
 * Returns the session row from the "bib" binding whose IPv4 node has "saddr":"sport" as its transport address.
 *
 * @param bib binding you want the session from.
 * @param ip address of the session's remote node.
 * @param port of the session's remote node.
 * @return session table entry fot the "bib" binding and the "saddr":"sport" remote node.
 */
struct nat64_st_entry *nat64_session_ipv4_lookup(struct nat64_bib_entry *bib, __be32 saddr, __be16 sport);
/**
 * TODO se parece a la anterior.
 */
struct nat64_st_entry *nat64_session_ipv4_hairpin_lookup(struct nat64_bib_entry *bib, __be32 local4_addr,
        __be16 local4_port);

/**
 * Redefines the timeout of the "session" session, using the "type" expiration type.
 *
 * @param session session whose timeout should be reset.
 * @param type Id of the expiration timeout. See expiry_base.
 */
void nat64_session_renew(struct nat64_st_entry *session, enum expiry_type type);

/**
 * Deletes from "queue" the sessions whose lifespan end happenend in the past.
 *
 * @param queue list to be cleaned.
 * @param j Timeout type. Depends on whether queue is a list of TCP sessions, UDP sessions or ICMP sessions.
 */
void nat64_clean_expired_sessions(struct list_head *queue, int j);

#endif /* _NF_NAT64_BIB_SESSION_H */
