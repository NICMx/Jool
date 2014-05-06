#ifndef _NF_NAT64_SESSION_H
#define _NF_NAT64_SESSION_H

/**
 * @file
 * The Session tables.
 * Formally defined in RFC 6146 section 3.2.
 *
 * @author Alberto Leiva
 */

#include "nat64/comm/types.h"

/** The states from the TCP state machine; RFC 6146 section 3.5.2. */
enum tcp_states {
	/** No traffic has been seen; state is fictional. */
	CLOSED = 0,
	/** A SYN packet arrived from the IPv6 side; some IPv4 node is trying to start a connection. */
	V6_INIT,
	/** A SYN packet arrived from the IPv4 side; some IPv4 node is trying to start a connection. */
	V4_INIT,
	/** The handshake is complete and the sides are exchanging upper-layer data. */
	ESTABLISHED,
	/**
	 * The IPv4 node wants to terminate the connection. Data can still flow.
	 * Awaiting a IPv6 FIN...
	 */
	V4_FIN_RCV,
	/**
	 * The IPv6 node wants to terminate the connection. Data can still flow.
	 * Awaiting a IPv4 FIN...
	 */
	V6_FIN_RCV,
	/** Both sides issued a FIN. Packets can still flow for a short time. */
	V4_FIN_V6_FIN_RCV,
	/** The session might die in a short while. */
	TRANS,
};

/**
 * A row, intended to be part of one of the session tables.
 * The mapping between the connections, as perceived by both sides (IPv4 vs IPv6).
 *
 * Please note that modifications to this structure may need to cascade to config_proto.h.
 */
struct session_entry {
	/** IPv6 version of the connection. */
	struct ipv6_pair ipv6;
	/** IPv4 version of the connection. */
	struct ipv4_pair ipv4;

	/** Jiffy (from the epoch) this session should expire in, if still inactive. */
	unsigned long dying_time;

	/**
	 * Owner bib of this session. Used for quick access during removal.
	 * (when the session dies, the BIB might have to die too.)
	 */
	struct bib_entry *bib;

	/** A reference counter related to this session. */
	struct kref refcounter;
	/**
	 * Chainer to one of the expiration timer lists (sessions_udp, sessions_tcp_est, etc).
	 * Used for iterating while looking for expired sessions.
	 */
	struct list_head expire_list_hook;
	/**
	 * Transport protocol of the table this entry is in.
	 * Used to know which table the session should be removed from when expired.
	 */
	l4_protocol l4_proto;

	/** Current TCP state.
	 * 	Each STE represents a state machine
	 */
	u_int8_t state;

	struct rb_node tree6_hook;
	struct rb_node tree4_hook;
};

/**
 * Initializes the three tables (UDP, TCP and ICMP).
 * Call during initialization for the remaining functions to work properly.
 */
int session_init(void);
/**
 * Empties the session tables, freeing any memory being used by them.
 * Call during destruction to avoid memory leaks.
 */
void session_destroy(void);

/**
 * Helper function, intended to increment a BIB refcounter
 */
void session_get(struct session_entry *session);
/**
 * Helper function, intended to decrement a BIB refcounter
 */
int session_return(struct session_entry *session);

/**
 * Helper function, intended to initialize a Session entry.
 * The entry is generated IN DYNAMIC MEMORY (if you end up not inserting it to a Session table, you
 * need to session_kfree() it).
 */
struct session_entry *session_create(struct ipv4_pair *ipv4, struct ipv6_pair *ipv6,
		l4_protocol l4_proto);
/**
 * Warning: Careful with this one; "session" cannot be NULL.
 */
void session_kfree(struct session_entry *session);


#endif /* _NF_NAT64_SESSION_H */
