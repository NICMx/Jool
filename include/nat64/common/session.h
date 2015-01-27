#ifndef _JOOL_COMMON_SESSION_H
#define _JOOL_COMMON_SESSION_H

/** The states from the TCP state machine; RFC 6146 section 3.5.2. */
enum tcp_state {
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

#endif /* _JOOL_COMMON_SESSION_H */
