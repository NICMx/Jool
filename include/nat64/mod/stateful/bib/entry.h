#ifndef _JOOL_MOD_BIB_ENTRY_H
#define _JOOL_MOD_BIB_ENTRY_H

#include "nat64/common/session.h"
#include "nat64/common/types.h"

/**
 * A mask that dictates which IPv4 transport address is being used to mask a
 * given IPv6 (transport) client.
 *
 * Please note that modifications to this structure may need to cascade to
 * struct bib_entry_usr.
 */
struct bib_entry {
	/** The mask. */
	struct ipv4_transport_addr ipv4;
	/** The service/client being masked. */
	struct ipv6_transport_addr ipv6;
	/** Protocol of the channel. */
	l4_protocol l4_proto;
};

typedef enum session_timer_type {
	SESSION_TIMER_EST,
	SESSION_TIMER_TRANS,
	SESSION_TIMER_SYN4,
} session_timer_type;

/**
 * An IPv6 connection and the IPv4 version of it once translated.
 *
 * This is a codensed/public version of the structure that is actually stored in
 * the database.
 *
 * Please note that modifications to this structure may need to cascade to
 * "struct session_entry_usr".
 */
struct session_entry {
	/**
	 * IPv6 version of the connection.
	 *
	 * "src" and "dst" are inherited names from the RFC. They are
	 * unfortunate, as they only make sense in the 6-to-4 direction.
	 *
	 * @src6 is the remote IPv6 node's transport address.
	 *     We used to call it "remote6".
	 * @dst6 is the address the NAT64 is using to mask the IPv4 endpoint.
	 *     We used to call it "local6".
	 */
	struct ipv6_transport_addr src6;
	struct ipv6_transport_addr dst6;

	/**
	 * IPv4 version of the connection.
	 *
	 * "src" and "dst" are inherited names from the RFC. They are
	 * unfortunate, as they only make sense in the 6-to-4 direction.
	 *
	 * @src4 is the address the NAT64 is using to mask the IPv6 endpoint.
	 *     We used to call it "local4".
	 * @dst4 is the remote IPv4 node's transport address.
	 *     We used to call it "remote4".
	 */
	struct ipv4_transport_addr src4;
	struct ipv4_transport_addr dst4;

	/** Transport protocol of the connection this session describes. */
	l4_protocol proto;
	/** Current TCP SM state. Only relevant if @l4_proto == L4PROTO_TCP. */
	tcp_state state;
	/** An indicator of the timer that is going to expire this session. */
	session_timer_type timer_type;

	/** Jiffy (from the epoch) this session was last updated/used. */
	unsigned long update_time;
	/*
	 * Number of jiffies before this session is to be downgraded. (Either
	 * deleted or changed into a transitory state.)
	 */
	unsigned long timeout;

	bool has_stored;
};

struct bib_session {
	/** Are @session.src6, @session.src4, @session.proto set? */
	bool bib_set;
	/**
	 * Are all of @session's fields set?
	 * (@session_set true implies @bib_set true.)
	 */
	bool session_set;
	struct session_entry session;
};

void bib_session_init(struct bib_session *bs);

bool session_equals(const struct session_entry *s1,
		const struct session_entry *s2);

#endif /* _JOOL_MOD_BIB_ENTRY_H */
