#ifndef _JOOL_MOD_SESSION_DB_H
#define _JOOL_MOD_SESSION_DB_H

/**
 * @file
 * The BIB and session tables.
 * Formally defined in RFC 6146 section 3.2.
 */

#include "nat64/mod/common/config.h"
#include "nat64/mod/common/packet.h"
#include "nat64/mod/stateful/pool4/db.h"
#include "nat64/mod/stateful/bib/entry.h"

struct bib;

enum session_fate {
	/**
	 * Assign the established timer to the session.
	 * (An "established" timer is one where it is assumed the session is
	 * not going to die soon.)
	 */
	FATE_TIMER_EST,
	/**
	 * Assign the transitory timer to the session.
	 * (A "transitory" timer is one where it is assumed the session is
	 * going to die soon.)
	 */
	FATE_TIMER_TRANS,
	/**
	 * The session expired; it has to be removed from the DB right away.
	 */
	FATE_RM,
	/**
	 * No changes.
	 */
	FATE_PRESERVE,
	/**
	 * Send a probe packet, then reset timer into transitory mode.
	 */
	FATE_PROBE,
	/**
	 * Drop the packet (the new packet, not the stored one),
	 * preserve the session (stored packet included).
	 */
	FATE_DROP,

	/**
	 * Like FATE_TIMER_EST or FATE_TIMER_TRANS, except the session's
	 * lifetime must not be reset.
	 * It's called "slow" because this means the database cannot just add
	 * the session to the end of the sorted (by expiration date) list and so
	 * the proper slot has to be found in a sequential search.
	 */
	FATE_TIMER_SLOW,
};

int bib_init(void);
void bib_destroy(void);

struct bib *bib_create(void);
void bib_get(struct bib *db);
void bib_put(struct bib *db);

void bib_config_copy(struct bib *db, struct bib_config *config);
void bib_config_set(struct bib *db, struct bib_config *config);

typedef enum session_fate (*fate_cb)(struct session_entry *, void *);

struct collision_cb {
	/**
	 * Note: This callback can edit the session's state, timer_type,
	 * update_time, and also turn off has_stored.
	 * Any other changes will be rolled back.
	 */
	fate_cb cb;
	void *arg;
};

/* These are used by Filtering. */

int bib_add6(struct bib *db, struct mask_domain *masks, struct tuple *tuple6,
		struct ipv4_transport_addr *dst4, struct bib_session *result);
int bib_add4(struct bib *db, struct ipv6_transport_addr *dst6,
		struct tuple *tuple4, struct bib_session *result);
verdict bib_add_tcp6(struct bib *db, struct mask_domain *masks,
		struct ipv4_transport_addr *dst4, struct packet *pkt,
		struct collision_cb *cb, struct bib_session *result);
verdict bib_add_tcp4(struct bib *db, struct ipv6_transport_addr *dst6,
		struct packet *pkt, struct collision_cb *cb,
		struct bib_session *result);

/* These are used by other kernel submodules. */

int bib_find(struct bib *db, struct tuple *tuple,
		struct bib_session *result);
int bib_add_session(struct bib *db, struct session_entry *new,
		struct collision_cb *cb);
void bib_clean(struct bib *db, struct net *ns);

/* These are used by userspace request handling. */

struct bib_foreach_func {
	int (*cb)(struct bib_entry *, bool, void *);
	void *arg;
};

struct session_foreach_func {
	int (*cb)(struct session_entry *, void *);
	void *arg;
};

struct session_foreach_offset {
	struct taddr4_tuple offset;
	bool include_offset;
};

int bib_foreach(struct bib *db, l4_protocol proto,
		struct bib_foreach_func *func,
		const struct ipv4_transport_addr *offset);
int bib_foreach_session(struct bib *db, l4_protocol proto,
		struct session_foreach_func *collision_cb,
		struct session_foreach_offset *offset);
int bib_find6(struct bib *db, l4_protocol proto,
		struct ipv6_transport_addr *addr,
		struct bib_entry *result);
int bib_find4(struct bib *db, l4_protocol proto,
		struct ipv4_transport_addr *addr,
		struct bib_entry *result);
int bib_add_static(struct bib *db, struct bib_entry *new,
		struct bib_entry *old);
int bib_rm(struct bib *db, struct bib_entry *entry);
void bib_rm_range(struct bib *db, l4_protocol proto, struct ipv4_range *range);
void bib_flush(struct bib *db);
int bib_count(struct bib *db, l4_protocol proto, __u64 *count);
int bib_count_sessions(struct bib *db, l4_protocol proto, __u64 *count);

void bib_print(struct bib *db);

/* The user of this module has to implement this. */
enum session_fate tcp_est_expire_cb(struct session_entry *new, void *arg);

#endif /* _JOOL_MOD_SESSION_DB_H */
