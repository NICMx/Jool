#ifndef _JOOL_MOD_BIB_ENTRY_H
#define _JOOL_MOD_BIB_ENTRY_H

#include "nat64/mod/common/types.h"

/**
 * A row, intended to be part of one of the BIB tables.
 * A binding between a transport address from the IPv4 network to one from the
 * IPv6 network.
 *
 * Please note that modifications to this structure may need to cascade to
 * struct bib_entry_usr.
 */
struct bib_entry {
	/** The address from the IPv4 network. */
	const struct ipv4_transport_addr ipv4;
	/** The address from the IPv6 network. */
	const struct ipv6_transport_addr ipv6;

	/** l4 protocol used for pool4 return. */
	const l4_protocol l4_proto;

	/**
	 * Should the entry never expire?
	 *
	 * This field is currently only being used by the userspace app's code.
	 * If you want to do something else with it, keep in mind that you might
	 * face the wrath of concurrence hell, because the configuration mutex
	 * is the only thing protecting it.
	 *
	 * The kernel never needs to know whether the entry is static.
	 * Preventing the death of a static entry when it runs out of sessions
	 * is handled by adding a fake user to refcounter.
	 */
	bool is_static;

	/**
	 * Number of active references to this entry, excluding the ones from
	 * the table it belongs to.
	 * When this reaches zero, the db module removes the entry from the
	 * table and frees it.
	 */
	struct kref refcounter;

	/** Appends this entry to the database's IPv6 index. */
	struct rb_node tree6_hook;
	/** Appends this entry to the database's IPv4 index. */
	struct rb_node tree4_hook;

	/**
	 * A reference for the IPv4 borrowed from pool4, this is hold it just
	 * for keeping the host6_node alive in the database.
	 */
	struct host_addr4 *host4_addr;
};

int bibentry_init(void);
void bibentry_destroy(void);

struct bib_entry *bibentry_create(const struct ipv4_transport_addr *addr4,
		const struct ipv6_transport_addr *addr6,
		const bool is_static, const l4_protocol proto);
void bibentry_kfree(struct bib_entry *bib);
void bibentry_get(struct bib_entry *bib);
int bibentry_return(struct bib_entry *bib);

void bibentry_log(const struct bib_entry *bib, const char *action);

#endif /* _JOOL_MOD_BIB_ENTRY_H */
