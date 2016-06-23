#ifndef _JOOL_MOD_BIB_ENTRY_H
#define _JOOL_MOD_BIB_ENTRY_H

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

void bibentry_log(const struct bib_entry *bib, const char *action);

#endif /* _JOOL_MOD_BIB_ENTRY_H */
