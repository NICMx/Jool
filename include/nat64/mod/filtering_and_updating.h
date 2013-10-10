#ifndef _NF_NAT64_FILTERING_H
#define _NF_NAT64_FILTERING_H

#include <linux/netfilter.h>
#include "nat64/comm/constants.h"
#include "nat64/comm/types.h"
#include "nat64/comm/config_proto.h"
#include "nat64/mod/bib.h"
#include "nat64/mod/session.h"


/**
 * Main F&U routine. Called during the processing of every packet.
 */
int filtering_and_updating(struct packet* pkt, struct tuple *tuple);

/**
 * This function should be called when "session_entry_p" expires. If F&U has reasons to prevent its
 * murder, this function will update its lifetime and return true.
 *
 * @param[in]   session_entry   The entry whose lifetime just expired.
 * @return true: keep STE, false: remove STE.
 */
bool session_expired(struct session_entry *session_entry_p);

/**
 * Loads the default configuration.
 */
int filtering_init(void);

/**
 * Frees any memory allocated by this module.
 */
void filtering_destroy(void);

/**
 * Copies the current configuration to "clone".
 */
int clone_filtering_config(struct filtering_config *clone);

/**
 * Updates the "operation"th value of the running configuration.
 */
int set_filtering_config(__u32 operation, struct filtering_config *new_config);


#endif /* _NF_NAT64_FILTERING_H */
