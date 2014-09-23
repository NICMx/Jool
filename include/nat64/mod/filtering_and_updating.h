#ifndef _JOOL_MOD_FILTERING_H
#define _JOOL_MOD_FILTERING_H

/**
 * @file
 * Second step of the stateful NAT64 translation algorithm: "Filtering and Updating Binding and
 * Session Information", as defined in RFC6146 section 3.5.
 *
 * @author Roberto Aceves
 * @author Alberto Leiva
 * @author Daniel Hernandez
 */

#include "nat64/comm/types.h"
#include "nat64/comm/config_proto.h"
#include "nat64/mod/packet.h"
#include "nat64/mod/session_db.h"


int filtering_init(void);
void filtering_destroy(void);

int filtering_clone_config(struct filtering_config *clone);
int filtering_set_config(enum filtering_type type, size_t size, void *value);

verdict filtering_and_updating(struct sk_buff *skb, struct tuple *in_tuple);


#endif /* _JOOL_MOD_FILTERING_H */
