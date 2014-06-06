#ifndef _NF_NAT64_FILTERING_H
#define _NF_NAT64_FILTERING_H

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

int clone_filtering_config(struct filtering_config *clone);
int set_filtering_config(__u32 operation, struct filtering_config *new_config);

verdict filtering_and_updating(struct fragment *frag, struct tuple *tuple);

void set_tcp_trans_timer(struct session_entry *session);

#endif /* _NF_NAT64_FILTERING_H */
