#ifndef _NF_NAT64_FILTERING_H
#define _NF_NAT64_FILTERING_H

#include <linux/netfilter.h>
#include "nat64/comm/constants.h"
#include "nat64/comm/types.h"
#include "nat64/comm/config_proto.h"
#include "nat64/mod/packet.h"
#include "nat64/mod/bib.h"
#include "nat64/mod/session.h"


int filtering_init(void);
void filtering_destroy(void);

int clone_filtering_config(struct filtering_config *clone);
int set_filtering_config(__u32 operation, struct filtering_config *new_config);

verdict filtering_and_updating(struct packet* pkt, struct tuple *tuple);


#endif /* _NF_NAT64_FILTERING_H */
