#ifndef _JOOL_MOD_FRAGMENT_DB_H
#define _JOOL_MOD_FRAGMENT_DB_H

/**
 * @file
 * Normally, the kernel's defragmenters (nf_defrag_ipv6 and nf_defrag_ipv4) queue the fragments in
 * a list. Normally, this list is skb_shinfo(skb)->frag_list, where skb is the first fragment.
 *
 * nf_defrag_ipv6 from kernels 3.0 through 3.12 works differently. Instead of queuing the
 * fragments, it only sorts them, and fetches them separately.
 *
 * This module queues these fragments in skb_shinfo(skb)->frag_list so the rest of Jool doesn't
 * have to worry about handling fragments differently depending on kernel version.
 */

#include "nat64/mod/types.h"
#include "nat64/comm/config_proto.h"


int fragdb_init(void);

int fragdb_set_config(enum fragmentation_type type, size_t size, void *value);
int fragdb_clone_config(struct fragmentation_config *clone);

verdict fragdb_handle(struct sk_buff *skb_in, struct sk_buff **skb_out);

void fragdb_destroy(void);


#endif /* _JOOL_MOD_FRAGMENT_DB_H */
