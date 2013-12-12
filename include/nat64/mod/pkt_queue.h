#ifndef _NF_NAT64_PKT_QUEUE_H
#define _NF_NAT64_PKT_QUEUE_H

/**
 * @file
 * The Session tables.
 * Formally defined in RFC 6146 section 3.2.
 *
 * @author Angel Cazares
 */

#include "nat64/comm/types.h"
#include "nat64/mod/bib.h"
#include "nat64/mod/session.h"

#include <linux/skbuff.h>

/**
 * Adds a packet's reference
 *
 *
 * @param session_entry_p
 * @param skb
 * @return whether the packet could be inserted or not. It will not be inserted
 *		if some dynamic memory allocation failed.
 */
int pktqueue_add(struct session_entry *session_entry_p, struct sk_buff *skb);

/*
 * Initializes the TCP packet list
 * Call during initialization of the filtering and updating module
 */
int pktqueue_init(void);

/*
 * Destroy the packet queue
 * Call during the destroy of the filtering and updating module
 */
void pktqueue_destroy(void);

#endif
