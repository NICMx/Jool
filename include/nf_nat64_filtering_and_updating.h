/**
 *  @file Filtering.h
 *
 *  @brief  Function prototypes used to test structures defined in files 
 *          'nf_nat64_bib_session.h' and 'nf_nat64_types.h'
 */

#ifndef _FILTERING_H
#define _FILTERING_H

#include <linux/netfilter.h>
#include "nf_nat64_types.h"
#include "nf_nat64_bib.h"
#include "nf_nat64_session.h"
#include "nf_nat64_constants.h"



int filtering_and_updating(struct sk_buff* skb, struct nf_conntrack_tuple *tuple);

bool session_expired(struct session_entry *session_entry_p);

#endif
