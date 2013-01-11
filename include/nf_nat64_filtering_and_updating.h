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
//~ #include "validation.h"
#include "nf_nat64_bib.h"
#include "nf_nat64_session.h"

/* TOCHECK: This could be already defined somewhere else. */
/* ICMP error messaging */
//      Types:
#define TYPE_3  3
#define DESTINATION_UNREACHABLE TYPE_3
//      Codes:
#define CODE_1  1
#define CODE_3  3
#define CODE_13 13
#define HOST_UNREACHABLE        CODE_1
#define ADDRESS_UNREACHABLE     CODE_3
#define COMMUNICATION_ADMINISTRATIVELY_PROHIBITED   CODE_13

int filtering_and_updating(struct sk_buff* skb, struct nf_conntrack_tuple *tuple);

//~ int tcp(struct packet *packet, struct nf_conntrack_tuple *tuple);

#endif
