#ifndef _NF_NAT64_OUTGOING_H
#define _NF_NAT64_OUTGOING_H

#include "nf_nat64_types.h"

bool nat64_compute_outgoing_tuple_tuple5(struct nf_conntrack_tuple * outgoing_tuple, struct nf_conntrack_tuple * incoming_tuple, enum translation_mode translationMode);
bool nat64_compute_outgoing_tuple_tuple3(struct nf_conntrack_tuple * outgoing_tuple, struct nf_conntrack_tuple  *incoming_tuple, enum translation_mode translationMode);

#endif /* _NF_NAT64_OUTGOING_H */
