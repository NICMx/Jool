#ifndef _NF_NAT64_HANDLING_HARPINNING_H
#define _NF_NAT64_HANDLING_HARPINNING_H

/**
 * @file
 * Fifth and (officially) last step of the Nat64 translation algorithm: "Handling Hairpinning", as
 * defined in RFC6146 section 3.8.
 * Recognizes a packet that should return from the same interface and handles it accordingly.
 *
 * @author Miguel Gonzalez
 * @author Alberto Leiva  <- maintenance
 */

#include "nat64/comm/types.h"
#include "nat64/mod/packet.h"


bool is_hairpin(struct packet *pkt);
verdict handling_hairpinning(struct packet *pkt_in, struct tuple *tuple_in);


#endif /* _NF_NAT64_HANDLING_HARPINNING_H */
