#include "nf_nat64_types.h"
#include "nf_nat64_config.h"

#include "external_stuff.h"
#include "nf_nat64_determine_incoming_tuple.h"
#include "nf_nat64_outgoing.h"
#include "nf_nat64_translate_packet.h"
#include "nf_nat64_handling_hairpinning.h"
#include "nf_nat64_send_packet.h"


bool nat64_got_hairpin(struct nf_conntrack_tuple *outgoing) {
	if (outgoing->l3_protocol == NFPROTO_IPV6) {
		// TODO (later) esto no debería ser un query a pool?
		if (ntohl(outgoing->dst.u3.in.s_addr) >= ntohl(config.ipv4_pool_range_first.s_addr) &&
			ntohl(outgoing->dst.u3.in.s_addr) <= ntohl(config.ipv4_pool_range_last.s_addr)) {
			return true;
		} 
 	} 
	return false;
}

bool nat64_handling_hairpinning(struct sk_buff *skb_in, struct nf_conntrack_tuple *tuple_in)
{
	struct sk_buff *skb_out = NULL;
	struct nf_conntrack_tuple *tuple_out = NULL;

	log_debug("Step 5: Handling Hairpinning...");

	if (!nat64_determine_incoming_tuple(skb_in, &tuple_in))
		goto free_and_fail;
	if (!nat64_filtering_and_updating(tuple_in))
		goto free_and_fail;
	if (!nat64_determine_outgoing_tuple_4to6(tuple_in, &tuple_out))
		goto free_and_fail;
	if (!nat64_translating_the_packet(tuple_out, skb_in, &skb_out))
		goto free_and_fail;
	if (!nat64_send_packet_ipv6(skb_out))
		goto fail;

	log_debug("Done step 5.");
	kfree(tuple_out);
	return true;

free_and_fail:
	kfree_skb(skb_out);

fail:
	kfree(tuple_out);
	return false;
}
