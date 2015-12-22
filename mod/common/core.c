#include "nat64/mod/common/core.h"

#include "nat64/mod/common/config.h"
#include "nat64/mod/common/handling_hairpinning.h"
#include "nat64/mod/common/namespace.h"
#include "nat64/mod/common/rfc6145/core.h"
#include "nat64/mod/stateful/compute_outgoing_tuple.h"
#include "nat64/mod/stateful/determine_incoming_tuple.h"
#include "nat64/mod/stateful/filtering_and_updating.h"
#include "nat64/mod/stateful/fragment_db.h"
#include "nat64/mod/common/send_packet.h"


static verdict core_common(struct packet *in)
{
	struct packet out;
	struct tuple tuple_in;
	struct tuple tuple_out;
	verdict result;

	if (xlat_is_nat64()) {
		result = determine_in_tuple(in, &tuple_in);
		if (result != VERDICT_CONTINUE)
			goto end;
		result = filtering_and_updating(in, &tuple_in);
		if (result != VERDICT_CONTINUE)
			goto end;
		result = compute_out_tuple(&tuple_in, &tuple_out, in);
		if (result != VERDICT_CONTINUE)
			goto end;
	}
	result = translating_the_packet(&tuple_out, in, &out);
	if (result != VERDICT_CONTINUE)
		goto end;

	if (is_hairpin(&out, &tuple_out)) {
		result = handling_hairpinning(&out, &tuple_out);
		kfree_skb(out.skb);
	} else {
		result = sendpkt_send(in, &out);
		/* sendpkt_send() releases out's skb regardless of verdict. */
	}

	if (result != VERDICT_CONTINUE)
		goto end;

	log_debug("Success.");
	/*
	 * The new packet was sent, so the original one can die; drop it.
	 *
	 * NF_DROP translates into an error (see nf_hook_slow()).
	 * Sending a replacing & translated version of the packet should not
	 * count as an error, so we free the incoming packet ourselves and
	 * return NF_STOLEN on success.
	 */
	kfree_skb(in->skb);
	result = VERDICT_STOLEN;
	/* Fall through. */

end:
	if (result == VERDICT_ACCEPT)
		log_debug("Returning the packet to the kernel.");
	return result;
}

static struct jool_instance *get_jool_instance(const struct net_device *dev)
{
#ifdef CONFIG_NET_NS
	return joolns_get(dev_net(dev));
#else
	return joolns_get(&init_net); /* TODO is this right? */
#endif
}

unsigned int core_4to6(struct sk_buff *skb, const struct net_device *dev)
{
	struct jool_instance *jool;
	struct packet pkt;
	struct iphdr *hdr = ip_hdr(skb);
	verdict result;

	/*
	 * TODO (fine) The first if is silly.
	 * We should probably unhook Jool from Netfilter instead.
	 */
	if (config_is_xlat_disabled())
		return NF_ACCEPT;

	jool = get_jool_instance(dev);
	if (!jool)
		return NF_ACCEPT;

	log_debug("===============================================");
	log_debug("Catching IPv4 packet: %pI4->%pI4", &hdr->saddr, &hdr->daddr);

	/* Reminder: This function might change pointers. */
	if (pkt_init_ipv4(&pkt, skb, jool) != 0) {
		result = VERDICT_DROP;
		goto end;
	}

	result = core_common(&pkt);
	/* Fall through. */

end:
	joolns_return(jool);
	return result;
}

unsigned int core_6to4(struct sk_buff *skb, const struct net_device *dev)
{
	struct jool_instance *jool;
	struct packet pkt;
	struct ipv6hdr *hdr = ipv6_hdr(skb);
	verdict result;

	if (config_is_xlat_disabled())
		return NF_ACCEPT;

	jool = get_jool_instance(dev);
	if (!jool)
		return NF_ACCEPT;

	log_debug("===============================================");
	log_debug("Catching IPv6 packet: %pI6c->%pI6c",
			&hdr->saddr, &hdr->daddr);

	/* Reminder: This function might change pointers. */
	if (pkt_init_ipv6(&pkt, skb, jool) != 0) {
		result = VERDICT_DROP;
		goto end;
	}

	if (xlat_is_nat64()) {
		result = fragdb_handle(&pkt);
		if (result != VERDICT_CONTINUE)
			goto end;
	}

	result = core_common(&pkt);
	/* Fall through. */

end:
	joolns_return(jool);
	return result;
}
