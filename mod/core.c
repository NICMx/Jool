#include "nat64/mod/core.h"
#include "nat64/comm/nat64.h"
#include "nat64/mod/packet.h"
#include "nat64/mod/ipv6_hdr_iterator.h"
#include "nat64/mod/pool4.h"
#include "nat64/mod/pool6.h"
#include "nat64/mod/bib.h"
#include "nat64/mod/session.h"
#include "nat64/mod/config.h"
#include "nat64/mod/determine_incoming_tuple.h"
#include "nat64/mod/filtering_and_updating.h"
#include "nat64/mod/compute_outgoing_tuple.h"
#include "nat64/mod/translate_packet.h"
#include "nat64/mod/handling_hairpinning.h"
#include "nat64/mod/send_packet.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/ip.h>
#include <net/ipv6.h>
#include <net/netfilter/nf_conntrack.h>


MODULE_LICENSE("GPL");
MODULE_AUTHOR("NIC-ITESM");
MODULE_DESCRIPTION("\"NAT64\" (RFC 6146)");
/* MODULE_ALIAS("nat64"); TODO (later) uncomment when we fix the project's name. */

static char *pool6[5];
static int pool6_size;
module_param_array(pool6, charp, &pool6_size, 0);
MODULE_PARM_DESC(pool6, "The IPv6 pool's prefixes.");
static char *pool4[5];
static int pool4_size;
module_param_array(pool4, charp, &pool4_size, 0);
MODULE_PARM_DESC(pool4, "The IPv4 pool's addresses.");


unsigned int nat64_core(struct sk_buff *skb_in,
		bool (*compute_out_tuple_fn)(struct tuple *, struct sk_buff *, struct tuple *),
		bool (*translate_packet_fn)(struct tuple *, struct sk_buff *, struct sk_buff **),
		bool (*send_packet_fn)(struct sk_buff *, struct sk_buff *))
{
	struct sk_buff *skb_out = NULL;
	struct tuple tuple_in, tuple_out;

	if (!determine_in_tuple(skb_in, &tuple_in))
		goto free_and_fail;
	if (filtering_and_updating(skb_in, &tuple_in) != NF_ACCEPT)
		goto free_and_fail;
	if (!compute_out_tuple_fn(&tuple_in, skb_in, &tuple_out))
		goto free_and_fail;
	if (!translate_packet_fn(&tuple_out, skb_in, &skb_out))
		goto free_and_fail;
	if (is_hairpin(&tuple_out)) {
		if (!handling_hairpinning(skb_out, &tuple_out))
			goto free_and_fail;
	} else {
		if (!send_packet_fn(skb_in, skb_out))
			goto fail;
	}

	log_debug("Success.");
	return NF_DROP; /* Lol, the irony. */

free_and_fail:
	kfree_skb(skb_out);
	/* Fall through. */

fail:
	log_debug("Failure.");
	return NF_DROP;
}

unsigned int hook_ipv4(unsigned int hooknum, struct sk_buff *skb,
		const struct net_device *in, const struct net_device *out,
		int (*okfn)(struct sk_buff *))
{
	struct iphdr *ip4_header;
	struct in_addr daddr;
	enum verdict result;

	skb_linearize(skb);

	ip4_header = ip_hdr(skb);

	daddr.s_addr = ip4_header->daddr;
	if (!pool4_contains(&daddr))
		return NF_ACCEPT;

	log_debug("===============================================");
	log_debug("Catching IPv4 packet: %pI4->%pI4", &ip4_header->saddr, &ip4_header->daddr);

	result = validate_skb_ipv4(skb);
	if (result != VER_CONTINUE)
		return result;

	return nat64_core(skb,
			compute_out_tuple_4to6,
			translating_the_packet_4to6,
			send_packet_ipv6);
}

unsigned int hook_ipv6(unsigned int hooknum, struct sk_buff *skb,
		const struct net_device *in, const struct net_device *out,
		int (*okfn)(struct sk_buff *))
{
	struct ipv6hdr *ip6_header;
	enum verdict result;

	skb_linearize(skb);

	ip6_header = ipv6_hdr(skb);

	if (!pool6_contains(&ip6_header->daddr))
		return NF_ACCEPT;

	log_debug("===============================================");
	log_debug("Catching IPv6 packet: %pI6c->%pI6c", &ip6_header->saddr, &ip6_header->daddr);

	result = validate_skb_ipv6(skb);
	if (result != VER_CONTINUE)
		return result;

	return nat64_core(skb,
			compute_out_tuple_6to4,
			translating_the_packet_6to4,
			send_packet_ipv4);
}

static void deinit(void)
{
	translate_packet_destroy();
	filtering_destroy();
	session_destroy();
	bib_destroy();
	pool4_destroy();
	pool6_destroy();
	config_destroy();
}

static struct nf_hook_ops nfho[] = {
	{
		.hook = hook_ipv6,
		.hooknum = NF_INET_PRE_ROUTING,
		.pf = PF_INET6,
		.priority = NF_PRI_NAT64,
	},
	{
		.hook = hook_ipv4,
		.hooknum = NF_INET_PRE_ROUTING,
		.pf = PF_INET,
		.priority = NF_PRI_NAT64,
	}
};

int __init nat64_init(void)
{
	int error;

	log_debug("%s", banner);
	log_debug("Inserting the module...");

	error = config_init();
	if (error)
		goto failure;
	error = pool6_init(pool6, pool6_size);
	if (error)
		goto failure;
	error = pool4_init(pool4, pool4_size);
	if (error)
		goto failure;
	error = bib_init();
	if (error)
		goto failure;
	error = session_init(session_expired);
	if (error)
		goto failure;
	error = filtering_init();
	if (error)
		goto failure;
	error = translate_packet_init();
	if (error)
		goto failure;

	error = nf_register_hooks(nfho, ARRAY_SIZE(nfho));
	if (error)
		goto failure;

	log_debug("Ok, success.");
	return error;

failure:
	deinit();
	return error;
}

void __exit nat64_exit(void)
{
	deinit();
	nf_unregister_hooks(nfho, ARRAY_SIZE(nfho));
	log_debug("NAT64 module removed.");
}

module_init(nat64_init);
module_exit(nat64_exit);
