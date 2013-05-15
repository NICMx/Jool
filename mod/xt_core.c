#include "nat64/mod/xt_core.h"
#include "nat64/comm/nat64.h"
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
//MODULE_ALIAS("nat64"); // TODO (later) uncomment when we fix the project's name.

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
	return NF_DROP; // Lol, the irony.

free_and_fail:
	kfree_skb(skb_out);
	// Fall through.

fail:
	log_debug("Failure.");
	return NF_DROP;
}

unsigned int hook_ipv4(unsigned int hooknum, struct sk_buff *skb,
		const struct net_device *in, const struct net_device *out,
		int (*okfn)(struct sk_buff *))
{
	struct iphdr *ip4_header;
	__u8 l4protocol;
	struct in_addr daddr;

	skb_linearize(skb);
	
	ip4_header = ip_hdr(skb);
	l4protocol = ip4_header->protocol;

	// Validate.
	daddr.s_addr = ip4_header->daddr;
	if (!pool4_contains(&daddr))
		return NF_ACCEPT; // Let something else handle it.

	log_debug("===============================================");
	log_debug("Catching IPv4 packet: %pI4->%pI4", &ip4_header->saddr, &ip4_header->daddr);

	// TODO (test) validate l4 headers further?
	if (l4protocol != IPPROTO_TCP && l4protocol != IPPROTO_UDP && l4protocol != IPPROTO_ICMP) {
		log_debug("Packet does not use TCP, UDP or ICMP.");
		return NF_ACCEPT;
	}

	// Set the skb's transport header pointer.
	// It's yet to be set because the packet hasn't reached the kernel's transport layer.
	// And despite that, its availability will be appreciated.
	skb_set_transport_header(skb, 4 * ip4_header->ihl);

log_warning("%pI4 -> %pI4 skb->len:%d , ip4_header->tot_len:%d",
		&ip4_header->saddr, &ip4_header->daddr, 
		(skb->len), be16_to_cpu(ip4_header->tot_len) );


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
	struct hdr_iterator iterator;
	enum hdr_iterator_result iterator_result;
	__u8 l4protocol;

	skb_linearize(skb);
	
	ip6_header = ipv6_hdr(skb);
	hdr_iterator_init(&iterator, ip6_header);
	
	// Validate.
	if (!pool6_contains(&ip6_header->daddr))
		goto failure;

	log_debug("===============================================");
	log_debug("Catching IPv6 packet: %pI6c->%pI6c", &ip6_header->saddr, &ip6_header->daddr);

	iterator_result = hdr_iterator_last(&iterator);
	switch (iterator_result) {
	case HDR_ITERATOR_SUCCESS:
		log_crit(ERR_INVALID_ITERATOR, "Iterator reports there are headers beyond the payload.");
		goto failure;
	case HDR_ITERATOR_END:
		l4protocol = iterator.hdr_type;
		break;
	case HDR_ITERATOR_UNSUPPORTED:
		// RFC 6146 section 5.1.
		log_info("Packet contains an Authentication or ESP header, which I do not support.");
		goto failure;
	case HDR_ITERATOR_OVERFLOW:
		log_warning("IPv6 extension header analysis ran past the end of the packet. "
				"Packet seems corrupted; ignoring.");
		goto failure;
	default:
		log_crit(ERR_INVALID_ITERATOR, "Unknown header iterator result code: %d.", iterator_result);
		goto failure;
	}

	switch (l4protocol) {
	case NEXTHDR_TCP:
		if (iterator.data + tcp_hdrlen(skb) > iterator.limit) {
			log_warning("TCP header doesn't fit in the packet. Packet seems corrupted; ignoring.");
			goto failure;
		}
		break;

	case NEXTHDR_UDP: {
		struct udphdr *hdr = iterator.data;
		if (iterator.data + sizeof(struct udphdr) > iterator.limit) {
			log_warning("UDP header doesn't fit in the packet. Packet seems corrupted; ignoring.");
			goto failure;
		}
		if (iterator.data + be16_to_cpu(hdr->len) > iterator.limit) {
			log_warning("UDP header + payload do not fit in the packet. "
					"Packet seems corrupted; ignoring.");
			goto failure;
		}
		break;
	}

	case NEXTHDR_ICMP: {
		struct icmp6hdr *hdr = iterator.data;
		if (iterator.data + sizeof(*hdr) > iterator.limit) {
			log_warning("ICMP header doesn't fit in the packet. Packet seems corrupted; ignoring.");
			goto failure;
		}
		break;
	}

	default:
		log_info("Packet does not use TCP, UDP or ICMPv6.");
		goto failure;
	}

	// Set the skb's transport header pointer.
	// It's yet to be set because the packet hasn't reached the kernel's transport layer.
	// And despite that, its availability will be appreciated.
	skb_set_transport_header(skb, iterator.data - (void *) ip6_header);

	return nat64_core(skb,
			compute_out_tuple_6to4,
			translating_the_packet_6to4,
			send_packet_ipv4);

failure:
	return NF_ACCEPT;
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
	error = session_init();
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
