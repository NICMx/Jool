#include "nl_handler.h"

#include <linux/version.h>

#include "nat64/mod/common/nl/nl_core2.h"

#include "expecter.h"
#include "sender.h"

/*
static void print_pkt(void *skb)
{
	struct iphdr *hdr4;
	struct ipv6hdr *hdr6;

	switch (get_l3_proto(skb)) {
	case 6:
		hdr6 = skb;
		log_debug("Version: %u", hdr6->version);
		log_debug("Priority: %u", hdr6->priority);
		// __u8 flow_lbl[3];
		log_debug("Payload length: %u", ntohs(hdr6->payload_len));
		log_debug("Nexthdr: %u", hdr6->nexthdr);
		log_debug("Hop limit: %u", hdr6->hop_limit);
		log_debug("Saddr: %pI6c", &hdr6->saddr);
		log_debug("Daddr: %pI6c", &hdr6->daddr);
		break;
	case 4:
		hdr4 = skb;
		log_debug("Version: %u", hdr4->version);
		log_debug("IHL: %u", hdr4->ihl);
		log_debug("TOS: %u", hdr4->tos);
		log_debug("Total length: %u", ntohs(hdr4->tot_len));
		log_debug("ID: %u", hdr4->id);
		log_debug("Fragment offset: %u", hdr4->frag_off);
		log_debug("TTL: %u", hdr4->ttl);
		log_debug("Proto: %u", hdr4->protocol);
		// log_debug("Check: %u", hdr4->);
		log_debug("Saddr: %pI4", &hdr4->saddr);
		log_debug("Daddr: %pI4", &hdr4->daddr);
		break;
	default:
		log_err("Invalid protocol: %u", get_l3_proto(skb));
		break;
	}
}
*/

static struct genl_family family = {
	.id = GENL_ID_GENERATE,
	.hdrsize = 0,
	.name = "graybox",
	.version = 1,
	.maxattr = __ATTR_MAX,
	.netnsok = true,
};

int handle_expect(struct sk_buff *skb, struct genl_info *info)
{
	struct expected_packet pkt;

	pkt.filename = nla_data(info->attrs[ATTR_FILENAME]);
	pkt.bytes = nla_data(info->attrs[ATTR_PKT]);
	pkt.bytes_len = nla_len(info->attrs[ATTR_PKT]);
	pkt.exceptions = nla_data(info->attrs[ATTR_EXCEPTIONS]);
	pkt.exceptions_len = nla_len(info->attrs[ATTR_EXCEPTIONS]);

	return nlcore_respond(info, expecter_add(&pkt));
}

int handle_send(struct sk_buff *skb, struct genl_info *info)
{
	char *filename;
	struct nlattr *pkt;
	int error;

	filename = nla_data(info->attrs[ATTR_FILENAME]);
	pkt = info->attrs[ATTR_PKT];

	error = sender_send(filename, nla_data(pkt), nla_len(pkt));
	return nlcore_respond(info, error);
}

int handle_flush(struct sk_buff *skb, struct genl_info *info)
{
	expecter_flush();
	return nlcore_respond(info, 0);
}

int handle_stats(struct sk_buff *skb, struct genl_info *info)
{
	struct graybox_stats stats;
	expecter_stat(&stats);
	return nlcore_respond_struct(info, &stats, sizeof(stats));
}

static struct genl_ops ops[] = {
	{
		.cmd = COMMAND_EXPECT,
		.doit = handle_expect,
		.dumpit = NULL,
	},
	{
		.cmd = COMMAND_SEND,
		.doit = handle_send,
		.dumpit = NULL,
	},
	{
		.cmd = COMMAND_FLUSH,
		.doit = handle_flush,
		.dumpit = NULL,
	},
	{
		.cmd = COMMAND_STATS,
		.doit = handle_stats,
		.dumpit = NULL,
	},
};

int nlhandler_init(void)
{
	int error;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)
	error = genl_register_family_with_ops(&family, ops, ARRAY_SIZE(ops));
#else
	error = genl_register_family_with_ops(&family, ops);
#endif
	if (error) {
		log_err("Errcode %d registering the Genetlink family.", error);
		return error;
	}

	nlcore_init(&family);
	return 0;
}

void nlhandler_destroy(void)
{
	genl_unregister_family(&family);
}
