#include "nl_handler.h"

#include <linux/version.h>
#include "expecter.h"
#include "genetlink.h"
#include "sender.h"
#include "nat64/common/types.h"

static DEFINE_MUTEX(config_mutex);

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

int verify_superpriv(void)
{
	if (!capable(CAP_NET_ADMIN)) {
		log_err("Administrative privileges required.");
		return -EPERM;
	}

	return 0;
}

static int handle_expect_add(struct genl_info *info)
{
	struct expected_packet pkt;
	struct nlattr *attr;

	if (verify_superpriv())
		return -EPERM;

	attr = info->attrs[ATTR_FILENAME];
	if (!attr) {
		log_err("Request lacks a file name.");
		return -EINVAL;
	}
	pkt.filename = nla_data(attr);

	attr = info->attrs[ATTR_PKT];
	if (!attr) {
		log_err("Request lacks a packet.");
		return -EINVAL;
	}
	pkt.bytes = nla_data(attr);
	pkt.bytes_len = nla_len(attr);

	attr = info->attrs[ATTR_EXCEPTIONS];
	pkt.exceptions = attr ? nla_data(attr) : NULL;
	pkt.exceptions_len = attr ? (nla_len(attr) / sizeof(*pkt.exceptions)) : 0;

	return genl_respond(info, expecter_add(&pkt));
}

static int handle_send(struct genl_info *info)
{
	char *filename;
	struct nlattr *attr;
	int error;

	if (verify_superpriv())
		return -EPERM;

	attr = info->attrs[ATTR_FILENAME];
	if (!attr) {
		log_err("Request lacks a file name.");
		return -EINVAL;
	}
	filename = nla_data(attr);

	attr = info->attrs[ATTR_PKT];
	if (!attr) {
		log_err("Request lacks a packet.");
		return -EINVAL;
	}

	error = sender_send(filename, nla_data(attr), nla_len(attr));
	return genl_respond(info, error);
}

static int handle_expect_flush(struct genl_info *info)
{
	if (verify_superpriv())
		return -EPERM;

	expecter_flush();
	return genl_respond(info, 0);
}

static int handle_stats_display(struct genl_info *info)
{
	struct graybox_stats stats;
	expecter_stat(&stats);
	return genl_respond_attr(info, ATTR_STATS, &stats, sizeof(stats));
}

static int handle_stats_flush(struct genl_info *info)
{
	expecter_stat_flush();
	return genl_respond(info, 0);
}

static int handle_userspace_msg(struct sk_buff *skb, struct genl_info *info)
{
	int error;

	mutex_lock(&config_mutex);
	error_pool_activate();

	switch (info->genlhdr->cmd) {
	case COMMAND_EXPECT_ADD:
		error = handle_expect_add(info);
		break;
	case COMMAND_EXPECT_FLUSH:
		error = handle_expect_flush(info);
		break;
	case COMMAND_SEND:
		error = handle_send(info);
		break;
	case COMMAND_STATS_DISPLAY:
		error = handle_stats_display(info);
		break;
	case COMMAND_STATS_FLUSH:
		error = handle_stats_flush(info);
		break;
	default:
		log_err("Unknown command code: %d", info->genlhdr->cmd);
		error_pool_deactivate();
		return genl_respond(info, -EINVAL);
	}

	error_pool_deactivate();
	mutex_unlock(&config_mutex);

	return error;
}

static struct genl_ops ops[] = {
	{
		.cmd = COMMAND_EXPECT_ADD,
		.doit = handle_userspace_msg,
	},
	{
		.cmd = COMMAND_EXPECT_FLUSH,
		.doit = handle_userspace_msg,
	},
	{
		.cmd = COMMAND_SEND,
		.doit = handle_userspace_msg,
	},
	{
		.cmd = COMMAND_STATS_DISPLAY,
		.doit = handle_userspace_msg,
	},
	{
		.cmd = COMMAND_STATS_FLUSH,
		.doit = handle_userspace_msg,
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

	genl_init(&family);
	return 0;
}

void nlhandler_destroy(void)
{
	genl_unregister_family(&family);
}
