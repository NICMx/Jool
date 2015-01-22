#include "config.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/skbuff.h>
#include <linux/ipv6.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/sock.h>
#include <net/netlink.h>

#include "types.h"
#include "ipv6_hdr_iterator.h"
#include "send_packet.h"
#include "receiver.h"
#include "skb_ops.h"


/**
 * Socket the userspace application will speak to.
 */
static struct sock *nl_socket;

/**
 * A lock, used to avoid sync issues when receiving messages from userspace.
 *
 * This was already here when I joined this project, but AFAIK this is only used to protect RCU
 * updating code. -- ydahhrk
 */
/* TODO: dhernandez I guess this might not be necessary, check function receive_from_usrspace().
static DEFINE_MUTEX(my_mutex);*/

/**
 * Use this when data_len is known to be smaller than BUFFER_SIZE.
 */
static int respond_single_msg(struct nlmsghdr *nl_hdr_in, int type,
		void *payload, int payload_len)
{
	struct sk_buff *skb_out;
	struct nlmsghdr *nl_hdr_out;
	int res;

	skb_out = nlmsg_new(NLMSG_ALIGN(payload_len), GFP_ATOMIC);
	if (!skb_out) {
		log_err("Failed to allocate a response skb to the user.");
		return -ENOMEM;
	}

	nl_hdr_out = nlmsg_put(skb_out,
			0, /* src_pid (0 = kernel) */
			nl_hdr_in->nlmsg_seq, /* seq */
			type, /* type */
			payload_len, /* payload len */
			0); /* flags */
	memcpy(nlmsg_data(nl_hdr_out), payload, payload_len);
	/* NETLINK_CB(skb_out).dst_group = 0; */

	res = nlmsg_unicast(nl_socket, skb_out, nl_hdr_in->nlmsg_pid);
	if (res < 0) {
		log_err("Error code %d while returning response to the user.", res);
		return res;
	}

	return 0;
}


/**
 * "ACK messages also use the message type NLMSG_ERROR and payload format
 * but the error code is set to 0."
 * (http://www.infradead.org/~tgr/libnl/doc/core.html#core_msg_ack).
 */
static int respond_error(struct nlmsghdr *nl_hdr_in, int error)
{
	struct nlmsgerr payload = { abs(error), *nl_hdr_in };
	return respond_single_msg(nl_hdr_in, NLMSG_ERROR, &payload,
			sizeof(payload));
}

static void print_pkt(void *skb)
{
	struct iphdr *hdr4;
	struct ipv6hdr *hdr6;

	switch (get_l3_proto(skb)) {
	case 6:
		hdr6 = skb;
		log_debug("Version: %u", hdr6->version);
		log_debug("Priority: %u", hdr6->priority);
		/* __u8 flow_lbl[3]; */
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
		/* log_debug("Check: %u", hdr4->); */
		log_debug("Saddr: %pI4", &hdr4->saddr);
		log_debug("Daddr: %pI4", &hdr4->daddr);
		break;
	default:
		log_err("Invalid protocol: %u", get_l3_proto(skb));
		break;
	}
}

/**
 *	Handler for the sender module.
 */
static int handle_send_packet_order(void *pkt, u32 pkt_len)
{
	struct sk_buff *skb;
	int error;

	error = skb_from_pkt(pkt, pkt_len, &skb);
	if (error)
		return error;

	error = skb_route(skb, pkt);
	if (error)
		return error;

	log_debug("Sending the skb...");
	switch (get_l3_proto(pkt)) {
	case 6:
		error = ip6_local_out(skb);
		break;
	case 4:
		error = ip_local_out(skb);
		break;
	default:
		error = -EINVAL;
	}

	if (error)
		log_err("ip*_local_out returned errcode %d.", error);

	return error;
}

/**
 * Handler for the receiver module.
 */
static int handle_receiver_packet_order(void *pkt, u32 pkt_len)
{
	struct sk_buff *skb;
	int error;

	error = skb_from_pkt(pkt, pkt_len, &skb);
	if (error)
		return error;

	error = handle_skb_from_user(skb);
	if (error)
		kfree(skb);

	return error;
}

static int respond_setcfg(struct nlmsghdr *nl_hdr_in, void *payload, int payload_len)
{
	return respond_single_msg(nl_hdr_in, MSG_TYPE_GRAYBOX, payload, payload_len);
}

/**
 * Gets called by "netlink_rcv_skb" when the userspace application wants to
 * interact with us.
 *
 * @param skb packet received from userspace.
 * @param nlh message's metadata.
 * @return result status.
 */
static int handle_netlink_message(struct sk_buff *skb, struct nlmsghdr *nl_hdr)
{
	struct request_hdr *hdr;
	int error;

	/* log_debug("%u %d", nl_hdr->nlmsg_type, MSG_TYPE_GRAYBOX);*/

	if (nl_hdr->nlmsg_type != MSG_TYPE_GRAYBOX) {
		log_debug("Expecting %#x, got %#x.", MSG_TYPE_GRAYBOX,
				nl_hdr->nlmsg_type);
		return -EINVAL;
	}

	log_debug(" ********* Received a Netlink message. *********");

	hdr = NLMSG_DATA(nl_hdr);
	switch (hdr->mode) {
	case MODE_RECEIVER:
		switch (hdr->operation) {
		case OP_DISPLAY:
			log_debug("showing Receiver stats.");
			error = receiver_display_stats();
			break;
		case OP_ADD:
			log_debug("Adding an SKB from user space.");
			error = handle_receiver_packet_order(hdr + 1, hdr->len);
			break;
		case OP_FLUSH:
			log_debug("Flushing the skb database.");
			error = receiver_flush_db();
			break;
		default:
			log_err("Unknown operation %u", hdr->operation);
			error = -EINVAL;
			break;
		}
		break;
	case MODE_SENDER:
		switch (hdr->operation) {
		case OP_ADD:
			log_debug("Sending an SKB from user space.");
			error = handle_send_packet_order(hdr + 1, hdr->len);
			break;
		default:
			log_err("Unknown operation %u", hdr->operation);
			error = -EINVAL;
			break;
		}
		break;
	case MODE_GENERAL:
		switch (hdr->operation) {
		case OP_DISPLAY:
			log_debug("Showing the byte arrays.");

			error = display_bytes_array();
			break;
		case OP_ADD:
			log_debug("Adding byte arrays.");
			error = update_bytes_array(hdr + 1, hdr->len);
			break;
		case OP_FLUSH:
			log_debug("Flushing the byte arrays.");
			error = flush_bytes_array();
			break;
		default:
			log_err("Unknown operation %u", hdr->operation);
			error = -EINVAL;
			break;
		}
		break;
	default:
		log_err("Unknown mode %u", hdr->mode);
		error = -EINVAL;
		break;
	}
	log_debug(" *********************************************** ");

	return respond_error(nl_hdr, error);
}

/**
 * Gets called by Netlink when the userspace application wants to interact with
 * us.
 *
 * @param skb packet received from userspace.
 */
static void receive_from_userspace(struct sk_buff *skb)
{
	log_debug("Message arrived.");
//	mutex_lock(&my_mutex);
	netlink_rcv_skb(skb, &handle_netlink_message);
//	mutex_unlock(&my_mutex);
}

int config_init(void)
{

	#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 6, 0)
		nl_socket = netlink_kernel_create(&init_net, NETLINK_USERSOCK, 0, receive_from_userspace,
				NULL, THIS_MODULE);
	#elif LINUX_VERSION_CODE < KERNEL_VERSION(3, 7, 0)
		struct netlink_kernel_cfg nl_cfg = { .input  = receive_from_userspace };
		nl_socket = netlink_kernel_create(&init_net, NETLINK_USERSOCK, THIS_MODULE, &nl_cfg);
	#else
		struct netlink_kernel_cfg nl_cfg = { .input  = receive_from_userspace };
		nl_socket = netlink_kernel_create(&init_net, NETLINK_USERSOCK, &nl_cfg);
	#endif
	/**nl_socket = netlink_kernel_create(&init_net, NETLINK_USERSOCK, 0,
			receive_from_userspace, NULL, THIS_MODULE);*/
	if (!nl_socket) {
		log_err("Creation of netlink socket failed.");
		return -EINVAL;
	}
	log_debug("Netlink socket created.");

	return 0;
}

void config_destroy(void)
{
	netlink_kernel_release(nl_socket);
}
