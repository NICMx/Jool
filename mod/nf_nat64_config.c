#include <linux/module.h>
#include <linux/slab.h>
#include <linux/inet.h>
#include <linux/inetdevice.h>
#include <net/netlink.h>
#include "nf_nat64_config.h"
#include "nf_nat64_static_routes.h"
#include "xt_nat64_module_comm.h"

struct configuration config;
struct config_struct cs;

/**
 * Default values for the config.mtu_plateaus field.
 */
const __u16 DEFAULT_MTU_PLATEAUS[] = { 65535, 32000, 17914, 8166,
		4352, 2002, 1492, 1006,
		508, 296, 68 };

/**
 * Socket the userspace application will speak to. We don't use it directly, but we need the
 * reference anyway.
 */
struct sock *my_nl_sock;

/**
 * A lock, used to avoid sync issues when receiving messages from userspace.
 */
DEFINE_MUTEX(my_mutex);


bool nat64_config_init(void)
{
	struct ipv6_prefixes ip6p;
	struct in_addr ipv4_pool_net;
	struct in_addr ipv4_pool_range_first;
	struct in_addr ipv4_pool_range_last;
	int ipv4_mask_bits;
	__be32 ipv4_netmask;	// TODO change data type -> 'in_addr' type. Rob.

	// TODO: Define & Set values for operational parameters:
	cs.address_dependent_filtering = 0;	//<<< TODO: Use a define for this value!
	cs.filter_informational_icmpv6 = 0;	//<<< TODO: Use a define for this value!
	cs.hairpinning_mode = 0;

	// IPv4 pool config
	if (!str_to_addr4(IPV4_DEF_POOL_NET, &ipv4_pool_net)) {
		log_warning("IPv4 pool net in Headers is malformed [%s].", IPV4_DEF_POOL_NET);
		return false;
	}
	ipv4_mask_bits = IPV4_DEF_POOL_NET_MASK_BITS;	// Num. of bits 'on' in the net mask
	if (ipv4_mask_bits > 32 || ipv4_mask_bits < 1) {
		log_warning("IPv4 Pool netmask bits value is invalid [%d].", IPV4_DEF_POOL_NET_MASK_BITS);
		return false;
	}
	ipv4_netmask = inet_make_mask(ipv4_mask_bits);
	ipv4_pool_net.s_addr = ipv4_pool_net.s_addr & ipv4_netmask; // For the sake of correctness

	if (!str_to_addr4(IPV4_DEF_POOL_FIRST, &ipv4_pool_range_first)) {
		log_warning("IPv4 pool net in Headers is malformed [%s].", IPV4_DEF_POOL_FIRST);
		return false;
	}
	if (!str_to_addr4(IPV4_DEF_POOL_LAST, &ipv4_pool_range_last)) {
		log_warning("IPv4 pool net in Headers is malformed [%s].", IPV4_DEF_POOL_LAST);
		return false;
	}

	cs.ipv4_pool_net = ipv4_pool_net;
	cs.ipv4_pool_net_mask_bits = ipv4_mask_bits;
	cs.ipv4_pool_range_first = ipv4_pool_range_first;
	cs.ipv4_pool_range_last = ipv4_pool_range_last;

	// IPv6 pool config
	if (!str_to_addr6(IPV6_DEF_PREFIX, &ip6p.addr)) {
		log_warning("IPv6 prefix in Headers is malformed [%s].", IPV6_DEF_PREFIX);
		return false;
	}
	if (IPV6_DEF_MASKBITS > IPV6_DEF_MASKBITS_MAX || IPV6_DEF_MASKBITS < IPV6_DEF_MASKBITS_MIN) {
		log_warning("Bad IPv6 network mask bits value in Headers: %d", IPV6_DEF_MASKBITS);
		return false;
	}
	ip6p.maskbits = IPV6_DEF_MASKBITS;

	// TODO (miguel) revisar el valor de retorno de estos kmallocs.
	cs.ipv6_net_prefixes = kmalloc(1 * sizeof(struct ipv6_prefixes*), GFP_ATOMIC);
	cs.ipv6_net_prefixes[0] = kmalloc(sizeof(struct ipv6_prefixes), GFP_ATOMIC);
	(*cs.ipv6_net_prefixes[0]) = ip6p;
	cs.ipv6_net_prefixes_qty = 1;

	log_debug("Initial (default) configuration loaded:");
	log_debug("  using IPv4 pool subnet %pI4/%d (netmask %pI4),", &(cs.ipv4_pool_net),
			cs.ipv4_pool_net_mask_bits, &ipv4_netmask);
	log_debug("  and IPv6 prefix %pI6c/%d.", &(cs.ipv6_net_prefixes[0]->addr),
			cs.ipv6_net_prefixes[0]->maskbits);

	// Translate the packet config
	config.packet_head_room = 0;
	config.packet_tail_room = 32;
	config.override_ipv6_traffic_class = false;
	config.override_ipv4_traffic_class = false;
	config.ipv4_traffic_class = 0;
	config.df_always_set = true;
	config.generate_ipv4_id = false;
	config.improve_mtu_failure_rate = true;
	config.ipv6_nexthop_mtu = 1280;
	config.ipv4_nexthop_mtu = 576;

	config.mtu_plateau_count = ARRAY_SIZE(DEFAULT_MTU_PLATEAUS);
	config.mtu_plateaus = kmalloc(sizeof(DEFAULT_MTU_PLATEAUS), GFP_ATOMIC);
	if (!config.mtu_plateaus) {
		log_warning("Could not allocate memory to store the MTU plateaus.");
		return false;
	}
	memcpy(config.mtu_plateaus, &DEFAULT_MTU_PLATEAUS, sizeof(DEFAULT_MTU_PLATEAUS));

	// Netlink sockets.
	// TODO find out what causes Osorio's compatibility issues and fix it.
/*	struct netlink_kernel_cfg cfg = {
			.input = &my_nl_rcv_msg,
	};
	my_nl_sock = netlink_kernel_create(&init_net, NETLINK_USERSOCK, &cfg);
	if (!my_nl_sock) {
		log_warning("Creation of netlink socket failed.");
		return false;
	}
	log_debug("Netlink socket created.");
*/
	return true;
	// TODO (miguel) hay kmallocs en esta función, y en caso de error no se están liberando.
}

void nat64_config_destroy(void)
{
	// TODO (miguel) hay elementos en la configuración que se encuentran en el heap. Liberarlos.

	// Netlink sockets.
//	if (my_nl_sock)
//		netlink_kernel_release(my_nl_sock);
}

/**
 * Helper of update_nat_config().
 * Writes the "msg" message along with "mst"'s mode and operation on "as", and stores its length in
 * "as_len".
 */
static void write_message(char *msg, struct manconf_struct *mst, struct answer_struct **as,
		__u32 *as_len)
{
	*as_len = sizeof(struct answer_struct) + strlen(msg) + 1;
	*as = kmalloc(*as_len, GFP_ATOMIC); // TODO (miguel) revisar valor de retorno.
	(*as)->mode = mst->mode;
	(*as)->operation = mst->operation;
	memcpy((*as) + 1, msg, strlen(msg) + 1);
}

/**
 * Actual configuration function. Worries nothing of Netlink, and just updates the module's
 * configuration using "mst".
 *
 * @param mst configuration update petition from userspace.
 * @param as this function's response to userspace (out parameter).
 * @param as_len "as"'s length in bytes (out parameter).
 * @return "true" if successful.
 */
bool update_nat_config(struct manconf_struct *mst, struct answer_struct **as, __u32 *as_len)
{
	unsigned char i = 0;
	unsigned char qty = 0;
	struct bib_entry_us *bibs = NULL;
	struct session_entry_us *sessions = NULL;
	__u32 count = 0;
	struct ipv6_prefixes ip6p;

	switch (mst->mode) {
	case 0: // TODO (miguel) #define estas constantes.
		switch (mst->operation) {
		case 2:
			log_debug("Sending BIB to userspace.");
			if (nat64_print_bib_table(&mst->us.rs, &count, &bibs)) {
				__u32 payload_len = count * sizeof(struct bib_entry);

				*as_len = sizeof(struct answer_struct) + payload_len;
				*as = kmalloc(*as_len, GFP_ATOMIC);
				if (!(*as)) {
					// TODO (miguel) liberar bibs.
					return false;
				}
				(*as)->mode = mst->mode;
				(*as)->operation = mst->operation;
				(*as)->array_quantity = count;

				memcpy((*as) + 1, bibs, payload_len);

				kfree(bibs);
			} else {
				if (count == 0)
					write_message("The table is empty.", mst, as, as_len);
				else if (count == -1)
					write_message("Could not allocate the table to display.", mst, as, as_len);
				(*as)->array_quantity = 0;
			}
			break;
		default:
			log_warning("Unknown operation while handling BIBs: %d", mst->operation);
			write_message("Parameter error.", mst, as, as_len);
		}
		break;

	case 1:
		switch (mst->operation) {
		case 0:
			log_debug("Adding session.");
			if (nat64_add_static_route(&mst->us.rs))
				write_message("Insertion was successful.", mst, as, as_len);
			else
				write_message("Could NOT create a new Session entry.", mst, as, as_len);
			break;
		case 1:
			log_debug("Removing session.");
			if (nat64_delete_static_route(&mst->us.rs))
				write_message("Deletion was successful.", mst, as, as_len);
			else
				write_message("Could NOT remove the Session entry.", mst, as, as_len);
			break;
		case 2:
			log_debug("Sending session table to userspace.");
			if (nat64_print_session_table(&mst->us.rs, &count, &sessions)) {
				__u32 payload_len = count * sizeof(struct session_entry);

				*as_len = sizeof(struct answer_struct) + payload_len;
				*as = kmalloc(*as_len, GFP_ATOMIC);
				if (!(*as)) {
					// TODO (miguel) liberar sessions.
					return false;
				}
				(*as)->mode = mst->mode;
				(*as)->operation = mst->operation;
				(*as)->array_quantity = count;

				memcpy((*as) + 1, sessions, payload_len);

				kfree(sessions);
			} else {
				if (count == 0)
					write_message("The table is empty.", mst, as, as_len);
				else if (count == -1)
					write_message("Could not allocate the table to display.", mst, as, as_len);
				(*as)->array_quantity = 0;
			}
			break;
		default:
			log_warning("Unknown operation while handling Sessions: %d", mst->operation);
			write_message("Parameter error.", mst, as, as_len);
		}
		break;

	case 2:
		switch (mst->operation) {
		case 0:
			log_debug("Updating ipv6 pool.");

			qty = (mst->us.cs).ipv6_net_prefixes_qty;
			cs.ipv6_net_prefixes_qty = qty;
			// TODO (miguel) no se están liberando los prefijos anteriores.
			cs.ipv6_net_prefixes = kmalloc(qty * sizeof(struct ipv6_prefixes*), GFP_ATOMIC);
			if (!cs.ipv6_net_prefixes) {
				log_warning("Could not allocate memory to store the IPv6 Prefixes.");
				return false;
			}

			for (i = 0; i < qty; i++) {
				cs.ipv6_net_prefixes[i] = kmalloc(sizeof(struct ipv6_prefixes), GFP_ATOMIC);
				ip6p.addr = mst->us.cs.ipv6_net_prefixes[i]->addr;
				ip6p.maskbits = mst->us.cs.ipv6_net_prefixes[i]->maskbits;
				(*cs.ipv6_net_prefixes[i]) = ip6p;
				log_debug("NAT64:	and IPv6 prefix %pI6c/%d.",
						&mst->us.cs.ipv6_net_prefixes[i]->addr,
						mst->us.cs.ipv6_net_prefixes[i]->maskbits);
			}

			// TODO (miguel) llamar init pool6
			write_message("IPv6 pool was updated.", mst, as, as_len);
			break;
		case 1:
			// TODO (later) implementar múltiples pools de IPv6.
			break;
		case 2: {
			char buffer[65];
			log_debug("IPv6 prefix: %pI6c/%d.", &(cs.ipv6_net_prefixes[0]->addr),
					cs.ipv6_net_prefixes[0]->maskbits);
			sprintf(buffer, "IPv6 prefix: %pI6c/%d.", &(cs.ipv6_net_prefixes[0]->addr),
					cs.ipv6_net_prefixes[0]->maskbits);
			write_message(buffer, mst, as, as_len);
			break;
		}
		default:
			log_warning("Unknown operation while handling the IPv6 pool: %d", mst->operation);
			write_message("Parameter error.", mst, as, as_len);
		}
		break;

	case 3:
		switch (mst->operation) {
		case 0:
			log_debug("Updating ipv4 pool.");
			cs.ipv4_pool_net = mst->us.cs.ipv4_pool_net;
			cs.ipv4_pool_net_mask_bits = mst->us.cs.ipv4_pool_net_mask_bits;
			cs.ipv4_pool_range_first = mst->us.cs.ipv4_pool_range_first;
			cs.ipv4_pool_range_last = mst->us.cs.ipv4_pool_range_last;
			log_debug("	 using IPv4 pool subnet %pI4/%d", &(mst->us.cs.ipv4_pool_net),
					mst->us.cs.ipv4_pool_net_mask_bits);
			//init_pools(&ms.us.cs); // Bernardo
			write_message("IPv4 pool was updated.", mst, as, as_len);
			break;
		case 1:
			// TODO (later) implementar múltiples pools de IPv4.
			break;
		case 2: {
			char buffer[30];
			log_debug("IPv4 pool: %pI4/%d.", &(cs.ipv4_pool_net), cs.ipv4_pool_net_mask_bits);
			sprintf(buffer, "IPv4 pool: %pI4/%d.", &(cs.ipv4_pool_net), cs.ipv4_pool_net_mask_bits);
			write_message(buffer, mst, as, as_len);
			break;
		}
		default:
			log_warning("Unknown operation while handling the IPv4 pool: %d", mst->operation);
			write_message("Parameter error.", mst, as, as_len);
		}
		break;

	case 4:
		log_debug("Updating hair:");
		cs.hairpinning_mode = mst->us.cs.hairpinning_mode;
		write_message("Hairpinning handling was updated.", mst, as, as_len);
		break;

	case 5:
		log_debug("Updating translator options:");

		if (mst->submode & PHR_MASK)
			config.packet_head_room = mst->us.cc.packet_head_room;
		if (mst->submode & PTR_MASK)
			config.packet_tail_room = mst->us.cc.packet_tail_room;
		if (mst->submode & IPV6_NEXTHOP_MASK)
			config.ipv6_nexthop_mtu = mst->us.cc.ipv6_nexthop_mtu;
		if (mst->submode & IPV4_NEXTHOP_MASK)
			config.ipv4_nexthop_mtu = mst->us.cc.ipv4_nexthop_mtu;
		if (mst->submode & IPV4_TRAFFIC_MASK)
			config.ipv4_traffic_class = mst->us.cc.ipv4_traffic_class;
		if (mst->submode & OIPV6_MASK)
			config.override_ipv6_traffic_class = mst->us.cc.override_ipv6_traffic_class;
		if (mst->submode & OIPV4_MASK)
			config.override_ipv4_traffic_class = mst->us.cc.override_ipv4_traffic_class;
		if (mst->submode & DF_ALWAYS_MASK)
			config.df_always_set = mst->us.cc.df_always_set;
		if (mst->submode & GEN_IPV4_MASK)
			config.generate_ipv4_id = mst->us.cc.generate_ipv4_id;
		if (mst->submode & IMP_MTU_FAIL_MASK)
			config.improve_mtu_failure_rate = mst->us.cc.improve_mtu_failure_rate;
		if (mst->submode & MTU_PLATEAUS_MASK) {
			config.mtu_plateau_count = mst->us.cc.mtu_plateau_count;

			config.mtu_plateaus = kmalloc(sizeof(mst->us.cc.mtu_plateaus), GFP_ATOMIC);
			if (!config.mtu_plateaus) {
				log_warning("Could not allocate memory to store the MTU plateaus.");
				return false;
			}
			memcpy(config.mtu_plateaus, &mst->us.cc.mtu_plateaus, sizeof(mst->us.cc.mtu_plateaus));
		}
		if (mst->submode & ADDRESS_DEPENDENT_FILTER_MASK)
			cs.address_dependent_filtering = mst->us.cs.address_dependent_filtering;
		if (mst->submode & FILTER_INFO_MASK)
			cs.filter_informational_icmpv6 = mst->us.cs.filter_informational_icmpv6;
		if (mst->submode & DROP_TCP_MASK)
			cs.drop_externally_initiated_tcp_connections =
					mst->us.cs.drop_externally_initiated_tcp_connections;

		write_message("Translator options were updated.", mst, as, as_len);
		break;

	default:
		log_warning("Unknown mode: %d", mst->mode);
		write_message("Parameter error.", mst, as, as_len);

	}

	return true;
}

/**
 * Gets called by "netlink_rcv_skb" when the userspace application wants to interact with us.
 *
 * @param skb packet received from userspace.
 * @param nlh message's metadata.
 * @return result status.
 *
 * TODO (miguel) Name sounds taken from a tutorial; fix it.
 */
static int my_rcv_msg(struct sk_buff *skb, struct nlmsghdr *nlh)
{
	int type;
	int pid;
	struct manconf_struct *mst;
	struct answer_struct *as;
	int res;
	__u32 aslen;
	struct sk_buff *skb_out;

	type = nlh->nlmsg_type;
	if (type != MSG_TYPE_NAT64) {
		log_debug("Expecting %#x but got %#x.", MSG_TYPE_NAT64, type);
		return -EINVAL;
	}

	mst = NLMSG_DATA(nlh);
	pid = nlh->nlmsg_pid;

	if (!update_nat_config(mst, &as, &aslen) != 0) {
		log_warning("Error while updating NAT64 running configuration");
		return -EINVAL;
	}

	skb_out = nlmsg_new(aslen, 0);
	if (!skb_out) {
		log_warning("Failed to allocate a response skb to the user.");
		return -EINVAL;
	}

	nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, aslen, 0);
	NETLINK_CB(skb_out).dst_group = 0;

	memcpy(nlmsg_data(nlh), as, aslen);
	kfree(as);

	res = nlmsg_unicast(my_nl_sock, skb_out, pid);
	if (res < 0) {
		log_warning("Error code %d while returning response to the user.", res);
		// TODO no debería haber un return -EINVAL aquí?
	}

	// TODO (miguel) as y quizá skb_out no parecen estarse liberando en todos los caminos.
	return 0;
}

/**
 * Gets called by Netlink when the userspace application wants to interact with us.
 *
 * @param skb packet received from userspace.
 *
 * TODO (miguel) Name sounds taken from a tutorial; fix it.
 */
static void my_nl_rcv_msg(struct sk_buff *skb)
{
	log_debug("Message arrived.");
	mutex_lock(&my_mutex);
	netlink_rcv_skb(skb, &my_rcv_msg);
	mutex_unlock(&my_mutex);
}
