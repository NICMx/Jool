#include <linux/module.h>
#include <linux/slab.h>
#include <linux/inet.h>
#include <linux/inetdevice.h>
#include <linux/netlink.h>
#include "nf_nat64_config.h"
#include "nf_nat64_static_routes.h"
#include "xt_nat64_module_comm.h"

struct configuration config;
struct config_struct cs;

const __u16 DEFAULT_MTU_PLATEAUS[] = { 65535, 32000, 17914, 8166,
		4352, 2002, 1492, 1006,
		508, 296, 68 };

/** Apparently, socket to speak to the userspace application with. TODO Also apparently currently unused. */
struct sock *my_nl_sock;

DEFINE_MUTEX(my_mutex);

int my_rcv_msg(struct sk_buff *skb, struct nlmsghdr *nlh)
{
    int type;
	int pid;
    struct manconf_struct *mst;
    struct answer_struct *as;
	int res;
	__u32 aslen;
	struct sk_buff *skb_out;

    type = nlh->nlmsg_type;
    if (type != MSG_TYPE_NAT64)
	{
        pr_debug("NAT64:     netlink: %s: expecting %#x but got %#x\n",
        		 __func__, MSG_TYPE_NAT64, type);
        return -EINVAL;
    }

		mst = NLMSG_DATA(nlh);
		pid = nlh->nlmsg_pid;
		pr_debug("NAT64:     netlink: got message.\n" );
		pr_debug("NAT64:     netlink: updating NAT64 configuration.\n" );

	if (update_nat_config(mst,&as,&aslen) == 0) {

		pr_debug("NAT64:     netlink: Running configuration successfully updated\n");
		//pr_debug("length of our response to userspace: %d\n", aslen);
		//pr_debug("bib: %d struct: %d\n", sizeof(struct bib_entry), sizeof(struct answer_struct));

		pid = nlh->nlmsg_pid;

		skb_out = nlmsg_new(aslen,0);

		if(!skb_out) {
			pr_info("Failed to allocate new skb");
			return -EINVAL;
		}

		nlh=nlmsg_put(skb_out,0,0,NLMSG_DONE,aslen,0);
		NETLINK_CB(skb_out).dst_group = 0;

		memcpy(nlmsg_data(nlh),as,aslen);
		kfree(as);

		res = nlmsg_unicast(my_nl_sock,skb_out,pid);

		if(res < 0) {
	   		pr_info("Error while sending back to user");
		}

	} else {
			pr_debug("NAT64:     netlink: Error while updating NAT64 running configuration\n");
			return -EINVAL;
	}

    return 0;
}

void my_nl_rcv_msg(struct sk_buff *skb)
{

    pr_debug("NAT64:     netlink: message arrived.\n" );

    mutex_lock(&my_mutex);
    netlink_rcv_skb(skb, &my_rcv_msg);
    mutex_unlock(&my_mutex);
}

/**
 * Default configuration, until it be set up by the user space application.
 *
 * @return      TRUE if all was fine, FALSE otherwise.
 */
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

	/* IPv4 pool config */
	// Validate IPv4 Pool Network
    if (! in4_pton(IPV4_DEF_POOL_NET, -1, (u8 *)&ipv4_pool_net.s_addr, '\x0', NULL)) {
        pr_warning("NAT64: IPv4 pool net in Headers is malformed [%s].", IPV4_DEF_POOL_NET);
        return false;
    }
	// Validate IPv4 Pool - Netmask
	ipv4_mask_bits = IPV4_DEF_POOL_NET_MASK_BITS;	// Num. of bits 'on' in the net mask
    if (ipv4_mask_bits > 32 || ipv4_mask_bits < 1) {
        pr_warning("NAT64: IPv4 Pool netmask bits value is invalid [%d].",
                IPV4_DEF_POOL_NET_MASK_BITS);
        return false;
    }
	ipv4_netmask = inet_make_mask(ipv4_mask_bits);
	ipv4_pool_net.s_addr = ipv4_pool_net.s_addr & ipv4_netmask; // For the sake of correctness

	// Validate IPv4 Pool - First and Last addresses .
	if (! in4_pton(IPV4_DEF_POOL_FIRST, -1, (u8 *)&ipv4_pool_range_first.s_addr, '\x0', NULL)) {
        pr_warning("NAT64: IPv4 pool net in Headers is malformed [%s].", IPV4_DEF_POOL_FIRST);
        return false;
    }
    if (! in4_pton(IPV4_DEF_POOL_LAST, -1, (u8 *)&ipv4_pool_range_last.s_addr, '\x0', NULL)) {
        pr_warning("NAT64: IPv4 pool net in Headers is malformed [%s].", IPV4_DEF_POOL_LAST);
        return false;
    }

	// Assing IPv4 values to config struct.
    cs.ipv4_pool_net = ipv4_pool_net;
	cs.ipv4_pool_net_mask_bits = ipv4_mask_bits;
	cs.ipv4_pool_range_first = ipv4_pool_range_first;
	cs.ipv4_pool_range_last = ipv4_pool_range_last;

	/* IPv6 pool config */
    // Validate IPv6 prefix
	if (! in6_pton(IPV6_DEF_PREFIX, -1, (u8 *)&(ip6p.addr), '\0', NULL)) {
        pr_warning("NAT64: IPv6 prefix in Headers is malformed [%s].", IPV6_DEF_PREFIX);
        return false;
    }
    if (IPV6_DEF_MASKBITS > IPV6_DEF_MASKBITS_MAX || IPV6_DEF_MASKBITS < IPV6_DEF_MASKBITS_MIN)
	{
		pr_warning("NAT64: Bad IPv6 network mask bits value in Headers: %d\n", IPV6_DEF_MASKBITS);
		return false;
	}
    ip6p.maskbits = IPV6_DEF_MASKBITS;

    // Allocate memory for IPv6 prefix
	cs.ipv6_net_prefixes = (struct ipv6_prefixes**) kmalloc(1*sizeof(struct ipv6_prefixes*), GFP_ATOMIC);
	cs.ipv6_net_prefixes[0] = (struct ipv6_prefixes*) kmalloc(sizeof(struct ipv6_prefixes), GFP_ATOMIC);
	// Store values in config struct
	(*cs.ipv6_net_prefixes[0]) = ip6p;
	cs.ipv6_net_prefixes_qty = 1;
  
	pr_debug("NAT64: Initial (default) configuration loaded:");
	pr_debug("NAT64:	using IPv4 pool subnet %pI4/%d (netmask %pI4),",
			  &(cs.ipv4_pool_net), cs.ipv4_pool_net_mask_bits, &ipv4_netmask);
	pr_debug("NAT64:	and IPv6 prefix %pI6c/%d.",
			  &(cs.ipv6_net_prefixes[0]->addr), cs.ipv6_net_prefixes[0]->maskbits);

	/* Translate the packet config. */
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
		pr_warning("Could not allocate memory to store the MTU plateaus.\n");
		return false;
	}
	memcpy(config.mtu_plateaus, &DEFAULT_MTU_PLATEAUS, sizeof(DEFAULT_MTU_PLATEAUS));

	/* Netlink sockets. */
	// Create netlink socket, register 'my_nl_rcv_msg' as callback function.
	struct netlink_kernel_cfg cfg = {
	        .input = &my_nl_rcv_msg,
	};
	my_nl_sock = netlink_kernel_create(&init_net, NETLINK_USERSOCK, &cfg);
	if (!my_nl_sock) {
		pr_warning("NAT64: %s: Creation of netlink socket failed.\n", __func__);
		return false;
	}
	pr_debug("NAT64: Netlink socket created.\n");

	return true; // Alles Klar!
}

void nat64_config_destroy(void)
{
	/* Netlink sockets. */
	if (my_nl_sock)
		netlink_kernel_release(my_nl_sock);
}

void write_message(char *msg, struct manconf_struct *mst, struct answer_struct **as, __u32 *as_len)
{
	*as_len = sizeof(struct answer_struct) + strlen(msg) + 1;
	*as = kmalloc(*as_len, GFP_ATOMIC);
	(*as)->mode = mst->mode;
	(*as)->operation = mst->operation;
	memcpy((*as) + 1, msg, strlen(msg) + 1);
}

int update_nat_config(struct manconf_struct *mst, struct answer_struct **as, __u32 *as_len)
{
	unsigned char i = 0;
	unsigned char qty = 0;
	struct bib_entry *bibs = NULL;
	struct session_entry *sessions = NULL;
	__u32 count = 0;
	struct ipv6_prefixes ip6p;
	bool res = true;

	switch(mst->mode){
		case 0:
			pr_debug("NAT64: Updating bib:");
	  		switch(mst->operation) {
				case 2:
					if(nat64_print_static_bib_table(&mst->us.rs,&count,&bibs)){
						__u32 payload_len = count * sizeof(struct bib_entry);

						*as_len = sizeof(struct answer_struct) + payload_len;
						*as = kmalloc(*as_len, GFP_ATOMIC);
						if (!(*as)) {
							return -1;
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
							write_message("Could not allocate the BIB array.", mst, as, as_len);
						(*as)->array_quantity = 0;
					}
				break;
				default:
						pr_debug("NAT64: Nothing was updated in bib: ");
						write_message("Parameter error.", mst, as, as_len);
			}
		break;
		case 1:
			pr_debug("NAT64: Updating session:");
			switch(mst->operation){
				case 0:
					pr_debug("NAT64: Adding session:");
					res = nat64_add_static_route(&mst->us.rs);
					if (res)
						write_message("Insertion was successful.", mst, as, as_len);
					else 
						write_message("Could NOT create a new Session entry.", mst, as, as_len);
				break;
				case 1:
					pr_debug("NAT64: Removing session:");
					res = nat64_delete_static_route(&mst->us.rs);
					if (res)
						write_message("Deletion was successful.", mst, as, as_len);
					else 
						write_message("Could NOT remove the Session entry.", mst, as, as_len);
				break;			
				case 2:
					pr_debug("NAT64: Display session:");
					if(nat64_print_static_session_table(&mst->us.rs,&count,&sessions)){
						__u32 payload_len = count * sizeof(struct session_entry);

						*as_len = sizeof(struct answer_struct) + payload_len;
						*as = kmalloc(*as_len, GFP_ATOMIC);
						if (!(*as)) {
							return -1;
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
							write_message("Could not allocate the Session array.", mst, as, as_len);
						(*as)->array_quantity = 0;
					}
				break;
				default:
					pr_debug("NAT64: Nothing was updated in session: ");
					write_message("Parameter error.", mst, as, as_len);
			}

		break;
		case 2:
			switch(mst->operation){
				case 0:
					pr_debug("NAT64: Updating ipv6 pool:");
					qty = (mst->us.cs).ipv6_net_prefixes_qty;
					cs.ipv6_net_prefixes_qty = qty;
					// Allocate memory for IPv6 prefix
					cs.ipv6_net_prefixes = (struct ipv6_prefixes**) kmalloc(qty*sizeof(struct ipv6_prefixes*), GFP_ATOMIC);
					if (!cs.ipv6_net_prefixes ) {
							pr_warning("Could not allocate memory to store the IPv6 Prefixes.\n");
							return -1;
					}

					for (i = 0; i < qty; i++) {
						cs.ipv6_net_prefixes[i] = (struct ipv6_prefixes*) kmalloc(sizeof(struct ipv6_prefixes), GFP_ATOMIC);
						ip6p.addr = mst->us.cs.ipv6_net_prefixes[i]->addr;
						ip6p.maskbits = mst->us.cs.ipv6_net_prefixes[i]->maskbits;
						(*cs.ipv6_net_prefixes[i]) = ip6p;
						pr_debug("NAT64:	and IPv6 prefix %pI6c/%d.",
			 				&mst->us.cs.ipv6_net_prefixes[i]->addr, mst->us.cs.ipv6_net_prefixes[i]->maskbits);
					}

					//llamar init pool6
					write_message("IPv6 pool was updated.", mst, as, as_len);
				break;	
				case 1:
				break;	
				case 2:
					{
					char buffer [65];
					pr_debug("IPv6 prefix: %pI6c/%d.", &(cs.ipv6_net_prefixes[0]->addr), cs.ipv6_net_prefixes[0]->maskbits);
					sprintf(buffer,"IPv6 prefix: %pI6c/%d.", &(cs.ipv6_net_prefixes[0]->addr), cs.ipv6_net_prefixes[0]->maskbits);
					write_message(buffer, mst, as, as_len);
					}
				break;
				default:
						pr_debug("NAT64: Nothing was updated in IPv6 pool: ");
						write_message("Parameter error.", mst, as, as_len);
			}
		break;
		case 3:
			switch(mst->operation){
				case 0:
					pr_debug("NAT64: Updating ipv4 pool:");
					cs.ipv4_pool_net = mst->us.cs.ipv4_pool_net;
					cs.ipv4_pool_net_mask_bits = mst->us.cs.ipv4_pool_net_mask_bits;
					cs.ipv4_pool_range_first = mst->us.cs.ipv4_pool_range_first;
					cs.ipv4_pool_range_last = mst->us.cs.ipv4_pool_range_last;
					pr_debug("NAT64:	using IPv4 pool subnet %pI4/%d",
						  &(mst->us.cs.ipv4_pool_net), mst->us.cs.ipv4_pool_net_mask_bits);
				  	//init_pools(&ms.us.cs); // Bernardo

					write_message("IPv4 pool was updated.", mst, as, as_len);
				break;
				case 1:
				break;	
				case 2:
					{
					char buffer [30];
					pr_debug("IPv4 pool: %pI4/%d.", &(cs.ipv4_pool_net), cs.ipv4_pool_net_mask_bits);
					sprintf(buffer,"IPv4 pool: %pI4/%d.", &(cs.ipv4_pool_net), cs.ipv4_pool_net_mask_bits);
					write_message(buffer, mst, as, as_len);
					}
				break;
				default:
						pr_debug("NAT64: Nothing was updated in IPv4 pool: ");
						write_message("Parameter error.", mst, as, as_len);
			}

			break;
		case 4:
			pr_debug("NAT64: Updating hair:");
			cs.hairpinning_mode = mst->us.cs.hairpinning_mode;
			write_message("Hairpinning handling was updated.", mst, as, as_len);
		break;
		case 5:
			pr_debug("NAT64: Updating translator options:");

 			if (mst->submode & PHR_MASK){
				config.packet_head_room = mst->us.cc.packet_head_room;
	 		}

 			if (mst->submode & PTR_MASK){
				config.packet_tail_room = mst->us.cc.packet_tail_room;
	 		}

			if (mst->submode & IPV6_NEXTHOP_MASK){
				config.ipv6_nexthop_mtu = mst->us.cc.ipv6_nexthop_mtu;
	 		}

			if (mst->submode & IPV4_NEXTHOP_MASK){
				config.ipv4_nexthop_mtu = mst->us.cc.ipv4_nexthop_mtu;
	 		}

			if (mst->submode & IPV4_TRAFFIC_MASK){
				config.ipv4_traffic_class = mst->us.cc.ipv4_traffic_class;
	 		}

			if (mst->submode & OIPV6_MASK){
				config.override_ipv6_traffic_class = mst->us.cc.override_ipv6_traffic_class;
	 		}

			if (mst->submode & OIPV4_MASK){
				config.override_ipv4_traffic_class = mst->us.cc.override_ipv4_traffic_class;
	 		}

			if (mst->submode & DF_ALWAYS_MASK){
				config.df_always_set = mst->us.cc.df_always_set;
	 		}

			if (mst->submode & GEN_IPV4_MASK){
				config.generate_ipv4_id = mst->us.cc.generate_ipv4_id;
	 		}

			if (mst->submode & IMP_MTU_FAIL_MASK){
				config.improve_mtu_failure_rate = mst->us.cc.improve_mtu_failure_rate;
	 		}

			if (mst->submode & MTU_PLATEAUS_MASK){
				config.mtu_plateau_count = mst->us.cc.mtu_plateau_count;

				config.mtu_plateaus = kmalloc(sizeof(mst->us.cc.mtu_plateaus), GFP_ATOMIC);
				if (!config.mtu_plateaus) {
					pr_warning("Could not allocate memory to store the MTU plateaus.\n");
					return -1;
				}
				memcpy(config.mtu_plateaus, &mst->us.cc.mtu_plateaus, sizeof(mst->us.cc.mtu_plateaus));
	 		}

			if (mst->submode & ADDRESS_DEPENDENT_FILTER_MASK){
				cs.address_dependent_filtering = mst->us.cs.address_dependent_filtering;
	 		}

			if (mst->submode & FILTER_INFO_MASK ){
				cs.filter_informational_icmpv6 = mst->us.cs.filter_informational_icmpv6;
	 		}

			if (mst->submode & DROP_TCP_MASK ){
				cs.drop_externally_initiated_tcp_connections = mst->us.cs.drop_externally_initiated_tcp_connections;
	 		}

			write_message("Translator options were updated.", mst, as, as_len);
		break;
		default:
			pr_debug("NAT64: nothing to update...:");
			write_message("Parameter error.", mst, as, as_len);

		}	

	return 0; // Alles Klar!
}
