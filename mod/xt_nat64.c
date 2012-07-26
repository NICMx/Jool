/*
 * NAT64 - Network Address Translator IPv6 to IPv4
 *
 * Authors:
 *	Representative NIC-Mx
 *	Ing. Gustavo Lozano <glozano@nic.mx>
 *	Ing. Jorge Cano
 *
 *	Representative ITESM
 *	Dr. Juan Arturo Nolazco	<jnolazco@itesm.mx>
 *	Ing. Martha Sordia <msordia@itesm.mx>
 *
 *	Students ITESM
 *	Juan Antonio Osorio <jaosorior@gmail.com>
 *	Luis Fernando Hinojosa <lf.hinojosa@gmail.com>
 *	David Valenzuela <david.valenzuela.88@gmail.com>
 *	Jose Vicente Ramirez <pepermz@gmail.com>
 *	Mario Gerardo Trevinho <mario_tc88@hotmail.com>
 *	Roberto Aceves <roberto.aceves@gmail.com>
 *	Miguel Alejandro González <maggonzz@gmail.com>
 *	Ramiro Nava <ramironava@gmail.com>
 *	Adrian González <bernardogzzf@gmail.com>
 *	Manuel Aude <dormam@gmail.com>
 *	Gabriel Chavez <gabrielchavez02@gmail.com>
 *	Alan Villela López <avillop@gmail.com>
 *	  
 *	  The rest of us, I propose include our names and order all alphabetically.
 *
 * Authors of the ip_data, checksum_adjust, checksum_remove, checksum_add
 * checksum_change, adjust_checksum_ipv6_to_ipv4, nat64_output_ipv4, 
 * adjust_checksum_ipv4_to_ipv6, nat64_xlate_ipv6_to_ipv4, nat64_alloc_skb,
 * nat64_xlate_ipv4_to_ipv6 functions that belong to the Ecdysis project:
 *	Jean-Philippe Dionne <jean-philippe.dionne@viagenie.ca>
 *	Simon Perreault <simon.perreault@viagenie.ca>
 *	Marc Blanchet <marc.blanchet@viagenie.ca>
 *
 *	Ecdysis <http://ecdysis.viagenie.ca/>
 *
 * The previous functions are found in the nf_nat64_main.c file of Ecdysis's 
 * NAT64 implementation.
 *
 * Please note: 
 * The function nat64_output_ipv4 was renamed as nat64_send_packet_ipv4 
 * under the kernel version that is inferior to 3.0 in this 
 * implementation. The function nat64_send_packet_ipv6 for both
 * kernel versions were based on this function.
 *
 * The functions nat64_xlate_ipv6_to_ipv4 and nat64_xlate_ipv4_to_ipv6 were
 * used as a point of reference to implement nat64_get_skb_from6to4 and
 * nat64_get_skb_from4to6, respectively. Furthermore, nat64_alloc_skb was
 * also used as a point of reference to implement nat64_get_skb.
 * 
 * Author of the nat64_extract_ipv4, nat64_allocate_hash, tcp_timeout_fsm,
 * tcp4_fsm, tcp6_fsm, bib_allocate_local4_port, bib_ipv6_lookup, bib_ipv4_lookup,
 * bib_create, bib_session_create, session_ipv4_lookup, session_renew,
 * session_create, clean_expired_sessions functions, nat64_ipv6_input:
 *	Julius Kriukas <julius.kriukas@gmail.com>
 * 
 * 	Linux NAT64 <http://ipv6.lt/nat64_en.php>
 *
 * The previous functions are found in the nat64_session.c and nat64_core.c
 * files of Julius Kriukas's Linux NAT64 implementation. Furthermore, these
 * functions used global variables which were added (with a comment indicating
 * their origin) in our xt_nat64.c file. The majority of these functions can 
 * be found in our nf_nat64_filtering_and_updating.h file. Not all of them are 
 * being used in this release version but are planned to be used in the future.
 * This is the case of the tcp4_fsm, tcp6_fsm, tcp_timeout_fsm and 
 * clean_expired_sessions functions and some of the global variables they use.
 * Part of our nat64_filtering_and_updating function was based on Julius's 
 * implementation of his nat64_ipv6_input function.
 *
 * NAT64 is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * NAT64 is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * You should have received a copy of the GNU General Public License
 * along with NAT64.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/netfilter/x_tables.h>
#include <linux/skbuff.h>
#include <linux/etherdevice.h>
#include <linux/inetdevice.h>

#include <linux/netdevice.h>
#include <net/route.h>
#include <net/ip6_route.h>

#include <net/ipv6.h>
#include <net/ip.h>
#include <net/icmp.h>
#include <net/tcp.h>
#include <linux/icmp.h>
#include <linux/udp.h>

#include <linux/timer.h>
#include <linux/types.h>
#include <linux/jhash.h>
#include <linux/rcupdate.h>

#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/nf_conntrack_l3proto.h>
#include <net/netfilter/nf_conntrack_l4proto.h>
#include <net/netfilter/ipv4/nf_conntrack_ipv4.h>
#include <net/netfilter/nf_nat.h>
#include <net/netfilter/nf_nat_core.h>
#include <net/netfilter/nf_nat_protocol.h>

#include <linux/version.h>
#include <linux/netlink.h> 	// Testing communication with the module using netlink. Rob
#include <net/sock.h>		// Rob.

#include "xt_nat64.h"
#include "nf_nat64_ipv4_pool.h"
#include "nf_nat64_tuple_handling.h"
#include "nf_nat64_determine_incoming_tuple.h"
#include "nf_nat64_translate_packet.h"
#include "xt_nat64_module_conf.h"
#include "nf_nat64_bib_session.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Juan Antonio Osorio <jaosorior@gmail.com>");
MODULE_DESCRIPTION("Xtables: RFC 6146 \"NAT64\" implementation");
MODULE_ALIAS("ipt_nat64");
MODULE_ALIAS("ip6t_nat64");


#define ICMP_MINLEN 8
#define ICMP_ROUTERADVERT       9   
#define ICMP_ROUTERSOLICIT      10 
#define ICMP_INFOTYPE(type) \
	((type) == ICMP_ECHOREPLY || (type) == ICMP_ECHO || \
	 (type) == ICMP_ROUTERADVERT || (type) == ICMP_ROUTERSOLICIT || \
	 (type) == ICMP_TIMESTAMP || (type) == ICMP_TIMESTAMPREPLY || \
	 (type) == ICMP_INFO_REQUEST || (type) == ICMP_INFO_REPLY || \
	 (type) == ICMP_ADDRESS || (type) == ICMP_ADDRESSREPLY)


#define MY_MACIG 'G'
#define READ_IOCTL _IOR(MY_MACIG, 0, int)
#define WRITE_IOCTL _IOW(MY_MACIG, 1, int)

#define IPV6_HDRLEN 40
#ifndef KERNEL_VERSION
#define KERNEL_VERSION(a,b,c) ((a)*65536+(b)*256+(c))
#endif

/*
 * FIXME: Ensure all variables are 32 and 64-bits complaint. 
 * That is, no generic data types akin to integer.
 * FIXME: Rob. Change all 'printk' function calls by 'pr_debug' function
 * 
 */

/*
 * BEGIN: Global variables inherited from Julius Kriukas's 
 * 		  Linux NAT64 implementation.
 */


/* IPv4 */
//~ __be32 ipv4_addr;	// FIXME: Rob thinks this should be of 'u8 *' type,
					// as expected by in4_pton function. But think of 
					// changing it to 'in_addr' type. // Get rid of this
struct in_addr ipv4_pool_net; // This is meant to substitute variable 'ipv4_addr'
struct in_addr ipv4_pool_range_first;
struct in_addr ipv4_pool_range_last;
//~ char *ipv4_addr_str;	// Var type verified  . Rob // Get rid of this
int ipv4_mask_bits;		// Var type verified  ;). Rob
__be32 ipv4_netmask;	// Var type verified ;), but think of changing it
						// 	to 'in_addr' type. Rob.

/* IPv6 */
char *ipv6_pref_addr_str;
int ipv6_pref_len;	// Var type verified ;). Rob

/*
 * END: Global variables inherited from Julius Kriukas's 
 * 		Linux NAT64 implementation.
 */


/* Testing communication with the module using netlink. Rob
 * Example from: http://stackoverflow.com/questions/862964/who-can-give-me-the-latest-netlink-programming-samples
 */
// BEGIN
#include <net/sock.h>
#include <net/netlink.h>
#include "xt_nat64_module_conf.h"

//~ #define IPV4_POOL_MASK	0xffffff00	// FIXME: Think of use '/24' format instead.

//~ struct config_struct *cs;
struct config_struct cs;
struct sock *my_nl_sock;

DEFINE_MUTEX(my_mutex);

/*
 * Default configuration, until it's set up by the user space application.
 * */
int init_nat_config(struct config_struct *cs)
{
	/* IPv4 */
	// IPv4 Pool Network
    if (! in4_pton(IPV4_DEF_NET, -1, (u8 *)&ipv4_pool_net.s_addr, '\x0', NULL)) {
        pr_warning("NAT64: IPv4 pool net in Headers is malformed [%s].", IPV4_DEF_NET);
        return -EINVAL;
    }
	// IPv4 Pool - Netmask
	ipv4_mask_bits = IPV4_DEF_MASKBITS;	// Num. of bits 'on' in the net mask
    if (ipv4_mask_bits > 32 || ipv4_mask_bits < 1) {
        pr_warning("NAT64: IPv4 Pool netmask bits value is invalid [%d].", 
                IPV4_DEF_MASKBITS);
        return -EINVAL;
    }
	ipv4_netmask = inet_make_mask(ipv4_mask_bits);
	ipv4_pool_net.s_addr = ipv4_pool_net.s_addr & ipv4_netmask; // For the sake of correctness

	// IPv4 Pool - First and Last addresses .
	if (! in4_pton(IPV4_DEF_POOL_FIRST, -1, (u8 *)&ipv4_pool_range_first.s_addr, '\x0', NULL)) {
        pr_warning("NAT64: IPv4 pool net in Headers is malformed [%s].", IPV4_DEF_POOL_FIRST);
        return -EINVAL;
    }
    if (! in4_pton(IPV4_DEF_POOL_LAST, -1, (u8 *)&ipv4_pool_range_last.s_addr, '\x0', NULL)) {
        pr_warning("NAT64: IPv4 pool net in Headers is malformed [%s].", IPV4_DEF_POOL_LAST);
        return -EINVAL;
    }
    
	/* IPv6 */
	ipv6_pref_addr_str = (char *)kmalloc(sizeof(char) * strlen(IPV6_DEF_PREFIX) + 1, GFP_USER);
    strcpy(ipv6_pref_addr_str, IPV6_DEF_PREFIX);	// Default IPv6	(string)
    ipv6_pref_len = IPV6_DEF_MASKBITS; // Default IPv6 Prefix	(int)

	/* Initialize config struct for function 'init_pools' */
	//~ cs = (struct config_struct *)kmalloc(sizeof(struct config_struct),GFP_USER);

	//// IPv4:
    (*cs).ipv4_addr_net = ipv4_pool_net; 
	(*cs).ipv4_addr_net_mask_bits = ipv4_mask_bits; 
	(*cs).ipv4_pool_range_first = ipv4_pool_range_first;
	(*cs).ipv4_pool_range_last = ipv4_pool_range_last;
    //
    (*cs).ipv4_tcp_port_first = IPV4_DEF_TCP_POOL_FIRST;
    (*cs).ipv4_tcp_port_last = IPV4_DEF_TCP_POOL_LAST;
    //
    (*cs).ipv4_udp_port_first = IPV4_DEF_UDP_POOL_FIRST;
    (*cs).ipv4_udp_port_last = IPV4_DEF_UDP_POOL_LAST;
    
    //// IPv6:
	if (! in6_pton(IPV6_DEF_PREFIX, -1, (u8 *)&((*cs).ipv6_net_prefix), '\0', NULL)) {
        pr_warning("NAT64: IPv6 prefix in Headers is malformed [%s].", IPV6_DEF_PREFIX);
        return -EINVAL;
    }
	(*cs).ipv6_net_mask_bits = IPV6_DEF_MASKBITS;
    //
	(*cs).ipv6_tcp_port_range_first = IPV6_DEF_TCP_POOL_FIRST;
	(*cs).ipv6_tcp_port_range_last = IPV6_DEF_TCP_POOL_LAST;
	//
	(*cs).ipv6_udp_port_range_first = IPV6_DEF_UDP_POOL_FIRST;
    (*cs).ipv6_udp_port_range_last = IPV6_DEF_UDP_POOL_LAST;   


	pr_debug("NAT64: Initial (default) configuration loaded:");
	pr_debug("NAT64:	using IPv4 pool subnet %pI4/%d (netmask %pI4),", 
			  &((*cs).ipv4_addr_net), (*cs).ipv4_addr_net_mask_bits, &ipv4_netmask);
	pr_debug("NAT64:	and IPv6 prefix %pI6c/%d.", 
			  &((*cs).ipv6_net_prefix), (*cs).ipv6_net_mask_bits);

	return 0; // Alles Klar!	
}

/*
 * Update nat64 configuration with data received from the 'load_config'
 * userspace app. It's assumed that this data were validated before
 * being sent. 
 */
int update_nat_config(struct config_struct *cst)
{
	/* IPv4 */	
	// IPv4 Pool Network
	//~ ipv4_addr = (*cst).ipv4_addr_net.s_addr;

	ipv4_pool_net = (*cst).ipv4_addr_net;
	// IPv4 Pool - Netmask
	ipv4_mask_bits = (*cst).ipv4_addr_net_mask_bits;
	ipv4_netmask = inet_make_mask( (*cst).ipv4_addr_net_mask_bits );
	//~ ipv4_addr = ipv4_addr & ipv4_netmask; // For the sake of correctness // Rob. Get rid of this variable
	ipv4_pool_net.s_addr = ipv4_pool_net.s_addr & ipv4_netmask; // For the sake of correctness


	// IPv4 Pool - First and Last addresses .
	ipv4_pool_range_first = (*cst).ipv4_pool_range_first;
	ipv4_pool_range_last = (*cst).ipv4_pool_range_last;

	// TODO:
	//~ /* IPv6 */
	//~ ipv6_pref_addr_str;
	//~ ipv6_pref_len;


	cs = (*cst);

	pr_debug("NAT64: Updating configuration:");
	pr_debug("NAT64:	using IPv4 pool subnet %pI4/%d (netmask %pI4),", 
			  &(cs.ipv4_addr_net), (cs).ipv4_addr_net_mask_bits, &ipv4_netmask);
	pr_debug("NAT64:	and IPv6 prefix %pI6c/%d.", 
			  &(cs.ipv6_net_prefix), cs.ipv6_net_mask_bits);



	// Update IPv4 addresses pool
    init_pools(&cs); // Bernardo
	
	// :)
	return 0; // Alles Klar!	
}


int my_rcv_msg(struct sk_buff *skb, struct nlmsghdr *nlh)
{
    int type;
     struct config_struct *cst;

    type = nlh->nlmsg_type;
    if (type != MY_MSG_TYPE) {
        pr_debug("NAT64:     netlink: %s: expect %#x got %#x\n", 
        		 __func__, MY_MSG_TYPE, type);
        return -EINVAL;
    }

	cst = NLMSG_DATA(nlh);
    pr_debug("NAT64:     netlink: got message.\n" );
    pr_debug("NAT64:     netlink: updating NAT64 configuration.\n" );

	if (update_nat_config(cst) != 0)
	{
		pr_debug("NAT64:     netlink: Error while updating NAT64 running configuration\n");
		return -EINVAL;
	}
	
	pr_debug("NAT64:     netlink: Running configuration successfully updated");

    return 0;
}

void my_nl_rcv_msg(struct sk_buff *skb)
{
    mutex_lock(&my_mutex);
    netlink_rcv_skb(skb, &my_rcv_msg);
    mutex_unlock(&my_mutex);
}

// END





DEFINE_SPINLOCK(nf_nat64_lock);

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,0,0)
int nat64_send_packet_ipv4(struct sk_buff *skb) 
{
	// Begin Ecdysis (nat64_output_ipv4)
	struct iphdr *iph = ip_hdr(skb);
	struct flowi fl;
	struct rtable *rt;
	skb->protocol = htons(ETH_P_IP);
	memset(&fl, 0, sizeof(fl));
	fl.fl4_dst = iph->daddr;
	fl.fl4_tos = RT_TOS(iph->tos);
	fl.proto = skb->protocol;
	if (ip_route_output_key(&init_net, &rt, &fl)) {
		pr_warning("nf_NAT64: ip_route_output_key failed");
		return -EINVAL;
	}
	if (!rt) {
		pr_warning("nf_NAT64: rt null");
		return -EINVAL;
	}
	skb->dev = rt->dst.dev;
	skb_dst_set(skb, (struct dst_entry *)rt);

	if (ip_local_out(skb)) {
		pr_warning("nf_NAT64: ip_local_out failed");
		return -EINVAL;
	}

	return 0;
	// End Ecdysis (nat64_output_ipv4)
}

int nat64_send_packet_ipv6(struct sk_buff *skb) 
{
	// Function based on Ecdysis's nat64_output_ipv4
	struct ipv6hdr *iph = ipv6_hdr(skb);
	struct flowi fl;
	struct dst_entry *dst;

	skb->protocol = htons(ETH_P_IPV6);

	memset(&fl, 0, sizeof(fl));
	
	if(!&(fl.fl6_src)) {
		return -EINVAL;
	}
	fl.fl6_src = iph->saddr;
	fl.fl6_dst = iph->daddr;
	fl.fl6_flowlabel = 0;
	fl.proto = skb->protocol;

	dst = ip6_route_output(&init_net, NULL, &fl);

	if (!dst) {
		pr_warning("error: ip6_route_output failed");
		return -EINVAL;
	}

	skb->dev = dst->dev;

	skb_dst_set(skb, dst);

	if(ip6_local_out(skb)) {
		pr_warning("nf_NAT64: ip6_local_out failed.");
		return -EINVAL;
	}

	return 0;	
}
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3,0,0)
int nat64_send_packet_ipv4(struct sk_buff *skb) 
{
	struct iphdr *iph = ip_hdr(skb);
	struct flowi fl;
	struct rtable *rt;

	skb->protocol = htons(ETH_P_IP);

	memset(&fl, 0, sizeof(fl));

	fl.u.ip4.daddr = iph->daddr;
	fl.flowi_tos = RT_TOS(iph->tos);
	fl.flowi_proto = skb->protocol;

	rt = ip_route_output_key(&init_net, &fl.u.ip4);

	if (!rt || IS_ERR(rt)) {
		pr_warning("NAT64: nat64_send_packet - rt is null or an error");
		if (IS_ERR(rt))
			pr_warning("rt -1");
		return -1;
	}

	skb->dev = rt->dst.dev;
	skb_dst_set(skb, (struct dst_entry *)rt);

	if (ip_local_out(skb)) {
		pr_warning("nf_NAT64: ip_local_out failed");
		return -EINVAL;
	}
	return 0;	
}

int nat64_send_packet_ipv6(struct sk_buff *skb) 
{
	// Function based on Ecdysis's nat64_output_ipv4
	struct ipv6hdr *iph = ipv6_hdr(skb);
	struct flowi fl;
	struct dst_entry *dst;
	//union nat64_l4header_t {
	//	struct udphdr * uh;
	//	struct tcphdr * th;
	//	struct icmp6hdr * icmph;
	//} l4header;
	//int i = 0;

	skb->protocol = htons(ETH_P_IPV6);

	memset(&fl, 0, sizeof(fl));
	
	fl.u.ip6.saddr = iph->saddr;
	fl.u.ip6.daddr = iph->daddr;
	fl.u.ip6.flowlabel = 0;
	fl.flowi_proto= skb->protocol;

	dst = ip6_route_output(&init_net, NULL, &fl.u.ip6);

	if (!dst) {
		pr_warning("error: ip6_route_output failed.");
		return -EINVAL;
	}

	skb->dev = dst->dev;

	skb_dst_set(skb, dst);

	/*
	 * Makes sure the net_device can actually send packets.
	 */
	netif_start_queue(skb->dev);

	if(ip6_local_out(skb)) {
		pr_warning("nf_NAT64: ip6_local_out failed");
		return -EINVAL;
	}

	return 0;
}
#endif


/*
 * Sends the packet. Checks the old skb' L3 type to select the course of action.
 * Right now, the skb->data should be pointing to the L3 layer header.
 */
int nat64_send_packet(struct sk_buff * old_skb, struct sk_buff *skb, bool hairpin)
{
	int ret = -1;
	
	spin_lock_bh(&nf_nat64_lock);
	pr_debug("NAT64: Sending the new packet...");
		
	switch (ntohs(old_skb->protocol)) {
		case ETH_P_IPV6:
			if (hairpin) {
				pr_debug("NAT64: eth type ipv6 to ipv6");
				//skb->protocol = ETH_P_IPV6;
				ret = nat64_send_packet_ipv6(skb);
			} else {
				pr_debug("NAT64: eth type ipv6 to ipv4");
				//skb->protocol = ETH_P_IP;
				ret = nat64_send_packet_ipv4(skb);
			}
			break;
		case ETH_P_IP:
			pr_debug("NAT64: eth type ipv4 to ipv6");
			//skb->protocol = ETH_P_IPV6;
			ret = nat64_send_packet_ipv6(skb);
			break;
		default:
			kfree_skb(skb);
			pr_debug("NAT64: before unlocking spinlock..."
					" No known eth type.");
			spin_unlock_bh(&nf_nat64_lock);
			return -1;
	}

	if (ret)
		pr_debug("NAT64: an error occured while sending the packet");

	pr_debug("NAT64: dev_queue_xmit return code: %d", ret);

	pr_debug("NAT64: before unlocking spinlock...");
	spin_unlock_bh(&nf_nat64_lock);

	return ret;
}

/*
 * IPv6 comparison function. It's used as a call from nat64_tg6 to compare
 * the incoming packet's IP with the rule's IP; therefore, when the module is 
 * in debugging mode it prints the rule's IP.
 */
bool nat64_tg6_cmp(const struct in6_addr * ip_a, 
		const struct in6_addr * ip_b, const struct in6_addr * ip_mask, 
		__u8 flags)
{

	if (flags & XT_NAT64_IPV6_DST) {
		if (ipv6_masked_addr_cmp(ip_a, ip_mask, ip_b) == 0) {
			pr_debug("NAT64: IPv6 comparison returned true\n");
			return true;
		}
	}

	pr_debug("NAT64: IPv6 comparison returned false: %d\n",
			ipv6_masked_addr_cmp(ip_a, ip_mask, ip_b));
	return false;
}

/*
 * NAT64 Core Functionality
 *
 */
unsigned int nat64_core(struct sk_buff *skb, 
        const struct xt_action_param *par, u_int8_t l3protocol,
        u_int8_t l4protocol) {

    struct nf_conntrack_tuple inner;
    struct nf_conntrack_tuple * outgoing;
    struct sk_buff * new_skb;
    bool hairpin = false;

    if (!nat64_determine_incoming_tuple(l3protocol, l4protocol, skb, &inner)) {
        pr_info("NAT64: There was an error determining the Tuple");
        return NF_DROP;
    } 

    if (!nat64_filtering_and_updating(l3protocol, l4protocol, skb, &inner)) {
		pr_info("NAT64: There was an error in the updating and"
			" filtering module");
		return NF_DROP;
    }

    outgoing = nat64_determine_outgoing_tuple(l3protocol, l4protocol, 
        skb, &inner, outgoing);

    if (!outgoing) {
    	pr_info("NAT64: There was an error in the determining the outgoing"
                " tuple module");
        return NF_DROP;
    }		

    if (  nat64_got_hairpin(l3protocol, outgoing) ){
		pr_debug("NAT64: hairpin packet yo!");
		outgoing = nat64_hairpinning_and_handling(l4protocol, &inner, outgoing);
		l3protocol = NFPROTO_IPV6;
		hairpin = true;
    }

    new_skb = nat64_translate_packet(l3protocol, l4protocol, skb, outgoing, hairpin);

    if (!new_skb) {
        pr_info("NAT64: There was an error in the packet translation"
                " module");
        return NF_DROP;
    }

    //FIXME: The same value 'NF_DROP' is returned for both ERROR and CORRECT conditions.
    /*
     * Returns zero if it works
     */
    if (nat64_send_packet(skb, new_skb, hairpin)) {
        pr_info("NAT64: There was an error in the packet transmission"
                " module");
        return NF_DROP;
    }
	

    /* TODO: Incluir llamada a HAIRPINNING aqui */

    return NF_DROP;
}

/*
 * IPv4 entry function
 *
 */
unsigned int nat64_tg4(struct sk_buff *skb, 
        const struct xt_action_param *par)
{
    const struct xt_nat64_tginfo *info = par->targinfo;
    struct iphdr *iph = ip_hdr(skb);
    __u8 l4_protocol = iph->protocol;
    /*
       switch(l4_protocol) {
       case IPPROTO_TCP: return NF_ACCEPT;
       case IPPROTO_ICMP: return NF_ACCEPT;
       case IPPROTO_ICMPV6: return NF_ACCEPT;
       }
       */
    pr_debug("\n* INCOMING IPV4 PACKET *\n");
    pr_debug("PKT SRC=%pI4 \n", &iph->saddr);
    pr_debug("PKT DST=%pI4 \n", &iph->daddr);
    pr_debug("RULE DST=%pI4 \n", &info->ipdst.in);
    pr_debug("RULE DST_MSK=%pI4 \n", &info->ipdst_mask);

    //ip_masked_addr_cmp(ip_a, ip_mask, ip_b)
	
	
	// Do NOT process the packet if it is destined to an address not in
	// the pool network. Rob.
	//~ if(skb->len < sizeof(struct iphdr) || iph->version != 4 || (iph->daddr & ipv4_netmask) != ipv4_addr)
	if(skb->len < sizeof(struct iphdr) || iph->version != 4
	   || (iph->daddr & ipv4_netmask) != ipv4_pool_net.s_addr)
			return NF_ACCEPT;

    if (l4_protocol & NAT64_IP_ALLWD_PROTOS) {
        /*
         * Core functions of the NAT64 implementation.
         */
        return nat64_core(skb, par, NFPROTO_IPV4, l4_protocol);
    }

    /*
     * If the packet is not in the allowed protocol list, it should be 
     * returned to the stack.
     */
    return NF_ACCEPT;
}

/*
 * IPv6 entry function
 *
 */
unsigned int nat64_tg6(struct sk_buff *skb, 
        const struct xt_action_param *par)
{
    const struct xt_nat64_tginfo *info = par->targinfo;
    struct ipv6hdr *iph = ipv6_hdr(skb);
    __u8 l4_protocol = iph->nexthdr;
    /*
       switch(l4_protocol) {
       case IPPROTO_TCP: return NF_ACCEPT;
       case IPPROTO_ICMP: return NF_ACCEPT;
       case IPPROTO_ICMPV6: return NF_ACCEPT;
       }
       */
    pr_debug("\n* INCOMING IPV6 PACKET *\n");
    pr_debug("PKT SRC=%pI6c \n", &iph->saddr);
    pr_debug("PKT DST=%pI6c \n", &iph->daddr);
    pr_debug("RULE DST=%pI6c \n", &info->ip6dst.in6);
    pr_debug("RULE DST_MSK=%pI6c \n", &info->ip6dst_mask);

    /*
     * If the packet is not directed towards the NAT64 prefix, 
     * continue through the Netfilter rules.
     */
    if (!nat64_tg6_cmp(&info->ip6dst.in6, &info->ip6dst_mask.in6, 
                &iph->daddr, info->flags))
        return NF_ACCEPT;

    if (l4_protocol & NAT64_IPV6_ALLWD_PROTOS) {
        /*
         * Core functions of the NAT64 implementation.
         */
        return nat64_core(skb, par, NFPROTO_IPV6, l4_protocol);
    }

    /*
     * If the packet's protocol is not one of the ones defined for NAT64,
     * accept it.
     */
    return NF_ACCEPT;
}

/*
 * General entry point. 
 *
 * Here the NAT64 implementation validates that the
 * incoming packet is IPv4 or IPv6. If it isn't, it silently drops the packet.
 * If it's one of those two, it calls it's respective function, since the IPv6
 * header is handled differently than an IPv4 header.
 */
unsigned int nat64_tg(struct sk_buff *skb, 
        const struct xt_action_param *par)
{
    if (par->family == NFPROTO_IPV4)
        return nat64_tg4(skb, par);
    else if (par->family == NFPROTO_IPV6)
        return nat64_tg6(skb, par);
    else
        return NF_ACCEPT;
}

int nat64_tg_check(const struct xt_tgchk_param *par)
{
    int ret;

    ret = nf_ct_l3proto_try_module_get(par->family);
    if (ret < 0)
        pr_info("cannot load support for proto=%u\n",
                par->family);
    return ret;
}

struct xt_target nat64_tg_reg __read_mostly = {
    .name = "nat64",
    .revision = 0,
    .target = nat64_tg,
    .checkentry = nat64_tg_check,
    .family = NFPROTO_UNSPEC,
    .table = "mangle",
    .hooks = (1 << NF_INET_PRE_ROUTING),
    .targetsize = sizeof(struct xt_nat64_tginfo),
    .me = THIS_MODULE,
};

int __init nat64_init(void)
{
	pr_debug("\n\n\n%s", banner);
    pr_debug("\n\nNAT64 module inserted!");

	// Load default configuration
	init_nat_config(&cs);

    /*
     * Include nf_conntrack dependency
     */
    need_conntrack();

    /*
     * Include nf_conntrack_ipv4 dependency.
     * IPv4 conntrack is needed in order to handle complete packets, and not
     * fragments.
     */
    need_ipv4_conntrack();
    nat64_determine_incoming_tuple_init();

    // BEGIN: code imported from nat64_init of Julius Kriukas' implementation

    // Init IPv4 addresses pool
    init_pools(&cs); // Bernardo

    nat64_create_bib_session_memory();
    pr_debug("NAT64: The bib table slab cache was succesfully created.");
    // END: code imported from nat64_init of Julius Kriukas' implementation

    // Load netlink sockets. Rob
    // BEGIN
    // Create netlink socket, register 'my_nl_rcv_msg' as callback function. // Rob
    my_nl_sock = netlink_kernel_create(&init_net, NETLINK_USERSOCK, 0,
            my_nl_rcv_msg, NULL, THIS_MODULE);
    if (!my_nl_sock) 
    {
        pr_warning("NAT64: %s: Creation of netlink socket failed.\n", __func__);
        goto error;
    } 
    // END

    return xt_register_target(&nat64_tg_reg);

    // The following goto were inspired by Julius Kriukas' nat64_init's goto
error:
    return -EINVAL;

}

void __exit nat64_exit(void)
{
    nat64_determine_incoming_tuple_destroy();
    nat64_destroy_bib_session_memory();
    xt_unregister_target(&nat64_tg_reg);

    if (my_nl_sock) netlink_kernel_release(my_nl_sock); // Unload netlink sockets. Rob
    kfree(ipv6_pref_addr_str);
	//~ kfree(cs);

    pr_debug("NAT64 module removed!\n\n\n");
}

module_init(nat64_init);
module_exit(nat64_exit);
