/*
 * NAT64 - Network Address Translator IPv6 to IPv4
 *
 * Authors:
 *    Juan Antonio Osorio <jaosorior@gmail.com>
 *    Luis Fernando Hinojosa <lf.hinojosa@gmail.com>
 *    David Valenzuela <david.valenzuela.88@gmail.com>
 *    Jose Vicente Ramirez <pepermz@gmail.com>
 *    Mario Gerardo Trevino <mario_tc88@hotmail.com>
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
#define MY_MSG_TYPE (0x10 + 2)  // + 2 is arbitrary. same value for kern/usr . Rob


#include <linux/fs.h>
#include <asm/uaccess.h>

#include "nf_nat64_bib.h"
#include "xt_nat64.h"
#include "nf_nat64_generic_functions.h"
#include "nf_nat64_auxiliary_functions.h"
#include "nf_nat64_filtering_and_updating.h"
#include "nf_nat64_ipv4_pool.h"

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

static int major; 
static char msg[200];

/*
 * FIXME: Ensure all variables are 32 and 64-bits complaint. 
 * That is, no generic data types akin to integer.
 * FIXED: All the output messages of the stages are in the opposite
 * order of execution
 * in the logs.
 */
// FIXME: Rob. Change all 'printk' function calls by 'pr_debug' function
//
//



static struct nf_conntrack_l3proto * l3proto_ip __read_mostly;
static struct nf_conntrack_l3proto * l3proto_ipv6 __read_mostly;

/*
 * BEGIN: Global variables inherited from Julius Kriukas's 
 * 		  Linux NAT64 implementation.
 */

struct kmem_cache *st_cache;
struct kmem_cache *bib_cache;
struct kmem_cache *st_cacheTCP;
struct kmem_cache *bib_cacheTCP;
struct hlist_head *hash6;
struct hlist_head *hash4;
unsigned int hash_size;
struct expiry_q	expiry_base[NUM_EXPIRY_QUEUES] =
{
	{{NULL, NULL}, 5*60},// FIXME: Use definitions in nat64_filtering_n_updating.h 
	{{NULL, NULL}, 4*60},//		   instead of hardcoded values. Rob.		  
	{{NULL, NULL}, 2*60*60},
	{{NULL, NULL}, 6},
	{{NULL, NULL}, 60}
};
struct list_head expiry_queue = LIST_HEAD_INIT(expiry_queue);

/* IPv4 */
__be32 ipv4_addr;	// FIXME: Rob thinks this should be of 'u8 *' type, as expected by in4_pton function.
static char *ipv4_addr_str;	// Var type verified  . Rob
int ipv4_mask_bits;		// Var type verified  ;). Rob
__be32 ipv4_netmask;	// Var type verified  ;). Rob
/* IPv6 */
//struct in6_addr	ipv6_prefix_base = {.s6_addr32[0] = 0, .s6_addr32[1] = 0, 
//						.s6_addr32[2] = 0, .s6_addr32[3] = 0};
static char *ipv6_pref_addr_str;
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
#include "xt_nat64_module_comm.h"

#define MY_MSG_TYPE (0x10 + 2)  // + 2 is arbitrary. same value for kern/usr
/* Definition of default values for the IPv4 & IPv6 pools. */
// 	IPv4
#define IPV4_POOL_FIRST	"192.168.2.1"
#define IPV4_POOL_LAST	"192.168.2.254"
#define IPV4_POOL_MASK	0xffffff00	// FIXME: Think of use '/24' format instead.
#define IPV4_POOL_MASKBITS	24
//	IPv6
#define IPV6_PREF_DEF	"64:ff9b::/96" // FIXME: Must be changed by prefix: 64:ff9b::/96   //Rob.
#define IPV6_PREF_NET	"64:ff9b::"	// Default IPv6	(string)
#define IPV6_PREF_MASKBITS	96 		// Default IPv6 Prefix	(int)

    
static struct sock *my_nl_sock;

DEFINE_MUTEX(my_mutex);

static int update_nat_config(const struct nat64_run_conf *nrc)
{
	int ret = 0;
	char err = 0x00;

	/* Validation: */
	// IPv4 Pool - First address.
	ret = in4_pton(nrc->ipv4_addr_str, -1, (u8 *)&ipv4_addr, '\x0', NULL);
	if (!ret) 
	{	err = 1;	// Error
		pr_warning("NAT64: Updating config: ipv4 is malformed: %s", 
					nrc->ipv4_addr_str);
	}
	// IPv4 Pool - Netmask 
	if ((*nrc).ipv4_mask_bits > 32 || (*nrc).ipv4_mask_bits < 1) 
	{	err = 1; 	// Error
		pr_warning("NAT64: Updating config: ipv4 prefix is malformed: %d", 
					(*nrc).ipv4_mask_bits);
	}
	// ...
	// :(
	if (err) return -EINVAL; // Error
	
	/* Alteration: */
	// IPv4 Pool - First address.
	ipv4_netmask = inet_make_mask((*nrc).ipv4_mask_bits);
	pr_debug("NAT64: Updating config: using IPv4 subnet %pI4/%d (netmask %pI4).", 
			  &ipv4_addr, (*nrc).ipv4_mask_bits, &ipv4_netmask);
	// IPv4 Pool - Netmask
	// ...
	// :)
	return 0; // Alles Klar!	
}


static int my_rcv_msg(struct sk_buff *skb, struct nlmsghdr *nlh)
{
    int type;
    //char *data;
    //struct in_addr *ipaddr;
    //char buf[INET_ADDRSTRLEN];
    struct nat64_run_conf *nrc;

    type = nlh->nlmsg_type;
    if (type != MY_MSG_TYPE) {
        pr_debug("NAT64:     netlink: %s: expect %#x got %#x\n", 
        		 __func__, MY_MSG_TYPE, type);
        return -EINVAL;
    }

    // data = NLMSG_DATA(nlh);
    // pr_debug("NAT64: netlink: got message: %s\n", data);

	//ipaddr = NLMSG_DATA(nlh);
//	inet_ntop(AF_INET, &(ipaddr.s_addr), buf, INET_ADDRSTRLEN);
    //pr_debug("NAT64: netlink: got message: %pI4\n", ipaddr );

	nrc = NLMSG_DATA(nlh);
//    pr_debug("NAT64:     netlink: got message: IPv4 addr=%s, mask bits=%d\n", 
//    		 (*nrc).ipv4_addr_str, (*nrc).ipv4_mask_bits );
    pr_debug("NAT64:     netlink: got message.\n" );
    pr_debug("NAT64:     netlink: updating NAT64 configuration.\n" );
	if (update_nat_config(nrc) != 0)
	{
		pr_debug("NAT64:     netlink: Error while updating NAT64 running configuration\n");
		return -EINVAL;
	}
	
	pr_debug("NAT64:     netlink: Running configuration successfully updated");

    return 0;
}

static void my_nl_rcv_msg(struct sk_buff *skb)
{
    mutex_lock(&my_mutex);
    netlink_rcv_skb(skb, &my_rcv_msg);
    mutex_unlock(&my_mutex);
}

// END





static DEFINE_SPINLOCK(nf_nat64_lock);

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,0,0)
static int nat64_send_packet_ipv4(struct sk_buff *skb) 
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

static int nat64_send_packet_ipv6(struct sk_buff *skb) 
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
static int nat64_send_packet_ipv4(struct sk_buff *skb) 
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
			pr_warning("rt - %d", (int)rt);
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

static int nat64_send_packet_ipv6(struct sk_buff *skb) 
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
static int nat64_send_packet(struct sk_buff * old_skb, struct sk_buff *skb)
{
	int ret = -1;
	
	spin_lock_bh(&nf_nat64_lock);
	pr_debug("NAT64: Sending the new packet...");
		
	switch (ntohs(old_skb->protocol)) {
		case ETH_P_IPV6:
			pr_debug("NAT64: eth type ipv6 to ipv4");
			skb->protocol = ETH_P_IP;
			ret = nat64_send_packet_ipv4(skb);
			break;
		case ETH_P_IP:
			pr_debug("NAT64: eth type ipv4 to ipv6");
			skb->protocol = ETH_P_IPV6;
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
 * Julius Kriukas's code. Extracts an ipv4 from an ipv6 addr based on the prefix.
 * A modification was made in case 32.
 */
static __be32 nat64_extract_ipv4(struct in6_addr addr, int prefix)
{
	switch(prefix) {
		case 32:
			return addr.s6_addr32[3];
		case 40:
			return 0;	//FIXME
		case 48:
			return 0;	//FIXME
		case 56:
			return 0;	//FIXME
		case 64:
			return 0;	//FIXME
		case 96:
			//return addr.s6_addr32[1];
			return addr.s6_addr32[3];
		default:
			return 0;
	}
}

/*
 * Julius Kriukas's code. Allocates the hash6 and hash4 global variables.
 */
static int nat64_allocate_hash(unsigned int size)
{
	int i;

	size = roundup(size, PAGE_SIZE / sizeof(struct hlist_head));
	hash_size = size;

	hash4 = (void *)__get_free_pages(GFP_KERNEL|__GFP_NOWARN,
			get_order(sizeof(struct hlist_head) * size));

	if (!hash4) {
		pr_warning("NAT64: Unable to allocate memory for hash4 via GFP.");
		return -1;
	}

	hash6 = (void *)__get_free_pages(GFP_KERNEL|__GFP_NOWARN,
			get_order(sizeof(struct hlist_head) * size));
	if (!hash6) {
		pr_warning("NAT64: Unable to allocate memory for hash6 via gfp X(.");
		free_pages((unsigned long)hash4,
				get_order(sizeof(struct hlist_head) * hash_size));
		return -1;
	}

	for (i = 0; i < size; i++)
	{
		INIT_HLIST_HEAD(&hash4[i]);
		INIT_HLIST_HEAD(&hash6[i]);
	}

	for (i = 0; i < NUM_EXPIRY_QUEUES; i++)
		INIT_LIST_HEAD(&expiry_base[i].queue);

	return 0;
}

/*
 * Function that gets the pointer directed to it's 
 * nf_conntrack_l3proto structure.
 */
static int nat64_get_l3struct(u_int8_t l3protocol, 
		struct nf_conntrack_l3proto ** l3proto)
{
	switch (l3protocol) {
		case NFPROTO_IPV4:
			*l3proto = l3proto_ip;
			return true;
		case NFPROTO_IPV6:
			*l3proto = l3proto_ipv6;
			return true;
		default:
			return false;
	}
}

/*
 * IPv6 comparison function. It's used as a call from nat64_tg6 to compare
 * the incoming packet's IP with the rule's IP; therefore, when the module is 
 * in debugging mode it prints the rule's IP.
 */
static bool nat64_tg6_cmp(const struct in6_addr * ip_a, 
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
 * Function to get the tuple out of a given struct_skbuff.
 */
static bool nat64_get_tuple(u_int8_t l3protocol, u_int8_t l4protocol, 
		struct sk_buff *skb, struct nf_conntrack_tuple * inner)
{
	const struct nf_conntrack_l4proto *l4proto;
	struct nf_conntrack_l3proto *l3proto;
	int l3_hdrlen, ret;
	unsigned int protoff = 0;
	u_int8_t protonum = 0;

	pr_debug("NAT64: Getting the protocol and header length");

	/*
	 * Get L3 header length
	 */
	l3_hdrlen = nat64_get_l3hdrlen(skb, l3protocol);

	if (l3_hdrlen == -1) {
		pr_debug("NAT64: Something went wrong getting the"
				" l3 header length");
		return false;
	}

	/*
	 * Get L3 struct to access it's functions.
	 */
	if (!(nat64_get_l3struct(l3protocol, &l3proto)))
		return false;

	if (l3proto == NULL) {
		pr_info("NAT64: nat64_get_tuple - the l3proto pointer is null");
		return false;
	}

	rcu_read_lock();

	pr_debug("NAT64: l3_hdrlen = %d", l3_hdrlen);

	/*
	 * Gets the structure with the respective L4 protocol functions.
	 */
	ret = l3proto->get_l4proto(skb, skb_network_offset(skb), 
			&protoff, &protonum);

	if (ret != NF_ACCEPT) {
		pr_info("NAT64: nat64_get_tuple - error getting the L4 offset");
		pr_debug("NAT64: ret = %d", ret);
		pr_debug("NAT64: protoff = %u", protoff);
		rcu_read_unlock();
		return false;
	} else if (protonum != l4protocol) {
		pr_info("NAT64: nat64_get_tuple - protocols don't match");
		pr_debug("NAT64: protonum = %u", protonum);
		pr_debug("NAT64: l4protocol = %u", l4protocol);
		rcu_read_unlock();
		return false;
	}

	l4proto = __nf_ct_l4proto_find(l3protocol, l4protocol);
	pr_debug("l4proto name = %s %d %d", l4proto->name, 
			(u_int32_t)l4proto->l3proto, (u_int32_t)l4proto->l4proto);

	/*
	 * Get the tuple out of the sk_buff.
	 */
	if (!nf_ct_get_tuple(skb, skb_network_offset(skb),
				l3_hdrlen,
				(u_int16_t)l3protocol, l4protocol,
				inner, l3proto, l4proto)) {
		pr_debug("NAT64: couldn't get the tuple");
		rcu_read_unlock();
		return false;
	}

	pr_debug("\nPRINTED TUPLE");
	nat64_print_tuple(inner);
	pr_debug("\n");
	rcu_read_unlock();

	return true;
}

/*
 * Function to get the SKB from IPv4 to IPv6.
 * @l4protocol = The incoming L4 protocol
 * @l3len = The outgoing L3 header length
 * @l4len = The outgoing l4 header length
 * @paylen = transport header length + data length
 *
 * IMPORTANT: We don't take into account the optional IPv6 header yet.
 */
static bool nat64_get_skb_from4to6(struct sk_buff * old_skb,
		struct sk_buff * new_skb, u_int8_t l3protocol, 
		u_int8_t l4protocol, u_int8_t l3len, u_int8_t l4len, 
		u_int8_t pay_len, struct nf_conntrack_tuple * outgoing)
{
	union nat64_l4header_t {
		struct udphdr * uh;
		struct tcphdr * th;
		struct icmp6hdr * icmph;
	} l4header;

	struct ipv6hdr * ip6;
	struct iphdr * ip4;
	void * ip_transp;

	ip6 = ipv6_hdr(new_skb);
	ip4 = ip_hdr(old_skb);

	ip6->version = 6;
	ip6->priority = 0;
	ip6->flow_lbl[0] = 0;
	ip6->flow_lbl[1] = 0;
	ip6->flow_lbl[2] = 0;

	ip6->payload_len = htons(pay_len);
	ip6->nexthdr  = ip4->protocol;
	ip6->hop_limit = ip4->ttl;

	memcpy(&(ip6->saddr), &(outgoing->src.u3.in6), sizeof(struct in6_addr)); // Y'
	memcpy(&(ip6->daddr), &(outgoing->dst.u3.in6), sizeof(struct in6_addr)); // X'

	/*
	 * Get pointer to Layer 4 header.
	 */
	ip_transp = skb_transport_header(old_skb);

	switch(ip6->nexthdr) {
		case IPPROTO_UDP:
			l4header.uh = (struct udphdr *)(ip6 + 1);
			memcpy(l4header.uh, ip_data(ip4), l4len + pay_len);
			checksum_change(&(l4header.uh->check), 
					//&(l4header.uh->source), 
					&(l4header.uh->dest), 
					//outgoing->src.u.udp.port, // Rob.
					outgoing->dst.u.udp.port, // Rob.
					(ip4->protocol == IPPROTO_UDP) ? true : false );
			adjust_checksum_ipv4_to_ipv6( &(l4header.uh->check), 
					ip4, 
					ip6, 
					(ip4->protocol == IPPROTO_UDP) ? true : false );

			break;
		case IPPROTO_TCP:
			l4header.th = (struct tcphdr *)(ip6 + 1);
			memcpy(l4header.th, ip_data(ip4), l4len + pay_len);
			checksum_change(&(l4header.th->check), 
					//&(l4header.th->source), 
					&(l4header.th->dest), 
					//htons(outgoing->src.u.tcp.port),
					//outgoing->src.u.tcp.port, // Rob.
					outgoing->dst.u.tcp.port, // Rob.
					false);
			adjust_checksum_ipv4_to_ipv6(&(l4header.th->check), ip4, ip6,false);
			break;
        case IPPROTO_ICMP:
            l4header.icmph = (struct icmp6hdr *)(ip6 + 1);
            memcpy(l4header.icmph, ip_data(ip4), l4len + pay_len);
            if (ICMP_INFOTYPE(l4header.icmph->icmp6_type)) {
                switch (l4header.icmph->icmp6_type) {
                    case ICMP_ECHO:
                        l4header.icmph->icmp6_type = ICMPV6_ECHO_REQUEST;
                        break;
                    case ICMP_ECHOREPLY:
                        l4header.icmph->icmp6_type = ICMPV6_ECHO_REPLY;
                        break;
                    default:
                        return NULL;
                }
            } else {
                switch (l4header.icmph->icmp6_type) {
                    case ICMP_DEST_UNREACH:
                        l4header.icmph->icmp6_type = ICMPV6_DEST_UNREACH;
                        switch (l4header.icmph->icmp6_code) {
                            case ICMP_NET_UNREACH:
                            case ICMP_HOST_UNREACH:
                                l4header.icmph->icmp6_code = ICMPV6_NOROUTE;
                                break;
                            case ICMP_PORT_UNREACH:
                                l4header.icmph->icmp6_code = ICMPV6_PORT_UNREACH;
                                break;
                            case ICMP_SR_FAILED:
                            case ICMP_NET_UNKNOWN:
                            case ICMP_HOST_UNKNOWN:
                            case ICMP_HOST_ISOLATED:
                            case ICMP_NET_UNR_TOS:
                            case ICMP_HOST_UNR_TOS:
                                l4header.icmph->icmp6_code = ICMPV6_NOROUTE;
                                break;
                            case ICMP_NET_ANO:
                            case ICMP_HOST_ANO:
                                l4header.icmph->icmp6_code =
                                    ICMPV6_ADM_PROHIBITED;
                                break;
                            case ICMP_PROT_UNREACH:
                                l4header.icmph->icmp6_type = ICMPV6_PARAMPROB;
                                l4header.icmph->icmp6_code =
                                    ICMPV6_UNK_NEXTHDR;
                                l4header.icmph->icmp6_pointer =
                                    (char *)&ip6->nexthdr -
                                    (char *)ip6;
                                break;
                            case ICMP_FRAG_NEEDED:
                                l4header.icmph->icmp6_type = ICMPV6_PKT_TOOBIG;
                                l4header.icmph->icmp6_code = 0;
                                l4header.icmph->icmp6_mtu += 20;
                                /* TODO handle icmp_nextmtu == 0 */
                                break;
                            default:
                                return NULL;
                        }
                        break;
                    case ICMP_TIME_EXCEEDED:
                        l4header.icmph->icmp6_type = ICMPV6_TIME_EXCEED;
                        break;
                    case ICMP_PARAMETERPROB:
                        l4header.icmph->icmp6_type = ICMPV6_PARAMPROB;
                        /* TODO update pointer */
                        break;
                    default:
                        return NULL;
                }
                /*nat64_xlate_ipv4_to_ipv6(ip_data(ip4) + 8,*/
                        /*i					session = session_ipv4_lookup(bib, */
                            /*nat64_extract_ipv4(inner->dst.u3.in6, */
                                /*prefix_len), inner->dst.u.udp.port);(struct ipv6hdr *)(l4header.icmph + 1),*/
                        /*plen - sizeof(*l4header.icmph) - sizeof(*ip6), s,*/
                        /*recur + 1);*/
            }
            l4header.icmph->icmp6_cksum = 0;
            ip6->nexthdr = IPPROTO_ICMPV6;
            l4header.icmph->icmp6_cksum = csum_ipv6_magic(&ip6->saddr, &ip6->daddr,
                    l4len + pay_len, IPPROTO_ICMPV6,
                    csum_partial(l4header.icmph, l4len + pay_len, 0));
            break;
        default:
            WARN_ON_ONCE(1);
            return false;
    }

    return true;
}

/*
 * Function to get the SKB from IPv6 to IPv4.
 * @l4protocol = The incoming L4 protocol
 * @l3len = The outgoing L3 header length
 * @l4len = The outgoing l4 header length
 * @paylen = transport header length + data length
 *
 * IMPORTANT: We don't take into account the optional IPv6 header yet.
 */
static bool nat64_get_skb_from6to4(struct sk_buff * old_skb,
        struct sk_buff * new_skb, u_int8_t l3protocol, 
        u_int8_t l4protocol, u_int8_t l3len, u_int8_t l4len, 
        u_int8_t pay_len, struct nf_conntrack_tuple * outgoing)
{
    /*
     * Genric Layer 4 header structure.
     */
    union nat64_l4header_t {
        struct udphdr * uh;
        struct tcphdr * th;
        struct icmphdr * icmph;
    } l4header;

    struct ipv6hdr * ip6;
    struct iphdr * ip4;
    void * ip6_transp;

    struct ipv6_opt_hdr *ip6e;

    ip6 = ipv6_hdr(old_skb);
    ip4 = ip_hdr(new_skb);

    /*
     * IPv4 construction.
     */
    ip4->version = 4;
    ip4->ihl = 5;
    ip4->tos = ip6->priority; 
    ip4->tot_len = htons(sizeof(*ip4) + l4len + pay_len);

    /*
     * According to the RFC6146 the ID should be zero.
     */
    ip4->id = 0;
    ip4->frag_off = htons(IP_DF);
    ip4->ttl = ip6->hop_limit;
    ip4->protocol = ip6->nexthdr;

    pr_debug("NAT64: l4 proto id = %u", ip6->nexthdr);

    ip4->saddr = outgoing->src.u3.in.s_addr;
    ip4->daddr = outgoing->dst.u3.in.s_addr;

    /*
     * Get pointer to Layer 4 header.
     * FIXME: IPv6 option headers should also be considered.
     */
    ip6_transp = skb_transport_header(old_skb);

    /* Skip extension headers. */
    ip6e = (struct ipv6_opt_hdr *)(ip6 + 1);
    while (ip4->protocol == 0 
            || ip4->protocol == 43 
            || ip4->protocol == 60) {
        ip4->protocol = ip6e->nexthdr;
        ip6e = (struct ipv6_opt_hdr *)((char *)ip6e + ip6e->hdrlen * 8);
    }

    switch (ip4->protocol) {
        /*
         * UDP and TCP have the same two first values in the struct. 
         * So UDP header values are used in order to save code.
         */
        case IPPROTO_UDP:
            l4header.uh = ip_data(ip4);
            memcpy(l4header.uh, ip6_transp, l4len + pay_len);

            pr_debug("NAT64: DEBUG: (outgoing->src.u.udp.port = %d), (outgoing->dst.u.udp.port = %d)", ntohs(outgoing->src.u.udp.port), ntohs(outgoing->dst.u.udp.port));
            checksum_change(&(l4header.uh->check), 
                    &(l4header.uh->source), 
                    //&(l4header.uh->dest), 
                    (outgoing->src.u.udp.port), 
                    //(outgoing->dst.u.udp.port), 
                    (ip4->protocol == IPPROTO_UDP) ? 
                    true : false);

            adjust_checksum_ipv6_to_ipv4(&(l4header.uh->check), ip6, 
                    ip4, (ip4->protocol == IPPROTO_UDP) ? 
                    true : false);
            break;
        case IPPROTO_TCP:	 
            l4header.th = ip_data(ip4);
            memcpy(l4header.th, ip6_transp, l4len + pay_len);

            checksum_change(&(l4header.th->check), 
                    &(l4header.th->source), 
                    outgoing->src.u.tcp.port,
                    false);

            adjust_checksum_ipv6_to_ipv4(&(l4header.th->check), ip6, ip4, false);
            break;
        case IPPROTO_ICMPV6:
            l4header.icmph = ip_data(ip4);
            memcpy(l4header.icmph, ip6e, l4len + pay_len);

            if (l4header.icmph->type & ICMPV6_INFOMSG_MASK) {
                switch (l4header.icmph->type) {
                    case ICMPV6_ECHO_REQUEST:
                        pr_debug("NAT64: icmp6 type"
                                " ECHO_REQUEST");
                        l4header.icmph->type = ICMP_ECHO;
                        break;
                    case ICMPV6_ECHO_REPLY:
                        pr_debug("NAT64: icmp6 type"
                                " ECHO_REPLY");
                        l4header.icmph->type = 
                            ICMP_ECHOREPLY;
                        break;
                    default:
                        pr_debug("NAT64: ICMPv6 not "
                                "echo or reply");
                        return false;
                }
            } else {
                switch (l4header.icmph->type) {
                    case ICMPV6_DEST_UNREACH:
                        l4header.icmph->type = ICMP_DEST_UNREACH;
                        switch (l4header.icmph->code) {
                            case ICMPV6_NOROUTE:
                            case ICMPV6_NOT_NEIGHBOUR:
                            case ICMPV6_ADDR_UNREACH:
                                l4header.icmph->code = ICMP_HOST_UNREACH;
                                break;
                            case ICMPV6_ADM_PROHIBITED:
                                l4header.icmph->code = ICMP_HOST_ANO;
                                break;
                            case ICMPV6_PORT_UNREACH:
                                l4header.icmph->code = ICMP_PORT_UNREACH;
                                break;
                            default:
                                return NULL;
                        }
                        break;
                    case ICMPV6_PKT_TOOBIG:
                        l4header.icmph->type = ICMP_DEST_UNREACH;
                        l4header.icmph->code = ICMP_FRAG_NEEDED;
                        l4header.icmph->un.frag.mtu -= 20;
                        break;
                    case ICMPV6_TIME_EXCEED:
                        l4header.icmph->type = ICMP_TIME_EXCEEDED;
                        break;
                    case ICMPV6_PARAMPROB:
                        if (l4header.icmph->code == ICMPV6_UNK_NEXTHDR)
                        {
                            l4header.icmph->type = ICMP_DEST_UNREACH;
                            l4header.icmph->code = ICMP_PROT_UNREACH;
                        } else {
                            l4header.icmph->type = ICMP_PARAMETERPROB;
                            l4header.icmph->code = 0;
                        }
                        /* TODO update pointer */
                        break;
                    default:
                        return NULL;
                }
                /*nat64_xlate_ipv6_to_ipv4(*/
                /*(struct ipv6hdr *)((char *)ip6e + 8),*/
                /*(struct iphdr *)(l4header.icmph + 1), */
                /*plen - ((char *)ip6e + 8 - (char *)ip6), s,*/
                /*recur + 1);*/

            }

            l4header.icmph->checksum = 0;
            l4header.icmph->checksum = 
                ip_compute_csum(l4header.icmph, l4len + pay_len);
            ip4->protocol = IPPROTO_ICMP;
            break;
        default:
            pr_debug("NAT64: encountered incompatible protocol "
                    "while creating the outgoing skb");
            return false;
    }

    ip4->check = 0;
    ip4->check = ip_fast_csum(ip4, ip4->ihl);

    return true;
}

/*
 * Function nat64_get_skb is a generic entry function to get a new skb 
 * that will be sent.
 */
static struct sk_buff * nat64_get_skb(u_int8_t l3protocol, u_int8_t l4protocol, 
        struct sk_buff *skb, struct nf_conntrack_tuple * outgoing)
{
    struct sk_buff *new_skb;

    u_int8_t pay_len = skb->len - skb->data_len;
    u_int8_t packet_len, l4hdrlen, l3hdrlen, l2hdrlen;

    l4hdrlen = -1;

    /*
     * Layer 2 header length is assigned the maximum possible header length
     * possible.
     */
    l2hdrlen = LL_MAX_HEADER;

    pr_debug("NAT64: get_skb paylen = %u", pay_len);

    /*
     * This is called in case a paged sk_buff arrives...this should'nt
     * happen.
     */ 
    if (skb_linearize(skb) < 0)
        return NULL;

    /*
     * It's assumed that if the l4 protocol is ICMP or ICMPv6, 
     * the size of the new header will be the other's.
     */
    switch (l4protocol) {
        case IPPROTO_ICMP:
            l4hdrlen = sizeof(struct icmp6hdr);
            pay_len = pay_len - sizeof(struct icmphdr);
            break;
        case IPPROTO_ICMPV6:
            l4hdrlen = sizeof(struct icmphdr);
            pay_len = pay_len - sizeof(struct icmp6hdr);
            break;
        default:
            l4hdrlen = nat64_get_l4hdrlength(l4protocol);
            pay_len = pay_len - nat64_get_l4hdrlength(l4protocol);
    }

    /*
     * We want to get the opposite Layer 3 protocol header length.
     */
    switch (l3protocol) {
        case NFPROTO_IPV4:
            l3hdrlen = sizeof(struct ipv6hdr);
            pay_len = pay_len - sizeof(struct iphdr);
            break;
        case NFPROTO_IPV6:
            l3hdrlen = sizeof(struct iphdr);
            pay_len = pay_len - sizeof(struct ipv6hdr);
            break;
        default:
            pr_debug("NAT64: nat64_get_skb - unidentified"
                    " layer 3 protocol");
            return NULL;
    }
    pr_debug("NAT64: paylen %d", pay_len);
    pr_debug("NAT64: l3hdrlen %d", l3hdrlen);
    pr_debug("NAT64: l4hdrlen %d", l4hdrlen);

    packet_len = l3hdrlen + l4hdrlen + pay_len;

    /*
     * LL_MAX_HEADER referes to the 'link layer' in the OSI stack.
     */
    new_skb = alloc_skb(l2hdrlen + packet_len, GFP_ATOMIC);

    if (!new_skb) {
        pr_debug("NAT64: Couldn't allocate space for new skb");
        return NULL;
    }

    /*
     * At this point skb->data and skb->head are at the same place.
     * They will be separated by the skb_reserve function.
     */
    skb_reserve(new_skb, l2hdrlen);
    skb_reset_mac_header(new_skb);

    skb_reset_network_header(new_skb);
    skb_set_transport_header(new_skb, l3hdrlen);

    /*
     * The skb->data pointer is right on the l2 header.
     * We move skb->tail to the end of the packet data.
     */
    skb_put(new_skb, packet_len);

    if (!new_skb) {
        if (printk_ratelimit()) {
            pr_debug("NAT64: failed to alloc a new sk_buff");
        }
        return NULL;
    }

    switch (l3protocol) {
        case NFPROTO_IPV4:
            if (nat64_get_skb_from4to6(skb, new_skb, l3protocol,
                        l4protocol, l3hdrlen, l4hdrlen, 
                        (pay_len), outgoing)) { 
                pr_debug("NAT64: Everything went OK populating the "
                        "new sk_buff");
                return new_skb;
            }

            pr_debug("NAT64: something went wrong populating the "
                    "new sk_buff");
            return NULL;
        case NFPROTO_IPV6:
            if (nat64_get_skb_from6to4(skb, new_skb, l3protocol,
                        l4protocol, l3hdrlen, l4hdrlen, 
                        (pay_len), outgoing)) { 
                pr_debug("NAT64: Everything went OK populating the "
                        "new sk_buff");
                return new_skb;
            }

            pr_debug("NAT64: something went wrong populating the "
                    "new sk_buff");
            return NULL;
    }

    pr_debug("NAT64: Not IPv4 or 6");
    return NULL;
}
/*
 * END: NAT64 shared functions.
 */

static struct sk_buff * nat64_translate_packet(u_int8_t l3protocol, 
        u_int8_t l4protocol, struct sk_buff *skb, 
        struct nf_conntrack_tuple * outgoing)
{
    /*
     * FIXME: Handle IPv6 options.
     * The following changes the skb and the L3 and L4 layer protocols to 
     * the respective new values and calls determine_outgoing_tuple.
     */
    struct sk_buff * new_skb = nat64_get_skb(l3protocol, l4protocol, skb,
            outgoing);

    if (!new_skb) {
        pr_debug("NAT64: Skb allocation failed -- returned NULL");
        return NULL;
    }

    /*
     * Adjust the layer 3 protocol variable to be used in the outgoing tuple
     * Wether it's IPV4 or IPV6 is already checked in the nat64_tg function
     */
    l3protocol = (l3protocol == NFPROTO_IPV4) ? NFPROTO_IPV6 : NFPROTO_IPV4;

    /*
     * Adjust the layer 4 protocol variable to be used 
     * in the outgoing tuple.
     */
    if (l4protocol == IPPROTO_ICMP) {
        l4protocol = IPPROTO_ICMPV6;
    } else if (l4protocol == IPPROTO_ICMPV6) {
        l4protocol = IPPROTO_ICMP;
    } else if (!(l4protocol & NAT64_IPV6_ALLWD_PROTOS)){
        pr_debug("NAT64: update n filter -> unkown L4 protocol");
        return NULL;
    }

    //FIXME: No sirve para IPv6
    pr_debug("NAT64: DEBUG: nat64_translate_packet()");
    if (l3protocol == NFPROTO_IPV4 && !(nat64_get_tuple(l3protocol, l4protocol, 
                    new_skb, outgoing))) { 
        pr_debug("NAT64: Something went wrong getting the tuple");
        return NULL;
    }
    pr_debug("NAT64: Determining the translate the packet stage went OK.");

    return new_skb;
}

static struct nf_conntrack_tuple * nat64_determine_outgoing_tuple(
        u_int8_t l3protocol, u_int8_t l4protocol, struct sk_buff *skb, 
        struct nf_conntrack_tuple * inner,
        struct nf_conntrack_tuple * outgoing)
{
    struct nat64_bib_entry *bib;
    struct nat64_st_entry *session;
    struct in_addr * temp_addr;
    struct in6_addr * temp6_addr;
    struct tcphdr *th;

    outgoing = kmalloc(sizeof(struct nf_conntrack_tuple), GFP_ATOMIC);
    memset(outgoing, 0, sizeof(struct nf_conntrack_tuple));

    if (!outgoing) {
        pr_warning("NAT64: There's not enough memory for the outgoing tuple.");
        return NULL;
    }

    /*
     * Get the tuple out of the BIB and ST entries.
     */
    if (l3protocol == NFPROTO_IPV4) {
        temp6_addr = kmalloc(sizeof(struct in6_addr), GFP_ATOMIC);
        memset(temp6_addr, 0, sizeof(struct in6_addr));

        if (!temp6_addr) {
            pr_warning("NAT64: There's not enough memory to do a procedure "
                    "to get the outgoing tuple.");
            return NULL;
        }
        switch (l4protocol) {
            case IPPROTO_TCP:

                //pr_debug("NAT64: TCP protocol not"
                //		" currently supported.");
                bib = bib_ipv4_lookup(inner->dst.u3.in.s_addr, 
                        inner->dst.u.tcp.port, 
                        IPPROTO_TCP);
                if (!bib) {
                    pr_warning("NAT64: The bib entry of the outgoing"
                            " tuple wasn't found.");
                    return NULL;
                }
                session = session_ipv4_lookup(bib, 
                        inner->src.u3.in.s_addr, 
                        inner->src.u.tcp.port);				
                if (!session) {
                    pr_debug("NAT64: The session table entry of"
                            " the outgoing tuple wasn't"
                            " found.");
                    return NULL;
                }
                th=tcp_hdr(skb);
                tcp4_fsm(session, th);

                // Obtain the data of the tuple.
                outgoing->src.l3num = (u_int16_t)l3protocol;

                // Ports
                outgoing->src.u.tcp.port = 
                    session->embedded6_port; // y port
                outgoing->dst.u.tcp.port = 
                    session->remote6_port; // x port

                // SRC IP
                outgoing->src.u3.in6 = 
                    session->embedded6_addr; // Y' addr

                // DST IP
                outgoing->dst.u3.in6 = 
                    session->remote6_addr; // X' addr

                pr_debug("NAT64: TCP outgoing tuple: %pI6c : %d --> %pI6c : %d", 
                        &(outgoing->src.u3.in6), ntohs(outgoing->src.u.tcp.port), 
                        &(outgoing->dst.u3.in6), ntohs(outgoing->dst.u.tcp.port) ); 
                break;
            case IPPROTO_UDP:
                bib = bib_ipv4_lookup(inner->dst.u3.in.s_addr, 
                        inner->dst.u.udp.port,  
                        IPPROTO_UDP);
                if (!bib) {
                    pr_warning("NAT64: The bib entry of the outgoing"
                            " tuple wasn't found.");
                    return NULL;
                }

                session = session_ipv4_lookup(bib, 
                        inner->src.u3.in.s_addr, 
                        inner->src.u.udp.port);				
                if (!session) {
                    pr_debug("NAT64: The session table entry of"
                            " the outgoing tuple wasn't"
                            " found.");
                    return NULL;
                }

                // Obtain the data of the tuple.
                outgoing->src.l3num = (u_int16_t)l3protocol;

                // Ports
                outgoing->src.u.udp.port = 
                    session->embedded6_port; // y port
                outgoing->dst.u.udp.port = 
                    session->remote6_port; // x port

                // SRC IP
                outgoing->src.u3.in6 = 
                    session->embedded6_addr; // Y' addr

                // DST IP
                outgoing->dst.u3.in6 = 
                    session->remote6_addr; // X' addr

                pr_debug("NAT64: UDP outgoing tuple: %pI6c : %d --> %pI6c : %d", 
                        &(outgoing->src.u3.in6), ntohs(outgoing->src.u.udp.port), 
                        &(outgoing->dst.u3.in6), ntohs(outgoing->dst.u.udp.port) );  //Rob

                break;
            case IPPROTO_ICMP:
                bib = bib_ipv4_lookup(inner->dst.u3.in.s_addr, 
                        inner->src.u.icmp.id,  
                        IPPROTO_ICMPV6);

                if (!bib) {
                    pr_warning("NAT64: The bib entry of the outgoing"
                            " tuple wasn't found.");
                    return NULL;
                }

                session = session_ipv4_lookup(bib, 
                        inner->src.u3.in.s_addr, 
                        inner->src.u.icmp.id);				

                if (!session) {
                    pr_debug("NAT64: The session table entry of"
                            " the outgoing tuple wasn't"
                            " found.");
                    return NULL;
                }

                // Obtain the data of the tuple.
                outgoing->src.l3num = (u_int16_t)l3protocol;

                // Ports
                outgoing->src.u.icmp.id = 
                    session->embedded6_port; // y port

                // SRC IP
                outgoing->src.u3.in6 = 
                    session->embedded6_addr; // Y' addr

                // DST IP
                outgoing->dst.u3.in6 = 
                    session->remote6_addr; // X' addr


                break;
            case IPPROTO_ICMPV6:
                pr_debug("NAT64: ICMPv6 protocol not currently "
                        "supported.");
                break;
            default:
                pr_debug("NAT64: layer 4 protocol not currently "
                        "supported.");
                break;
        }
    } else if (l3protocol == NFPROTO_IPV6) {
        temp_addr = kmalloc(sizeof(struct in_addr), GFP_ATOMIC);
        memset(temp_addr, 0, sizeof(struct in_addr));

        if (!temp_addr) {
            pr_warning("NAT64: There's not enough memory to do a "
                    "procedure to get the outgoing tuple.");
            return NULL;
        }
        /*
         * Get the tuple out of the BIB and ST entries.
         */

        switch (l4protocol) {
            case IPPROTO_TCP:
                bib = bib_ipv6_lookup(&(inner->src.u3.in6), inner->src.u.tcp.port, 
                        IPPROTO_TCP);
                break;
            case IPPROTO_UDP:
                bib = bib_ipv6_lookup(&(inner->src.u3.in6), inner->src.u.udp.port, 
                        IPPROTO_UDP);
                break;
            case IPPROTO_ICMPV6:
                bib = bib_ipv6_lookup(&(inner->src.u3.in6), inner->src.u.icmp.id, 
                        IPPROTO_ICMPV6);
                break;
            default:
                pr_debug("NAT64: no hay BIB, lol, jk?");
                break;
        }

        if (bib) {
            //session = session_ipv4_lookup(bib, 
            //			nat64_extract_ipv4(inner->dst.u3.in6, ipv6_pref_len),
            //			inner->dst.u.udp.port);

            switch (l4protocol) {
                case IPPROTO_TCP:
                    session = session_ipv4_lookup(bib, 
                            nat64_extract_ipv4(inner->dst.u3.in6, 
                                //prefix_len), inner->dst.u.tcp.port);
                            ipv6_pref_len), inner->dst.u.tcp.port);
                    break;
                case IPPROTO_UDP:
                    session = session_ipv4_lookup(bib, 
                            nat64_extract_ipv4(inner->dst.u3.in6, 
                                //prefix_len), inner->dst.u.udp.port);
                            ipv6_pref_len), inner->dst.u.udp.port);
                    break;
                case IPPROTO_ICMPV6:
                    session = session_ipv4_lookup(bib, 
                            nat64_extract_ipv4(inner->dst.u3.in6, 
                                //prefix_len), inner->dst.u.udp.port);
                            ipv6_pref_len), inner->src.u.icmp.id);
                    break;
                default:
                    pr_debug("NAT64: no hay sesion, lol, jk?");
                    break;
            }

            if (session) {
                // Obtain the data of the tuple.
                outgoing->src.l3num = (u_int16_t)l3protocol;
                switch (l4protocol) {
                    case IPPROTO_TCP:
                        //pr_debug("NAT64: TCP protocol not "
                        //		"currently supported.");

                        // Ports
                        outgoing->src.u.tcp.port = bib->local4_port;
                        outgoing->dst.u.tcp.port = session->remote4_port;

                        // SRC IP
                        outgoing->src.u3.ip = bib->local4_addr;
                        temp_addr->s_addr = bib->local4_addr;
                        outgoing->src.u3.in = *(temp_addr);

                        // DST IP
                        outgoing->dst.u3.ip = session->remote4_addr;
                        temp_addr->s_addr = session->remote4_addr;
                        outgoing->dst.u3.in = *(temp_addr);

                        pr_debug("NAT64: TCP outgoing tuple: %pI4 : %d --> %pI4 : %d", 
                                &(outgoing->src.u3.in), ntohs(outgoing->src.u.tcp.port), 
                                &(outgoing->dst.u3.in), ntohs(outgoing->dst.u.tcp.port));
                        break;
                    case IPPROTO_UDP:
                        // Ports
                        outgoing->src.u.udp.port = 
                            bib->local4_port;
                        outgoing->dst.u.udp.port = 
                            session->remote4_port;

                        // SRC IP
                        outgoing->src.u3.ip = bib->local4_addr;
                        temp_addr->s_addr = bib->local4_addr;
                        outgoing->src.u3.in = *(temp_addr);

                        // DST IP
                        outgoing->dst.u3.ip = session->remote4_addr;
                        temp_addr->s_addr = session->remote4_addr;
                        outgoing->dst.u3.in = *(temp_addr);

                        pr_debug("NAT64: UDP outgoing tuple: %pI4 : %d --> %pI4 : %d", 
                                &(outgoing->src.u3.in), ntohs(outgoing->src.u.udp.port), 
                                &(outgoing->dst.u3.in), ntohs(outgoing->dst.u.udp.port) );
                        break;
                    case IPPROTO_ICMP:
                        pr_debug("NAT64: ICMP protocol not currently supported.");
                        break;
                    case IPPROTO_ICMPV6:
                        // Ports
                        outgoing->src.u.icmp.id = 
                            bib->local4_port;

                        // SRC IP
                        outgoing->src.u3.ip = bib->local4_addr;
                        temp_addr->s_addr = bib->local4_addr;
                        outgoing->src.u3.in = *(temp_addr);

                        // DST IP
                        outgoing->dst.u3.ip = session->remote4_addr;
                        temp_addr->s_addr = session->remote4_addr;
                        outgoing->dst.u3.in = *(temp_addr);

                        break;
                    default:
                        pr_debug("NAT64: layer 4 protocol not currently supported.");
                        break;
                }
            } else {
                pr_debug("The session wasn't found.");
                goto error;
            }
        } else {
            pr_debug("The BIB wasn't found.");
            goto error;
        }
    }

    return outgoing;

error:
    return NULL;
}

/*
 * This procedure performs packet filtering and
 * updates BIBs and STs.
 */
static bool nat64_filtering_and_updating(u_int8_t l3protocol, u_int8_t l4protocol, 
        struct sk_buff *skb, struct nf_conntrack_tuple * inner)
{
    struct nat64_bib_entry *bib;
    struct nat64_st_entry *session;
    struct tcphdr *tcph = tcp_hdr(skb);
    struct icmphdr *icmph = icmp_hdr(skb);
    bool res;
    //	int i;
    res = false;

    if (l3protocol == NFPROTO_IPV4) {
        pr_debug("NAT64: FNU - IPV4");
        /*
         * Query the STs for any records
         * If there's no active session for the specified 
         * connection, the packet should be dropped
         */
        switch (l4protocol) {
            case IPPROTO_TCP:
                //Query TCP ST
                //pr_debug("NAT64: TCP protocol not currently supported.");

                bib = bib_ipv4_lookup(inner->dst.u3.in.s_addr, 
                        inner->dst.u.tcp.port, 
                        IPPROTO_TCP);
                if (!bib) {
                    pr_warning("NAT64: IPv4 - BIB is missing.");
                    return res;
                }

                session = session_ipv4_lookup(bib, 
                        inner->src.u3.in.s_addr, 
                        inner->src.u.tcp.port);				
                if (!session) {
                    pr_warning("NAT64: IPv4 - session entry is "
                            "missing.");
                    return res;
                }

                pr_debug("NAT64: TCP protocol for IPv4 "
                        "finished properly.");
                res = true;
                break;
            case IPPROTO_UDP:
                //Query UDP BIB and ST

                bib = bib_ipv4_lookup(inner->dst.u3.in.s_addr, 
                        (inner->dst.u.udp.port),
                        IPPROTO_UDP);
                if (!bib) {
                    pr_warning("NAT64: IPv4 - BIB is missing.");
                    return res;
                }

                session = session_ipv4_lookup(bib, 
                        inner->src.u3.in.s_addr, 
                        inner->src.u.udp.port);				
                if (!session) {
                    pr_warning("NAT64: IPv4 - session entry is "
                            "missing.");
                    return res;
                }

                pr_debug("NAT64: UDP protocol for IPv4 "
                        "finished properly.");
                res = true;
                break;
            case IPPROTO_ICMP:
                //Query ICMP ST
                bib = bib_ipv4_lookup(inner->dst.u3.in.s_addr, 
                        (inner->src.u.icmp.id),
                        IPPROTO_ICMPV6);

                if (!bib) {
                    pr_debug("No se pudo con T':%pI4.", &inner->dst.u3.in.s_addr);
                    pr_debug("Inner: %hu", ntohs(inner->src.u.icmp.id));
                    pr_warning("NAT64: IPv4 - BIB is missing.");
                    return res;
                }

                session = session_ipv4_lookup(bib, 
                        inner->src.u3.in.s_addr, 
                        inner->src.u.icmp.id);				

                if (!session) {
                    pr_warning("NAT64: IPv4 - session entry is "
                            "missing.");
                    return res;
                }
                res = true;
                break;
            case IPPROTO_ICMPV6:
                //Query ICMPV6 ST
                pr_debug("NAT64: ICMPv6 protocol not "
                        "currently supported.");
                break;
            default:
                //Drop packet
                pr_debug("NAT64: layer 4 protocol not "
                        "currently supported.");
                break;
        }
        goto end;
    } else if (l3protocol == NFPROTO_IPV6) {
        pr_debug("NAT64: FNU - IPV6");	
        // FIXME: Return true if it is not H&H. A special return code 
        // will have to be added as a param in the future to handle it.
        res = false;
        //		clean_expired_sessions(&expiry_queue);
        //		for (i = 0; i < NUM_EXPIRY_QUEUES; i++)
        //			clean_expired_sessions(&expiry_base[i].queue);
        switch (l4protocol) {
            case IPPROTO_TCP:
                /*
                 * FIXME: Finish TCP session handling
                 */
                pr_debug("NAT64: FNU - TCP");

                bib = bib_ipv6_lookup(&(inner->src.u3.in6), 
                        inner->src.u.tcp.port, IPPROTO_TCP);
                if(bib) {
                    session = session_ipv4_lookup(bib, 
                            nat64_extract_ipv4(
                                inner->dst.u3.in6, 
                                //prefix_len), 
                            ipv6_pref_len), 
                            inner->dst.u.tcp.port);
                    if(session) {
                        tcp6_fsm(session, tcph);
                    }else{
                        pr_debug("Create a session entry, no sesion.");
                        session = session_create_tcp(bib, 
                                &(inner->dst.u3.in6), 
                                nat64_extract_ipv4(
                                    inner->dst.u3.in6, 
                                    //prefix_len), 
                                ipv6_pref_len), 
                                inner->dst.u.tcp.port, 
                                TCP_TRANS);
                    }
                } else if (tcph->syn) {
                    pr_debug("Create a new BIB and Session entry syn.");
                    bib = bib_session_create_tcp(
                            &(inner->src.u3.in6), 
                            &(inner->dst.u3.in6), 
                            nat64_extract_ipv4(
                                inner->dst.u3.in6, 
                                //prefix_len), 
                            ipv6_pref_len), 
                        inner->src.u.tcp.port, 
                        inner->dst.u.tcp.port, 
                        l4protocol, TCP_TRANS);

                    session = list_entry(bib->sessions.next, struct nat64_st_entry, list);
                    session->state = V6_SYN_RCV;
                }
                res = true;
                break;
            case IPPROTO_UDP:
                pr_debug("NAT64: FNU - UDP");
                /*
                 * Verify if there's any binding for the src 
                 * address by querying the UDP BIB. If there's a
                 * binding, verify if there's a connection to the 
                 * specified destination by querying the UDP ST.
                 * 
                 * In case these records are missing, they 
                 * should be created.
                 */
                bib = bib_ipv6_lookup(&(inner->src.u3.in6), 
                        inner->src.u.udp.port,
                        IPPROTO_UDP);
                if (bib) {
                    session = session_ipv4_lookup(bib, 
                            nat64_extract_ipv4(
                                inner->dst.u3.in6, 
                                ipv6_pref_len), 
                            inner->dst.u.udp.port);
                    if (session) {
                        session_renew(session, UDP_DEFAULT);
                    } else {
                        session = session_create(bib, 
                                &(inner->dst.u3.in6), 
                                nat64_extract_ipv4(
                                    inner->dst.u3.in6, 
                                    ipv6_pref_len), 
                                inner->dst.u.udp.port, 
                                UDP_DEFAULT);
                    }
                } else {
                    pr_debug("Create a new BIB and Session entry.");
                    bib = bib_session_create(
                            &(inner->src.u3.in6), 
                            &(inner->dst.u3.in6), 
                            nat64_extract_ipv4(
                                inner->dst.u3.in6, 
                                ipv6_pref_len), 
                            inner->src.u.udp.port, 
                            inner->dst.u.udp.port, 
                            l4protocol, UDP_DEFAULT);
                }
                res = true;
                break;
            case IPPROTO_ICMP:
                //Query ICMP ST
                pr_debug("NAT64: ICMP protocol not currently "
                        "supported.");
                break;
            case IPPROTO_ICMPV6:
                //Query ICMPV6 ST
                bib = bib_ipv6_lookup(&(inner->src.u3.in6), 
                        inner->src.u.icmp.id, IPPROTO_ICMP);
                if(bib) {
                    session = session_ipv4_lookup(bib, 
                            nat64_extract_ipv4(
                                inner->dst.u3.in6, 
                                //prefix_len), 
                            ipv6_pref_len), 
                            inner->src.u.icmp.id);
                    if(session) {
                        session_renew(session, ICMP_DEFAULT);
                    }else {
                        session = session_create(bib, 
                                &(inner->dst.u3.in6), 
                                nat64_extract_ipv4(
                                    inner->dst.u3.in6, 
                                    ipv6_pref_len), 
                                inner->src.u.icmp.id, 
                                ICMP_DEFAULT);
                    }
                } else {
                    pr_debug("Create a new BIB and Session entry.");
                    bib = bib_session_create(
                            &(inner->src.u3.in6), 
                            &(inner->dst.u3.in6), 
                            nat64_extract_ipv4(
                                inner->dst.u3.in6, 
                                ipv6_pref_len), 
                            inner->src.u.icmp.id, 
                            inner->src.u.icmp.id, 
                            l4protocol, ICMP_DEFAULT);
                }
                res = true;
                /*pr_debug("NAT64: ICMPv6 protocol not currently "*/
                /*"supported.");*/
                break;
            default:
                //Drop packet
                pr_debug("NAT64: layer 4 protocol not currently "
                        "supported.");
                break;
        }
        goto end;
    }

    return res;
end: 
    if (res) 
        pr_debug("NAT64: Updating and Filtering stage went OK.");
    else 
        pr_debug("NAT64: Updating and Filtering stage FAILED.");
    return res;
}

/*
 * Function that gets the packet's information and returns a tuple out of it.
 */
static bool nat64_determine_tuple(u_int8_t l3protocol, u_int8_t l4protocol, 
        struct sk_buff *skb, struct nf_conntrack_tuple * inner)
{
    pr_debug("NAT64: DEBUG: nat64_determine_tuple()");
    if (!(nat64_get_tuple(l3protocol, l4protocol, skb, inner))) {
        pr_debug("NAT64: Something went wrong getting the tuple");
        return false;
    }

    pr_debug("NAT64: Determining the tuple stage went OK.");

    return true;
}

/*
 * NAT64 Core Functionality
 *
 */
static unsigned int nat64_core(struct sk_buff *skb, 
        const struct xt_action_param *par, u_int8_t l3protocol,
        u_int8_t l4protocol) {

    struct nf_conntrack_tuple inner;
    struct nf_conntrack_tuple * outgoing;
    struct sk_buff * new_skb;

    if (!nat64_determine_tuple(l3protocol, l4protocol, skb, &inner)) {
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

    new_skb = nat64_translate_packet(l3protocol, l4protocol, skb, outgoing);

    if (!new_skb) {
        pr_info("NAT64: There was an error in the packet translation"
                " module");
        return NF_DROP;
    }

    //FIXME: The same value 'NF_DROP' is returned for both ERROR and CORRECT conditions.
    /*
     * Returns zero if it works
     */
    if (nat64_send_packet(skb, new_skb)) {
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
static unsigned int nat64_tg4(struct sk_buff *skb, 
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
static unsigned int nat64_tg6(struct sk_buff *skb, 
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
static unsigned int nat64_tg(struct sk_buff *skb, 
        const struct xt_action_param *par)
{
    if (par->family == NFPROTO_IPV4)
        return nat64_tg4(skb, par);
    else if (par->family == NFPROTO_IPV6)
        return nat64_tg6(skb, par);
    else
        return NF_ACCEPT;
}

static int nat64_tg_check(const struct xt_tgchk_param *par)
{
    int ret;

    ret = nf_ct_l3proto_try_module_get(par->family);
    if (ret < 0)
        pr_info("cannot load support for proto=%u\n",
                par->family);
    return ret;
}

static struct xt_target nat64_tg_reg __read_mostly = {
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


static ssize_t device_read(struct file *filp, char __user *buffer, size_t length, loff_t *offset)
{
    return simple_read_from_buffer(buffer, length, offset, msg, 200);
}


static ssize_t device_write(struct file *filp, const char __user *buff, size_t len, loff_t *off)
{
    if (len > 199)
        return -EINVAL;
    copy_from_user(msg, buff, len);

    msg[len] = '\0';
    return len;
}
char buf[200];
long device_ioctl(struct file *filep, unsigned int cmd, unsigned long arg) {

    long len = 200;
    switch(cmd) {
        case READ_IOCTL:
            copy_to_user((char *)arg, "Holakern\n", 10);
            break;

        case WRITE_IOCTL:
            copy_from_user(buf, (char *)arg, len);
            print_bufu(buf);
            break;

        default:
            return -ENOTTY;
    }
    return len;

}
static struct file_operations fops = {
    .read = device_read, 
    .write = device_write,
    .unlocked_ioctl = device_ioctl
};

static int __init nat64_init(void)
{
    /* Variables imported from Julius Kriukas's implementation */
    int ret = 0;

    /*	Previous implementation:	
        ipv4_prefixlen = 24;
        ipv4_addr = 0;
        ipv4_address = "192.168.2.1"; // Default IPv4
        ipv4_netmask = 0xffffff00; // Mask of 24 IPv4
        prefix_address = "64:ff9b::"; // Default IPv6
        prefix_len = 96; // Default IPv6 Prefix  
        */    

    // Rob : 
    ipv4_mask_bits = IPV4_POOL_MASKBITS;	// Num. of bits 'on' in the net mask
    ipv4_addr = 0;
    /* Default configuration, until it's set up by the user space application. */
    /* IPv4 */
    ipv4_addr_str = IPV4_POOL_FIRST;	// Default IPv4 (string)
    ipv4_netmask = IPV4_POOL_MASK; 		// Mask of 24-bits IPv4 (_be32)
    /* IPv6 */
    ipv6_pref_addr_str = IPV6_PREF_NET;	// Default IPv6	(string)
    ipv6_pref_len = IPV6_PREF_MASKBITS; // Default IPv6 Prefix	(int)

    // init IPv4 addresses pool
    init_pools(); // Bernardo

    pr_debug("\n\n\nNAT64 module inserted!");

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

    l3proto_ip = nf_ct_l3proto_find_get((u_int16_t) NFPROTO_IPV4);
    l3proto_ipv6 = nf_ct_l3proto_find_get((u_int16_t) NFPROTO_IPV6);

    if (l3proto_ip == NULL) {
        pr_warning("NAT64: couldn't load IPv4 l3proto");
        goto error;
    } 
    if (l3proto_ipv6 == NULL) {
        pr_warning("NAT64: couldn't load IPv6 l3proto");
        goto error;
    }

    // BEGIN: code imported from nat64_init of Julius Kriukas' implementation

    ret = in4_pton(ipv4_addr_str, -1, (u8 *)&ipv4_addr, '\x0', NULL);
    if (!ret) {
        pr_warning("NAT64: ipv4 is malformed [%s].", ipv4_addr_str);
        ret = -1;
        goto error;
    }
    //	if (ret) {
    if (ipv4_mask_bits > 32 || ipv4_mask_bits < 1) {
        pr_warning("NAT64: ipv4 netmask bits value is invalid [%s].", 
                ipv4_addr_str);
        ret = -1;
        goto error;
    }

    ipv4_netmask = inet_make_mask(ipv4_mask_bits);
    pr_debug("NAT64: using IPv4 subnet %pI4/%d (netmask %pI4).", 
            &ipv4_addr, ipv4_mask_bits, &ipv4_netmask);
    //	}

    if (nat64_allocate_hash(65536)) // FIXME: look in the kernel headers for the definition of this constant (size) and use it instead of this hardcoded value.
    {
        pr_warning("NAT64: Unable to allocate memmory for hash table.");
        goto hash_error;
    }

    st_cache = kmem_cache_create("nat64_st", sizeof(struct nat64_st_entry),
            0,0, NULL);
    st_cacheTCP = kmem_cache_create("nat64_stTCP", sizeof(struct nat64_st_entry),
            0,0, NULL);

    if (!st_cache || !st_cacheTCP) {
        pr_warning("NAT64: Unable to create session table slab cache.");
        goto st_cache_error;
    } 
    pr_debug("NAT64: The session table slab cache was succesfully created.\n");

    bib_cache = kmem_cache_create("nat64_bib", sizeof(struct nat64_bib_entry), 
            0,0, NULL);
    bib_cacheTCP = kmem_cache_create("nat64_bibTCP", sizeof(struct nat64_bib_entry), 
            0,0, NULL);

    if (!bib_cache || !bib_cacheTCP) {
        pr_warning("NAT64: Unable to create bib table slab cache.");
        goto bib_cache_error;
    }
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
        goto bib_cache_error;
    } 
    // END
    // // Load char device used by Miguel
    major = register_chrdev(0, "my_device", &fops);
    if (major < 0) {
        printk ("Registering the character device failed with %d\n", major);
        return major;
    }
    printk("\ncdev example: assigned major: %d\n", major);
    printk("create node with mknod /dev/cdev_example c %d 0\n", major);

    return xt_register_target(&nat64_tg_reg);

    // The following goto were inspired by Julius Kriukas' nat64_init's goto
error:
    return -EINVAL;
hash_error:
    return -ENOMEM;
st_cache_error:
    kmem_cache_destroy(st_cache);
    kmem_cache_destroy(st_cacheTCP);
    return -ENOMEM;
bib_cache_error:
    kmem_cache_destroy(st_cache);
    kmem_cache_destroy(st_cacheTCP);
    kmem_cache_destroy(bib_cache);
    kmem_cache_destroy(bib_cacheTCP);
    return -ENOMEM;
}

static void __exit nat64_exit(void)
{
    nf_ct_l3proto_put(l3proto_ip);
    nf_ct_l3proto_put(l3proto_ipv6);
    kmem_cache_destroy(st_cache); // Line inherited from Julius Kriukas's nat64_exit function.
    kmem_cache_destroy(bib_cache); // Line inherited from Julius Kriukas's nat64_exit function.
    kmem_cache_destroy(st_cacheTCP);
    kmem_cache_destroy(bib_cacheTCP);
    xt_unregister_target(&nat64_tg_reg);

    unregister_chrdev(major, "my_device");

    if (my_nl_sock) netlink_kernel_release(my_nl_sock); // Unload netlink sockets. Rob

    pr_debug("NAT64 module removed!\n\n\n");
}

module_init(nat64_init);
module_exit(nat64_exit);
