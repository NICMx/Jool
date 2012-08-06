#include <net/route.h>
#include <net/ip6_route.h>
#include <linux/version.h>
#include <linux/module.h>


#include "xt_nat64.h"
#include "nf_nat64_banner.h"
#include "nf_nat64_ipv4_pool.h"
#include "nf_nat64_tuple_handling.h"
#include "nf_nat64_determine_incoming_tuple.h"
#include "nf_nat64_translate_packet.h"
#include "xt_nat64_module_conf.h"
#include "nf_nat64_bib_session.h"
#include "nf_nat64_static_routes.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Juan Antonio Osorio <jaosorior@gmail.com>"); // TODO poner a toda la raza
MODULE_DESCRIPTION("Xtables: RFC 6146 \"NAT64\" implementation");
MODULE_ALIAS("ipt_nat64");
MODULE_ALIAS("ip6t_nat64");

#define IPV6_HDRLEN 40
#ifndef KERNEL_VERSION
#define KERNEL_VERSION(a,b,c) ((a)*65536+(b)*256+(c))
#endif

/*
 * FIXME: Ensure all variables are 32 and 64-bits complaint. 
 * That is, no generic data types akin to integer.
 * FIXME: Rob. Change all 'printk' function calls by 'pr_debug' function
 */

/*
 * BEGIN: Global variables inherited from Julius Kriukas's 
 * 		  Linux NAT64 implementation.
 */


/* IPv4 */
extern struct in_addr ipv4_pool_net; // Se puede mover a la estructura de config.
extern struct in_addr ipv4_pool_range_first; // igual.
extern struct in_addr ipv4_pool_range_last; // Igual.
extern int ipv4_mask_bits; // puede hacerse local.
extern __be32 ipv4_netmask;	// TODO change data type -> 'in_addr' type. Rob.
							// Se puede mover a la estructura de config.

/* IPv6 */
extern char *ipv6_pref_addr_str; // puede hacerse local.
extern int ipv6_pref_len; // es lo mismos que config_struct.ipv6_net_mask_bits.

extern struct config_struct cs;

/*
 * END: Global variables inherited from Julius Kriukas's 
 * 		Linux NAT64 implementation.
 */

//~ #define IPV4_POOL_MASK	0xffffff00	// FIXME: Think of use '/24' format instead.
/** Apparently, socket to speak to the userspace application with. TODO Also apparently currently unused. */
struct sock *my_nl_sock;

DEFINE_MUTEX(my_mutex);

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
        skb, &inner);

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

	nat64_create_character_device();

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
	nat64_destroy_character_device();
    if (my_nl_sock) netlink_kernel_release(my_nl_sock); // Unload netlink sockets. Rob
    kfree(ipv6_pref_addr_str);
	//~ kfree(cs);

    pr_debug("NAT64 module removed!\n\n\n");
}

module_init(nat64_init);
module_exit(nat64_exit);
