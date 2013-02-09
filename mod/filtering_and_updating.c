#include "nat64/filtering_and_updating.h"
#include "nat64/config.h"
#include "nat64/config_proto.h"
#include "nat64/config_validation.h"
#include "nat64/rfc6052.h"
#include "nat64/constants.h"
#include "nat64/pool4.h"
#include "nat64/pool6.h"
#include "nat64/send_packet.h"

#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/icmpv6.h>
#include <net/tcp.h>
#include <net/icmp.h>


static struct filtering_config config; ///< Hold the current valid configuration for the filtering and updating module.
static DEFINE_SPINLOCK(config_lock);

/** Esto se llama al insertar el módulo y se encarga de poner los valores por defecto
 *  
 *  @return TRUE: if initialization ran fine, FALSE: otherwhise. */
bool filtering_init(void)
{
    spin_lock_bh(&config_lock);
    
    config.to.udp = UDP_DEFAULT;
    config.to.icmp = ICMP_DEFAULT;
    config.to.tcp_trans = TCP_TRANS;
    config.to.tcp_est = TCP_EST;

    config.address_dependent_filtering = FILT_DEF_ADDR_DEPENDENT_FILTERING;
    config.drop_externally_initiated_tcp_connections = FILT_DEF_DROP_EXTERNAL_CONNECTIONS;
    config.filter_informational_icmpv6 = FILT_DEF_FILTER_ICMPV6_INFO;

    spin_unlock_bh(&config_lock);
    
    return true;
} 

/** Esto libera la memoria reservada por filtering_init. 
 *  */
void filtering_destroy(void)
{
    // No code.
} 

/** Esta guarda el contenido de config en el parámetro "clone". 
 *  La necesito en configuración para enviar la configuración a userspace cuando se consulta 
 * 
 *  @param[out]  clone   A copy of the current configuration values.
 *  @return     TRUE: if copy  , FALSE: otherwise. */
bool clone_filtering_config(struct filtering_config *clone)
{
    spin_lock_bh(&config_lock);
    *clone = config;
    spin_unlock_bh(&config_lock);

    return true;
} 

/** Sirve para modificar a config 
 *  
 *  @param[in]  operation   _____________
 *  @param[in]  new_config  The new configuration.
 *  @return response_code   ___________.
 *  */
enum response_code set_filtering_config(__u32 operation, struct filtering_config *new_config)
{
    spin_lock_bh(&config_lock);

    if (operation & ADDRESS_DEPENDENT_FILTER_MASK)
        config.address_dependent_filtering = new_config->address_dependent_filtering;
    if (operation & FILTER_INFO_MASK)
        config.filter_informational_icmpv6 = new_config->filter_informational_icmpv6;
    if (operation & DROP_TCP_MASK)
        config.drop_externally_initiated_tcp_connections =
            new_config->drop_externally_initiated_tcp_connections; // Dude.
 
    if (operation & UDP_TIMEOUT_MASK) {
        if ( new_config->to.udp < UDP_MIN )
            goto invalid_value;
        else
            config.to.udp = new_config->to.udp;
    }
    if (operation & ICMP_TIMEOUT_MASK)
        config.to.icmp = new_config->to.icmp;
    if (operation & TCP_TRANS_TIMEOUT_MASK) {
        if ( new_config->to.tcp_trans < TCP_TRANS )
            goto invalid_value;
        else
            config.to.tcp_trans = new_config->to.tcp_trans;
    }
    if (operation & TCP_EST_TIMEOUT_MASK) {
        if ( new_config->to.tcp_est < TCP_EST )
            goto invalid_value;
        else
            config.to.tcp_est = new_config->to.tcp_est;
    }
  
    spin_unlock_bh(&config_lock);
    return RESPONSE_SUCCESS;

// TODO: How do you respond what value is invalid? Maybe you should include the mask in the response.
invalid_value:
    spin_unlock_bh(&config_lock);
    return RESPONSE_INVALID_VALUE;
} 

static void update_session_lifetime(struct session_entry *session_entry_p, unsigned int *timeout)
{
    unsigned int temp;

    spin_lock_bh(&config_lock);
    temp = *timeout;
    spin_unlock_bh(&config_lock);

    nat64_update_session_lifetime(session_entry_p, temp); 
}

static bool filter_icmpv6_info(void)
{
    bool result;
    
    spin_lock_bh(&config_lock);
    result = config.filter_informational_icmpv6;
    spin_unlock_bh(&config_lock);
    
    return result;
}

static bool address_dependent_filtering(void)
{
    bool result;
    
    spin_lock_bh(&config_lock);
    result = config.address_dependent_filtering;
    spin_unlock_bh(&config_lock);
    
    return result;
}

static bool drop_external_connections(void)
{
    bool result;
    
    spin_lock_bh(&config_lock);
    result = config.drop_externally_initiated_tcp_connections;
    spin_unlock_bh(&config_lock);
    
    return result;
}



/*********************************************
 **                                         **
 **     DEVELOPMENT FUNCTIONS               **
 **                                         **
 *********************************************/
void print_bib_entry( struct bib_entry *bib_entry_p )
{
    if ( bib_entry_p == NULL )
        pr_debug("  > bib_entry = NULL   :'( ");
    else
        pr_debug("  > bib_entry = (%pI6c , %d) -- (%pI4 , %d)",
            &bib_entry_p->ipv6.address, bib_entry_p->ipv6.l4_id,
            &(bib_entry_p->ipv4.address), bib_entry_p->ipv4.l4_id );
}


/*********************************************
 **                                         **
 **     SUPPORT FUNCTIONS                   **
 **                                         **
 *********************************************/


/** Join a IPv4 address and a port (or ICMP ID) to create a Transport Address.
 *
 * @param[in]  addr IPv4 Address
 * @param[in]  pi   Port or ICMP ID
 * @param[out] ta   Transport Address
 * */
void transport_address_ipv4(struct in_addr addr, __be16 pi, struct ipv4_tuple_address *ta)
{ 
    ta->address = addr;
    ta->l4_id = be16_to_cpu(pi);
}

/** Join a IPv6 address and a port (or ICMP ID) to create a Transport Address.
 *
 * @param[in]  addr IPv6 Address
 * @param[in]  pi   Port or ICMP ID
 * @param[out] ta   Transport Address
 * */
void transport_address_ipv6(struct in6_addr addr, __be16 pi, struct ipv6_tuple_address *ta)
{ 
    ta->address = addr;
    ta->l4_id = be16_to_cpu(pi);
}

/** Retrieve a new port for the specified IPv4 pool address.
 *
 *  For an already asigned IPv4 pool entry, give me a free port with the same parity as the source port.
 * 
 * If the port s is in the Well-Known port range 0-1023, and the
NAT64 has an available port t in the same port range, then the
NAT64 SHOULD allocate the port t. If the NAT64 does not have a
port available in the same range, the NAT64 MAY assign a port t
from another range where it has an available port. (This behavior
is recommended in REQ 3-a of [RFC4787].)
If the port s is in the range 1024-65535, and the NAT64 has an
available port t in the same port range, then the NAT64 SHOULD
allocate the port t. If the NAT64 does not have a port available
in the same range, the NAT64 MAY assign a port t from another
range where it has an available port. (This behavior is
recommended in REQ 3-a of [RFC4787].)
The NAT64 SHOULD preserve the port parity (odd/even), as per
Section 4.2.2 of [RFC4787]).
 * 
 * @param[in]   protocol    In what protocolo we should look at?
 * @param[in]   address     Give me a free port for this IP address.
 * @param[in]   pi          Look for a port within the same range and parity.
 * @param[out]  new_ipv4_transport_address  New transport address obtained from the PROTOCOL's pool.
 * @return  true if everything went OK, false otherwise.
 * */
bool ipv4_pool_get_new_port(struct in_addr address, __be16 pi, u_int8_t protocol,
        struct ipv4_tuple_address *result)
{
    struct ipv4_tuple_address ta4;
    transport_address_ipv4(address, pi, &ta4);
    return pool4_get_similar(protocol, &ta4, result);
}

/** Allocate from IPv4 pool a new transport address for TCP & UDP.
 *
 *  RFC6146 - Sec. 3.5.1.1
 *
 * @param[in]   tuple       Packet's tuple containg the source address.
 * @param[in]   protocol    In what protocolo we should look at?
 * @param[out]  new_ipv4_transport_address  New transport address obtained from the PROTOCOL's pool.
 * @return  true if everything went OK, false otherwise.
 */
bool allocate_ipv4_transport_address(struct nf_conntrack_tuple *tuple, u_int8_t protocol,
        struct ipv4_tuple_address *result)
{
    struct bib_entry *bib_entry_t;

    // Check if the BIB has a previous entry from the same IPv6 source address (X’)
    bib_entry_t = nat64_get_bib_entry_by_ipv6_only( &tuple->ipv6_src_addr, protocol );

    // If true, use the same IPv4 address (T). 
    if ( bib_entry_t != NULL )
    {
        struct ipv4_tuple_address temp;
        transport_address_ipv4(bib_entry_t->ipv4.address, tuple->src_port, &temp);
        return pool4_get_similar(protocol, &temp, result);
    }
    else // Else, create a new BIB entry and ask the IPv4 pool for a new IPv4 address.
    {
        return pool4_get_any(protocol, tuple->src_port, result);
    }
}

/** Obtains a IPv4 transport address, looking for IPv4 address previously asigned
 *  to the Source's machine, search in the BIBs: TCP, UDP & ICMP.
 *
 *  RFC6146 - Sec. 3.5.2.3
 * 
 * @param[in]   tuple       Packet's tuple containg the source address.
 * @param[in]   protocol    In what protocolo we should look at FIRST?
 * @param[out]  new_ipv4_transport_address  New transport address obtained from the PROTOCOL's pool.
 * @return  true if everything went OK, false otherwise.
 */
bool allocate_ipv4_transport_address_digger(struct nf_conntrack_tuple *tuple, u_int8_t protocol,
        struct ipv4_tuple_address *result)
{ 
    unsigned char ii = 0;
    u_int8_t proto[] = {IPPROTO_TCP, IPPROTO_UDP, IPPROTO_ICMP};
    struct in_addr *address = NULL;

    /*  If there exists another BIB entry in any of the BIBs that
        contains the same IPv6 source address (S’) and maps it to an IPv4
        address (T), then use (T) as the BIB IPv4 address for this new
        entry. Otherwise, use any IPv4 address assigned to the IPv4
        interface. */
    
    /*  Look in the three BIB tables for a previous packet from the same origin (S'),
     *  we will do this anyway. */
    for (ii = 0 ; ii < 3 ; ii++)
    {
        struct bib_entry *bib_entry_p;
        
        bib_entry_p = nat64_get_bib_entry_by_ipv6_only(&tuple->ipv6_src_addr, proto[ii]);
        if (bib_entry_p != NULL)
        {
            address = &bib_entry_p->ipv4.address;
            break; // We found one entry!
        }
    }
    
    if ( address != NULL )
    {
        // Use the same address
        struct ipv4_tuple_address temp;
        transport_address_ipv4(*address, tuple->src_port, &temp);
        return pool4_get_similar(protocol, &temp, result);
    }
    else
    {
        // Use whichever address
        return pool4_get_any(protocol, tuple->src_port, result);
    }
}


/** Send an ICMP error message, with a specific Type & Code, to the original 
 *  sender of the packet (tuple->source).
 * 
 * @param[in]   tuple   Tuple containing info about the communication.
 * @param[in]   type    Type of message.
 * @param[in]   code    Code of the message.
 * // TODO borrar esto?
 */
bool send_icmp_error_message(struct sk_buff *skb, u_int8_t type, u_int8_t code)
{
    if ( skb->protocol == htons(ETH_P_IP) )
    {
        pr_debug("NAT64: Sending ICMPv4 error message to: %pI4  ", &ip_hdr(skb)->saddr );
        icmp_send(skb, type, code, 0x0);
    }
    else
    {
        pr_debug("NAT64: Sending ICMPv6 error message to: %pI6c ", &ipv6_hdr(skb)->saddr );
        icmpv6_send(skb, type, code, 0x0);
    }
    pr_debug("NAT64: Use a network tool (i.e. tcpdump or wireshark) to catch this packet.");
    return true;
}

/** Determine if a packet is IPv4 .
 * 
 * @param[in]   packet  The incoming packet.
 * @return  true if it is OK, false otherwise.
 */
bool packet_is_ipv4(struct sk_buff* skb)
{
    if (skb == NULL) { 
        pr_warning("  Error in packet_is_ipv4(): skb == NULL "); 
        return false; 
    } else
        return ( skb->protocol == htons(ETH_P_IP) );
}

/** Determine if a packet is IPv6 .
 * 
 * @param[in]   packet  The incoming packet.
 * @return  true if it is OK, false otherwise.
 */
bool packet_is_ipv6(struct sk_buff* skb)
{
    if (skb == NULL) {
        pr_warning("  Error in packet_is_ipv6(): skb == NULL ");
        return false;
    } else {
        return ( skb->protocol == htons(ETH_P_IPV6) );
    }
}

/** Determine if a packet is a V4 SYN packet.
 * 
 * @param[in]   packet  The incoming packet.
 * @return  true if it is OK, false otherwise.
 */
bool packet_is_v4_syn(struct sk_buff* skb)
{
    struct tcphdr *hdr = tcp_hdr(skb);
    if (!hdr)
        return false;
    return packet_is_ipv4(skb) && hdr->syn;
}

/** Determine if a packet is a V6 SYN packet.
 * 
 * @param[in]   packet  The incoming packet.
 * @return  true if it is OK, false otherwise.
 */
bool packet_is_v6_syn(struct sk_buff* skb)
{
    struct tcphdr *hdr = tcp_hdr(skb);
    if (!hdr)
        return false;
    return packet_is_ipv6(skb) && hdr->syn;
}

/** Determine if a packet is a V4 FIN packet.
 * 
 * @param[in]   packet  The incoming packet.
 * @return  true if it is OK, false otherwise.
 */
bool packet_is_v4_fin(struct sk_buff* skb)
{
    struct tcphdr *hdr = tcp_hdr(skb);
    if (!hdr)
        return false;
    return packet_is_ipv4(skb) && hdr->fin;
}

/** Determine if a packet is a V6 FIN packet.
 * 
 * @param[in]   packet  The incoming packet.
 * @return  true if it is OK, false otherwise.
 */
bool packet_is_v6_fin(struct sk_buff* skb)
{
    struct tcphdr *hdr = tcp_hdr(skb);
    if (!hdr)
        return false;
    return packet_is_ipv6(skb) && hdr->fin;
}

/** Determine if a packet is a V4 RST packet.
 * 
 * @param[in]   packet  The incoming packet.
 * @return  true if it is OK, false otherwise.
 */
bool packet_is_v4_rst(struct sk_buff* skb)
{
    struct tcphdr *hdr = tcp_hdr(skb);
    if (!hdr)
        return false;
    return packet_is_ipv4(skb) && hdr->rst;
}

/** Determine if a packet is a V6 RST packet.
 * 
 * @param[in]   packet  The incoming packet.
 * @return  true if it is OK, false otherwise.
 */
bool packet_is_v6_rst(struct sk_buff* skb)
{
    struct tcphdr *hdr = tcp_hdr(skb);
    if (!hdr)
        return false;
    return packet_is_ipv6(skb) && hdr->rst;
}

//~ #include <net/route.h>
//~ #include <net/ip.h>
//~ #include <net/tcp.h>
//~ /** Send a packet to IPv4 destination.
 //~ *  - Codigo de Miguel. 
 //~ *
 //~ * @param[in]   skb     Socket buffer to send. 
 //~ * @return      TRUE: if OK, FALSE: otherwise. */
//~ bool nat64_send_packet_ipv4(struct sk_buff *skb)
//~ {
    //~ struct iphdr *iph = ip_hdr(skb);
    //~ struct flowi fl;
    //~ struct rtable *rt;
//~ 
    //~ skb->protocol = htons(ETH_P_IP);
//~ 
    //~ memset(&fl, 0, sizeof(fl));
//~ 
    //~ fl.u.ip4.daddr = iph->daddr;
    //~ fl.flowi_tos = RT_TOS(iph->tos);
    //~ fl.flowi_proto = skb->protocol;
//~ 
    //~ rt = ip_route_output_key(&init_net, &fl.u.ip4);
//~ 
    //~ if (!rt || IS_ERR(rt)) {
        //~ pr_warning("NAT64: nat64_send_packet - rt is null or an error");
        //~ if (IS_ERR(rt))
            //~ pr_warning("rt -1");
        //~ return false;
    //~ }
//~ 
    //~ skb->dev = rt->dst.dev;
    //~ skb_dst_set(skb, (struct dst_entry *)rt);
//~ 
    //~ if (ip_local_out(skb)) {
        //~ pr_warning("nf_NAT64: ip_local_out failed");
        //~ return false;
    //~ }
    //~ return true;   
//~ }
//~ 

/** Send a probe packet to at least one of the endpoints involved in the TCP connection.
 * 
 * @param[in]   packet  The incoming packet.
 * @return  true if it is OK, false otherwise.
 */
bool send_probe_packet(struct session_entry *entry)
{
    struct tcphdr *th;
    struct ipv6hdr *iph;
    struct sk_buff* skb;

    unsigned int l3_hdr_len = sizeof(*iph);
    unsigned int l4_hdr_len = sizeof(*th);

    skb = alloc_skb(LL_MAX_HEADER + l3_hdr_len + l4_hdr_len, GFP_ATOMIC);
    if (skb == NULL)
        return false;
    skb_reserve(skb, LL_MAX_HEADER);
    skb_put(skb, l3_hdr_len + l4_hdr_len);
    skb_reset_mac_header(skb);
    skb_reset_network_header(skb);
    skb_set_transport_header(skb, l3_hdr_len);

    iph = ipv6_hdr(skb);
    iph->version = 6;
    iph->priority = 0;
    iph->flow_lbl[0] = 0;
    iph->flow_lbl[1] = 0;
    iph->flow_lbl[2] = 0;
    iph->payload_len = l4_hdr_len;
    iph->nexthdr = IPPROTO_TCP;
    iph->hop_limit = 64; // TODO (fine) nat64_send_packet_ipv6 debería setear este valor con dst?
    iph->saddr = entry->ipv6.local.address;
    iph->daddr = entry->ipv6.remote.address;

    th = tcp_hdr(skb);
    th->source = cpu_to_be16(entry->ipv6.local.l4_id);
    th->dest = cpu_to_be16(entry->ipv6.remote.l4_id);
    th->seq = htonl(0);
    th->ack_seq = htonl(0);
    th->res1 = 0;
    th->doff = l4_hdr_len / 4;
    th->fin = 0;
    th->syn = 0;
    th->rst = 0;
    th->psh = 0;
    th->ack = 1;
    th->urg = 0;
    th->ece = 0;
    th->cwr = 0;
    th->window = htons(8192);
    th->check = 0;
    th->urg_ptr = 0;

    th->check = csum_ipv6_magic(&iph->saddr, &iph->daddr, l4_hdr_len, IPPROTO_TCP,
            csum_partial(th, l4_hdr_len, 0));
    skb->ip_summed = CHECKSUM_UNNECESSARY;

    // Send the packet
    nat64_send_packet_ipv6(skb);
    printk("se mando el paquete\n");
    pr_debug("NAT64: Catch the packet using a tool like Wireshark or tcpdump\n");

    return true;
}

static bool extract_ipv4(struct in6_addr *src, struct in_addr *dst)
{
    struct ipv6_prefix prefix;
    if ( !pool6_peek(&prefix) )
    {
        log_warning("Could not extract a prefix from the IPv6 pool. Failing...");
        return false;
    }

    return nat64_extract_ipv4(src, &prefix, dst);
}

static bool append_ipv4(struct in_addr *src, struct in6_addr *dst)
{
    struct ipv6_prefix prefix;
    if ( !pool6_peek(&prefix) )
    {
        log_warning("Could not extract a prefix from the IPv6 pool. Failing...");
        return false;
    }

    return nat64_append_ipv4(src, &prefix, dst);
}

/*********************************************
 **                                         **
 **     MAIN FUNCTIONS                      **
 **                                         **
 *********************************************/

/** An IPv6 incoming packet with an incoming tuple with source transport
 *  address (X’,x) and destination transport address (Y’,y).
 * 
 * The result is a BIB entry as follows: (X’,x) <--> (T,t)
 *              
 * @param[in]   tuple   Tuple of the incoming packet.
 * @return  NF_ACCEPT if everything went OK, NF_DROP otherwise.
 */         
int ipv6_udp(struct sk_buff *skb, struct nf_conntrack_tuple *tuple)
{
    struct bib_entry *bib_entry_p = NULL;
    struct session_entry *session_entry_p = NULL;
    struct ipv4_tuple_address new_ipv4_transport_address;
    struct ipv4_tuple_address ipv4_remote; // ( Z(Y'), y)
    struct ipv6_tuple_address ipv6_ta; // Transport Address temporal var.
    struct ipv4_pair pair4;
    struct ipv6_pair pair6;
    u_int8_t protocol;
    bool bib_is_local;
    
    protocol = IPPROTO_UDP;
    bib_is_local = false;

    // Pack source address into transport address
    transport_address_ipv6(tuple->ipv6_src_addr, tuple->src_port, &ipv6_ta);

    // Check if a previous BIB entry exist, look for IPv6 source transport address (X’,x).
    spin_lock_bh(&bib_session_lock);
    bib_entry_p = nat64_get_bib_entry_by_ipv6( &ipv6_ta, protocol );

    // If not found, try to create a new one.
    if ( bib_entry_p == NULL )
    {
        // TODO:    Define the checks that evaluate if resources availability
        //          and policy allows the creation of a new entry.

        // Find a similar transport address (T, t)
        if ( !allocate_ipv4_transport_address(tuple, protocol, &new_ipv4_transport_address) ) {
            send_icmp_error_message(skb, DESTINATION_UNREACHABLE, ADDRESS_UNREACHABLE);
            log_info("Could NOT allocate a new IPv4 transport address for a incoming IPv6 UDP packet.");
            goto failure;
        }

        // Create the BIB entry
        bib_entry_p = nat64_create_bib_entry(&new_ipv4_transport_address, &ipv6_ta);
        if ( bib_entry_p == NULL ) {
            send_icmp_error_message(skb, DESTINATION_UNREACHABLE, ADDRESS_UNREACHABLE);
            log_warning("Could NOT create a new BIB entry for a incoming IPv6 UDP packet.");
            goto failure;
        }

        bib_is_local = true;
            
        // Add the BIB entry
        if (!nat64_add_bib_entry( bib_entry_p, protocol)) {
            log_warning("Could NOT add a new BIB entry for a incoming IPv6 UDP packet.");
            goto failure;
        }
    }

    // Once we have a BIB entry do ...
    
    session_entry_p = nat64_get_session_entry( tuple );

    // If session was not found, then try to create a new one.
    if ( session_entry_p == NULL )
    {
        // TODO:    Define the checks that evaluate if resources availability 
        //          and policy allows the creation of a new entry.

        // Translate address
        if ( !extract_ipv4(&tuple->ipv6_dst_addr, &ipv4_remote.address) ) // Z(Y')
        {
            log_warning("Could NOT extract IPv4 from IPv6 destination address while creating a SESSION entry.");
            goto failure;
        }
        ipv4_remote.l4_id = be16_to_cpu(tuple->dst_port); // y

        // Create the session entry
        pair6.remote.address = tuple->ipv6_src_addr; // X'
        pair6.remote.l4_id = be16_to_cpu(tuple->src_port); // x
        pair6.local.address = tuple->ipv6_dst_addr; // Y'
        pair6.local.l4_id = be16_to_cpu(tuple->dst_port); // y
        pair4.local = bib_entry_p->ipv4; // (T, t)
        pair4.remote = ipv4_remote; // (Z, z) // (Z(Y’),y)
        session_entry_p = nat64_create_session_entry(&pair4, &pair6, bib_entry_p, protocol);
        if ( session_entry_p == NULL )
        {
            log_warning("Could NOT create a new SESSION entry for a incoming IPv6 UDP packet.");
            goto failure;
        }

        // Add the session entry
        if ( !nat64_add_session_entry(session_entry_p) )
        {            
            log_warning("Could NOT add a new session entry for a incoming IPv6 UDP packet.");
            goto failure;
        }
    }
    
    // Reset session entry's lifetime.
    update_session_lifetime(session_entry_p, &config.to.udp); 
    spin_unlock_bh(&bib_session_lock);

    return NF_ACCEPT;

failure:
    kfree(session_entry_p);
    if ( bib_entry_p )
        nat64_remove_bib_entry(bib_entry_p, protocol);
    if ( bib_is_local )
        kfree(bib_entry_p);
    spin_unlock_bh(&bib_session_lock);

    return NF_DROP;
}

/**
 *  Process an incoming UDP packet, with an incoming tuple with source IPv4 transport
 *  address (W,w) and destination IPv4 transport address (T,t)
 *  Second half of rfc 6146 section 3.5.1.
 * 
 * @param[in]   tuple   Tuple obtained from incoming packet
 * @return  NF_ACCEPT if everything went OK, NF_DROP otherwise.
 */
int ipv4_udp(struct sk_buff* skb, struct nf_conntrack_tuple *tuple)
{
    struct bib_entry *bib_entry_p = NULL;
    struct session_entry *session_entry_p = NULL;
    struct ipv6_tuple_address ipv6_local; 
    struct ipv4_tuple_address ipv4_ta;
    struct ipv4_pair pair4;
    struct ipv6_pair pair6;
    u_int8_t protocol;
    
    protocol = IPPROTO_UDP;

    // Pack source address into transport address
    transport_address_ipv4( tuple->ipv4_dst_addr,tuple->dst_port, &ipv4_ta );

    // Check if a previous BIB entry exist, look for IPv4 destination transport address (T,t).
    spin_lock_bh(&bib_session_lock);
    bib_entry_p = nat64_get_bib_entry_by_ipv4( &ipv4_ta, protocol );

    // If not found, try to create a new one.
    if ( bib_entry_p == NULL )
    {
        // TODO:    Define the checks that evaluate if resources availability
        //          and policy allows the creation of a new entry.
        log_warning("A BIB entry does NOT exist for a incoming IPv4 UDP packet.");
        goto icmp_and_fail;
    }
    
    if ( address_dependent_filtering() && !nat64_is_allowed_by_address_filtering(tuple) )
    {
        log_warning("Packet was blocked by address-dependent filtering.");
        icmp_send(skb, DESTINATION_UNREACHABLE, COMMUNICATION_ADMINISTRATIVELY_PROHIBITED, 0);
        goto failure;
    }

    // Searches for the Session Table Entry corresponding to the incoming tuple->
    session_entry_p = nat64_get_session_entry( tuple );
    
    // If NO session was found:
    if ( session_entry_p == NULL )
    {
        // TODO:    Define the checks that evaluate if resources availability 
        //          and policy allows the creation of a new entry.
    
        // Translate address
        if ( !append_ipv4(&tuple->ipv4_src_addr, &ipv6_local.address) ) // Y’(W)
        {
            log_warning("Address translation failed.");
            goto icmp_and_fail;
        }
        ipv6_local.l4_id = be16_to_cpu(tuple->src_port); // w

        // Create the session entry
        pair6.remote = bib_entry_p->ipv6;   // (X', x)
        pair6.local = ipv6_local;           // (Y’(W), w)
        pair4.local.address = tuple->ipv4_dst_addr; // T
        pair4.local.l4_id = be16_to_cpu(tuple->dst_port); // t
        pair4.remote.address = tuple->ipv4_src_addr; // W
        pair4.remote.l4_id = be16_to_cpu(tuple->src_port); // w
        session_entry_p = nat64_create_session_entry(&pair4, &pair6, bib_entry_p, protocol);
        if ( session_entry_p == NULL )
        {
            log_warning("Could NOT create a new SESSION entry for a incoming IPv4 UDP packet.");
            goto icmp_and_fail;
        }

        // Add the session entry
        if ( !nat64_add_session_entry(session_entry_p) )
        {
            log_warning("Could NOT add a new session entry for a incoming IPv4 UDP packet.");
            goto icmp_and_fail;
        }
    }
    
    update_session_lifetime(session_entry_p, &config.to.udp);
    spin_unlock_bh(&bib_session_lock);
        
    return NF_ACCEPT;

icmp_and_fail:
    icmp_send(skb, DESTINATION_UNREACHABLE, ADDRESS_UNREACHABLE, 0);
    // Fall through.
failure:
    kfree(session_entry_p);
    if ( bib_entry_p )
        nat64_remove_bib_entry(bib_entry_p, protocol);
    kfree(bib_entry_p);
    spin_unlock_bh(&bib_session_lock);
    return NF_DROP;
}

/** Process an incoming ICMPv6 Informational packet, which has an incoming 
 *  tuple with IPv6 source address (X’), IPv6 destination address (Y’), and 
 *  ICMPv6 Identifier (i1)
 *  First half of rfc 6146 section 3.5.3
 * 
 * @param[in]   tuple   Tuple obtained from incoming packet
 * @return  NF_ACCEPT if everything went OK, NF_DROP otherwise.
 */
int ipv6_icmp6(struct sk_buff *skb, struct nf_conntrack_tuple *tuple)
{
    struct bib_entry *bib_entry_p = NULL;
    struct session_entry *session_entry_p = NULL;
    struct ipv4_tuple_address new_ipv4_transport_address;
    struct ipv6_tuple_address ipv6_source;
    struct ipv4_pair pair4;
    struct ipv6_pair pair6;

    struct in_addr ipv4_remote_address;
    u_int8_t protocol;
    bool bib_is_local = false;
    
    protocol = IPPROTO_ICMP;
    ipv4_remote_address.s_addr = 0x00000000; // TODO ver este warning
    
    if ( filter_icmpv6_info() )
    {
        return NF_DROP;
    }

    // Pack source address into transport address
    transport_address_ipv6( tuple->ipv6_src_addr, tuple->icmp_id, &ipv6_source );
    
    // Search for an ICMPv6 Query BIB entry that matches the (X’,i1) pair.
    spin_lock_bh(&bib_session_lock);
    bib_entry_p = nat64_get_bib_entry_by_ipv6( &ipv6_source, protocol );

    // If not found, try to create a new one.
    if ( bib_entry_p == NULL )
    {
        // TODO:    Define the checks that evaluate if resources availability 
        //          and policy allows the creation of a new entry.

        // Look in the BIB tables for a previous packet from the same origin (X')
        if (!allocate_ipv4_transport_address_digger(tuple, IPPROTO_ICMP, &new_ipv4_transport_address))
        {
            log_warning("Could NOT get a valid ICMPv4 identifier for a incoming IPv6 ICMP packet.");
            goto icmp_and_fail;
        }

        // Create the BIB entry
        bib_entry_p = nat64_create_bib_entry(&new_ipv4_transport_address, &ipv6_source);
        if ( bib_entry_p == NULL ) {
            log_warning("Could NOT create a new BIB entry for a incoming IPv6 ICMP packet.");
            goto icmp_and_fail;
        }

        bib_is_local = true;

        // Add the new BIB entry
        if ( !nat64_add_bib_entry(bib_entry_p, protocol) )
        {
            log_warning("NAT64:  Could NOT add a new BIB entry for a incoming IPv6 ICMP packet.");
            goto icmp_and_fail;
        }
    }

    // OK, we have a BIB entry to work with...

    /* Searche for an ICMP Query Session Table Entry corresponding to the incoming 
       3-tuple (X’,Y’,i1).  */
    session_entry_p = nat64_get_session_entry( tuple );

    // If NO session was found:
    if ( session_entry_p == NULL )
    {
        // TODO:    Define the checks that evaluate if resources availability 
        //          and policy allows the creation of a new entry.

        // Translate address from IPv6 to IPv4
        if ( !extract_ipv4(&tuple->ipv6_dst_addr, &ipv4_remote_address) ) // Z(Y')
        {
            log_warning("Could NOT extract IPv4 from IPv6 destination address while creating a SESSION entry.");
            goto icmp_and_fail;
        }

        // Create the session entry
        pair6.remote.address = tuple->ipv6_src_addr;      // (X')
        pair6.remote.l4_id = be16_to_cpu(tuple->icmp_id); // (i1)
        pair6.local.address = tuple->ipv6_dst_addr;       // (Y')
        pair6.local.l4_id = be16_to_cpu(tuple->icmp_id);  // (i1)
        pair4.local = bib_entry_p->ipv4;                  // (T, i2)
        pair4.remote.address = ipv4_remote_address;       // (Z(Y’))
        pair4.remote.l4_id = bib_entry_p->ipv4.l4_id;     // (i2)
        session_entry_p = nat64_create_session_entry(&pair4, &pair6, bib_entry_p, protocol);
        if ( session_entry_p == NULL )
        {
            log_warning("Could NOT create a new SESSION entry for a incoming IPv4 UDP packet.");
            goto icmp_and_fail;
        }

        // Add the session entry
        if ( !nat64_add_session_entry( session_entry_p ) )
        {
            log_warning("Could NOT add a new session entry for a incoming IPv6 ICMP packet.");
            goto icmp_and_fail;
        }
    }
    
    // Reset session entry's lifetime.
    update_session_lifetime(session_entry_p, &config.to.icmp);
    spin_unlock_bh(&bib_session_lock);

    return NF_ACCEPT;

icmp_and_fail:
    icmp_send(skb, DESTINATION_UNREACHABLE, ADDRESS_UNREACHABLE, 0);

    kfree(session_entry_p);
    if ( bib_entry_p )
        nat64_remove_bib_entry(bib_entry_p, protocol);
    if ( bib_is_local )
        kfree(bib_entry_p);
    spin_unlock_bh(&bib_session_lock);
    return NF_DROP;
}

/** Process an incoming ICMPv4 Query packet with source IPv4 address (Y), destination 
 *  IPv4 address (X), and ICMPv4 Identifier (i2)
 *  Second half of rfc 6146 section 3.5.3
 * 
 * @param[in]   tuple   Tuple obtained from incoming packet
 * @return  NF_ACCEPT if everything went OK, NF_DROP otherwise.
 */
int ipv4_icmp4(struct sk_buff* skb, struct nf_conntrack_tuple *tuple)
{
    struct bib_entry *bib_entry_p = NULL;
    struct session_entry *session_entry_p = NULL;
    struct in6_addr ipv6_remote;
    struct ipv4_tuple_address ipv4_ta;
    struct ipv4_pair pair4;
    struct ipv6_pair pair6;
    
    u_int8_t protocol;
    
    protocol = IPPROTO_ICMP;

    // Pack source address into transport address
    transport_address_ipv4( tuple->ipv4_dst_addr, tuple->icmp_id, &ipv4_ta );
    
    // Look for a previous BIB entry that contains (X) as the IPv4 address and (i2) as the ICMPv4 Identifier.
    spin_lock_bh(&bib_session_lock);
    bib_entry_p = nat64_get_bib_entry_by_ipv4( &ipv4_ta, protocol );

    // If such an entry does not exist,
    if ( bib_entry_p == NULL )
    {   
        // TODO: Does the policy allow us to send this packet?
        icmp_send(skb, DESTINATION_UNREACHABLE, HOST_UNREACHABLE, 0);
        log_warning("A BIB entry does NOT exist for a incoming IPv4 ICMP packet.");
        goto failure;
    }

    // If we're applying address-dependent filtering in the IPv4 interface,
    if ( address_dependent_filtering() && !nat64_is_allowed_by_address_filtering(tuple) )
    {
        icmp_send(skb, DESTINATION_UNREACHABLE, COMMUNICATION_ADMINISTRATIVELY_PROHIBITED, 0);
        log_warning("Packet filtered by address-dependent filtering.");
        goto failure;
    }

    // Search the Session Table Entry corresponding to the incoming tuple
    session_entry_p = nat64_get_session_entry( tuple );
    
    // If NO session was found:
    if ( session_entry_p == NULL )
    {
        // TODO:    Define the checks that evaluate if resources availability 
        //          and policy allows the creation of a new entry.
    
        // Translation the address
        if ( !append_ipv4(&tuple->ipv4_src_addr, &ipv6_remote) ) // Y’(Z)
        {
            log_warning("Could NOT translate IPv4 on IPv6, while creating a SESSION entry for a IPv4 ICMP packet.");
            goto icmp_and_fail;
        }

        // Create the session entry.
        // TODO revisar estos valores; por ahí habían cosas locales mezcladas con remotas.
        pair6.remote.address = bib_entry_p->ipv6.address; // X'
        pair6.remote.l4_id = bib_entry_p->ipv6.l4_id; // i1
        pair6.local.address = ipv6_remote; // Y'(Z)
        pair6.local.l4_id = bib_entry_p->ipv6.l4_id; // i1
        pair4.local.address = tuple->ipv4_dst_addr; // T
        pair4.local.l4_id = be16_to_cpu(tuple->icmp_id); // i2
        pair4.remote.address = tuple->ipv4_src_addr; // Z
        pair4.remote.l4_id = be16_to_cpu(tuple->icmp_id); // i2
        session_entry_p = nat64_create_session_entry(&pair4, &pair6, bib_entry_p, protocol);
        if ( session_entry_p == NULL )
        {
            log_warning("Could NOT create a new SESSION entry for a incoming IPv4 ICMP packet.");
            goto icmp_and_fail;
        }

        // Add the session entry
        if ( !nat64_add_session_entry(session_entry_p) )
        {
            log_warning("Could NOT add a new session entry for a incoming IPv4 ICMP packet.");
            goto icmp_and_fail;
        }
    }

    // Reset session entry's lifetime.
    update_session_lifetime(session_entry_p, &config.to.icmp);
    spin_unlock_bh(&bib_session_lock);

    return NF_ACCEPT;

icmp_and_fail:
    icmp_send(skb, DESTINATION_UNREACHABLE, ADDRESS_UNREACHABLE, 0);
    // Fall through.

failure:
    kfree(session_entry_p);
    if ( bib_entry_p )
        nat64_remove_bib_entry(bib_entry_p, protocol);
    kfree(bib_entry_p);
    spin_unlock_bh(&bib_session_lock);
    return NF_DROP;
}


/*********************************************
 **                                         **
 **     TCP SECTION                         **
 **                                         **
 *********************************************/

/** TCP States definition. */
enum {  CLOSED = 0,
        ESTABLISHED,
        TRANS,
        V4_FIN_RCV,
        V4_INIT,
        V6_FIN_RCV,
        V4_FIN_V6_FIN_RCV,
        V6_INIT
};

/** CLOSED state
 *
 *  Handle SYN packets.
 *
 *  The motivation for this is to support simultaneous open of TCP connections.
 *
 * @param[in]   packet  The incoming packet.
 * @param[in]   tuple   Tuple of the incoming packet.
 * @return  NF_ACCEPT if everything went OK, NF_DROP otherwise.
 */
int tcp_closed_state_handle(struct sk_buff* skb, struct nf_conntrack_tuple *tuple)
{
    struct bib_entry *bib_entry_p = NULL;
    struct session_entry *session_entry_p = NULL;

    struct ipv4_tuple_address new_ipv4_transport_address;
    struct ipv6_tuple_address ipv6_ta;
    struct ipv4_tuple_address ipv4_ta;

    struct ipv4_tuple_address ipv4_remote;
    struct ipv6_tuple_address ipv6_local;
    struct ipv6_pair pair6;
    struct ipv4_pair pair4;
    u_int8_t protocol;
    bool bib_is_local = false;

    protocol = IPPROTO_TCP;

    // For any packet, other than SYN, belonging to this connection:
    if ( !packet_is_v4_syn(skb) && !packet_is_v6_syn(skb) )
    {
        // Pack source address into transport address
        transport_address_ipv6( tuple->ipv6_dst_addr, tuple->dst_port, &ipv6_ta );

        // Look if there is a corresponding entry in the TCP BIB
        spin_lock_bh(&bib_session_lock);
        bib_entry_p = nat64_get_bib_entry_by_ipv6( &ipv6_ta, protocol );
        spin_unlock_bh(&bib_session_lock);
        return ( bib_entry_p == NULL ) ? NF_DROP : NF_ACCEPT;
    }
    
    //  V6 SYN packet: IPv6 -> IPv4
    if ( packet_is_v6_syn(skb) )
    {
        // Pack source address into transport address
        transport_address_ipv6( tuple->ipv6_src_addr, tuple->src_port, &ipv6_ta );
        
        // Check if a previous BIB entry exist, look for IPv6 source transport address (X’,x).
        spin_lock_bh(&bib_session_lock);
        bib_entry_p = nat64_get_bib_entry_by_ipv6( &ipv6_ta, protocol );

        // If bib does not exist, try to create a new one,
        if ( bib_entry_p == NULL )
        {
            /* TODO: Define if resources and policy permit the creation of a BIB entry*/            

            // Obtain a new BIB IPv4 transport address (T,t), put it in new_ipv4_transport_address.
            if ( !allocate_ipv4_transport_address_digger(tuple, protocol, &new_ipv4_transport_address) )
            {
                icmpv6_send(skb, DESTINATION_UNREACHABLE, ADDRESS_UNREACHABLE, 0);
                log_warning("CLOSED State. Could NOT allocate a new IPv4 transport address for an incoming IPv6 packet.");
                goto failure;
            }

            // Create the BIB entry
            bib_entry_p = nat64_create_bib_entry(&new_ipv4_transport_address, &ipv6_ta);
            if ( bib_entry_p == NULL ) {
                icmpv6_send(skb, DESTINATION_UNREACHABLE, ADDRESS_UNREACHABLE, 0);
                log_warning("CLOSED State. Could NOT create a new BIB entry for an incoming IPv6 TCP packet.");
                goto failure;
            }
            bib_is_local = true;

            // Add the new BIB entry
            if ( !nat64_add_bib_entry( bib_entry_p, protocol) )
            {
                icmpv6_send(skb, DESTINATION_UNREACHABLE, ADDRESS_UNREACHABLE, 0);
                log_warning("CLOSED State. Could NOT add a new BIB entry for an incoming IPv6 TCP packet.");
                goto failure;
            }
        }

        // Now that we have a BIB entry...

        // Translate address
        if ( !extract_ipv4(&tuple->ipv6_dst_addr, &ipv4_remote.address) ) // Z(Y')
        {
            log_warning("CLOSED State. Could NOT extract IPv4 from IPv6 destination address.");
            goto icmp_and_fail;
        }
        ipv4_remote.l4_id = be16_to_cpu(tuple->dst_port); // y

        // Create the session entry.
        // TODO:     What about of checking Policy and Resources for the creation of a STE.
        pair6.remote.address = tuple->ipv6_src_addr; // X'
        pair6.remote.l4_id = be16_to_cpu(tuple->src_port); // x
        pair6.local.address = tuple->ipv6_dst_addr; // Y'
        pair6.local.l4_id = be16_to_cpu(tuple->dst_port); // y
        pair4.local = bib_entry_p->ipv4; // (T, t)
        pair4.remote = ipv4_remote; // (Z, z) // (Z(Y’),y)
        session_entry_p = nat64_create_session_entry(&pair4, &pair6, bib_entry_p, protocol);
        if ( session_entry_p == NULL )
        {
            log_warning("Could NOT create a new SESSION entry for a incoming IPv4 ICMP packet.");
            goto icmp_and_fail;
        }

        update_session_lifetime(session_entry_p, &config.to.tcp_trans);
        session_entry_p->current_state = V6_INIT;

        if ( !nat64_add_session_entry(session_entry_p) )
        {
            log_warning("CLOSED State. Could NOT add a new session entry for an incoming IPv6 UDP packet.");
            goto icmp_and_fail;
        }
        spin_unlock_bh(&bib_session_lock);
    }
    else if ( packet_is_v4_syn(skb) )
    {
        if ( drop_external_connections() )
        {
            pr_debug("NAT64: Applying policy: Drop externally initiated TCP connections.");
            return NF_DROP;
        }

        // Pack addresses and ports into transport address
        transport_address_ipv4( tuple->ipv4_dst_addr, tuple->dst_port, &ipv4_ta );

        // Look for the destination transport address (X,x) in the BIB 
        spin_lock_bh(&bib_session_lock);
        bib_entry_p = nat64_get_bib_entry_by_ipv4( &ipv4_ta, protocol );

        // TODO:    Define the checks that evaluate if resources availability 
        //          and policy allows the creation of a new entry.
        // If not found (not in use), even try to create a new SESSION entry!!!
        if ( bib_entry_p == NULL )
        {           
//            /*  Side:   <-------- IPv6 -------->  N  <------- IPv4 ------->
//                Packet: dest(X',x) <-- src(Y',y)  A  dest(X,x) <-- src(Y,y)
//                NAT64:    remote       local      T    local        remote
//            */
//
//            // Try to create a new Session Entry
//
//            // Allocate memory for a new Session entry
//            session_entry_p = (struct session_entry *) kmalloc( sizeof(struct session_entry), GFP_ATOMIC );
//            if (session_entry_p == NULL)
//            {
//                pr_warning("NAT64:  CLOSED State. Could NOT create a new SESSION entry for an incoming IPv4 TCP packet.");
//                pr_warning("        Dropping packet.");
//
//                // TODO: Should we delete the previously created BIB entry ????
//                nat64_remove_bib_entry( bib_entry_p, protocol);
//                return NF_DROP;
//            }
//
//            // Translate address from IPv4 to IPv6
//            ret = embed_ipv4_in_ipv6(tuple->ipv4_src_addr, &ipv6_local.address); // Y'(Y)
//            if (ret == false)
//            {
//                pr_warning("NAT64:  CLOSED State. Could NOT embed IPv4 in IPv6 destination address,");
//                pr_warning("        while creating a SESSION entry. Dropping packet.");
//
//                return NF_DROP;
//            }
//            ipv6_local.l4_id = be16_to_cpu(tuple->src_port); // y
//
//            // Pack addresses and ports into transport address
//            transport_address_ipv4( tuple->ipv4_dst_addr, tuple->dst_port, &ipv4_ta_local );
//            transport_address_ipv4( tuple->ipv4_src_addr, tuple->src_port, &ipv4_ta_remote );
//
//            // Fill the session entry
//            session_entry_p->ipv4.local = ipv4_ta_local; // (X, x)  (T, t)
//            session_entry_p->ipv4.remote = ipv4_ta_remote; // (Z(Y’),y) ; // (Z, z)
//
//            // session_entry_p->ipv6.remote = Not_Available; // (X', x) INTENTIONALLY LEFT UNSPECIFIED!
//            session_entry_p->ipv6.local = ipv6_local; // (Y', y)
//
//            session_entry_p->l4protocol = protocol; //
//
//            session_entry_p->current_state = V4_INIT;
//
//            session_entry_p->bib = bib_entry_p;     // Owner bib_entry of this session.
//            session_entry_p->is_static = false;     // This is a dynamic entry.
//
//            update_session_lifetime(session_entry_p, TCP_INCOMING_SYN);
//
//            /* TODO:    The packet is stored !!!
//             *          The result is that the NAT64 will not drop the packet based on the filtering,
//             *          nor create a BIB entry.  Instead, the NAT64 will only create the Session
//             *          Table Entry and store the packet. The motivation for this is to support
//             *          simultaneous open of TCP connections. */
        }
        else // if a bib entry exists
        {
            // TODO:    Define the checks that evaluate if resources availability 
            //          and policy allows the creation of a new entry.

            // Translate address
            if ( !append_ipv4(&tuple->ipv4_src_addr, &ipv6_local.address) ) // Y'(Y)
            {
                log_warning("CLOSED State. Could NOT embed IPv4 in IPv6 destination address.");
                return NF_DROP;
            }
            ipv6_local.l4_id = be16_to_cpu(tuple->src_port); // y

            // Create the session entry
            pair6.remote = bib_entry_p->ipv6; // (X', x)
            pair6.local = ipv6_local; // (Y', y)
            pair4.local.address = tuple->ipv4_dst_addr; // (X, x)  (T, t)
            pair4.local.l4_id = be16_to_cpu(tuple->dst_port);
            pair4.remote.address = tuple->ipv4_src_addr; // (Z(Y’),y) ; // (Z, z)
            pair4.remote.l4_id = be16_to_cpu(tuple->src_port);
            session_entry_p = nat64_create_session_entry(&pair4, &pair6, bib_entry_p, protocol);
            if ( session_entry_p == NULL )
            {
                log_warning("Could NOT create a new SESSION entry for a incoming IPv4 ICMP packet.");
                goto icmp_and_fail;
            }
            session_entry_p->current_state = V4_INIT;

            if ( address_dependent_filtering() ) {
                unsigned int temp = TCP_INCOMING_SYN;
                update_session_lifetime(session_entry_p, &temp);
            } else {
                update_session_lifetime(session_entry_p, &config.to.tcp_trans);
            }
        }

        if ( !nat64_add_session_entry(session_entry_p) )
        {
            log_warning("CLOSED State. Could NOT add a new session entry for an incoming IPv4 TCP packet.");
            goto icmp_and_fail;
        }
        spin_unlock_bh(&bib_session_lock);
    }

    return NF_ACCEPT;

icmp_and_fail:
    icmp_send(skb, DESTINATION_UNREACHABLE, ADDRESS_UNREACHABLE, 0);
    // Fall through.

failure:
    kfree(session_entry_p);
    if ( bib_entry_p )
        nat64_remove_bib_entry(bib_entry_p, protocol);
    if ( bib_is_local )
        kfree(bib_entry_p);
    spin_unlock_bh(&bib_session_lock);
    return NF_DROP;
}

/** V4 INIT state
 * 
 * Handle IPv6 SYN packets.
 *
 * @param[in]   tuple   Tuple of the incoming packet, source (X’,x) and destination (Y’,y).
 * @return  NF_ACCEPT if everything went OK, NF_DROP otherwise.
 */
int tcp_v4_init_state_handle(struct sk_buff* skb, struct nf_conntrack_tuple *tuple)
{
    if ( packet_is_v6_syn(skb) )
    {
        struct session_entry *session_entry_p;
        
        spin_lock_bh(&bib_session_lock);
        session_entry_p = nat64_get_session_entry( tuple );
        
        if ( session_entry_p == NULL )
        {
            log_warning("V4 INIT state. Could NOT find an existing SESSION entry for an incoming V6 SYN packet.");
            spin_unlock_bh(&bib_session_lock);
            return NF_DROP;
        }

        update_session_lifetime(session_entry_p, &config.to.tcp_est);
        nat64_update_session_state(session_entry_p, ESTABLISHED);
        spin_unlock_bh(&bib_session_lock);
    } // else, the state remains unchanged.

    return NF_ACCEPT;
}

/** V6 INIT state.
 * 
 * Handle IPv4 & IPv6 SYN packets.
 *
 * @param[in]   tuple   Tuple of the incoming packet, source (Y,y) and destination (X,x).
 * @return  NF_ACCEPT if everything went OK, NF_DROP otherwise.
 */
int tcp_v6_init_state_handle(struct sk_buff* skb, struct nf_conntrack_tuple *tuple)
{
    struct session_entry *session_entry_p;

    if (packet_is_v4_syn(skb))
    {
        spin_lock_bh(&bib_session_lock);
        session_entry_p = nat64_get_session_entry( tuple );
        
        if ( session_entry_p == NULL )
        {
            log_warning("V6 INIT state. Could NOT find an existing SESSION entry for an incoming V4 SYN packet.");
            spin_unlock_bh(&bib_session_lock);
            return NF_DROP;
        }

        update_session_lifetime(session_entry_p, &config.to.tcp_est);
        nat64_update_session_state(session_entry_p, ESTABLISHED);
        spin_unlock_bh(&bib_session_lock);
    }
    else if (packet_is_v6_syn(skb))
    {
        spin_lock_bh(&bib_session_lock);
        session_entry_p = nat64_get_session_entry( tuple );

        if ( session_entry_p == NULL )
        {
            log_warning("V6 INIT state. Could NOT find an existing SESSION entry for an incoming V6 SYN packet.");
            spin_unlock_bh(&bib_session_lock);
            return NF_DROP;
        }

        update_session_lifetime(session_entry_p, &config.to.tcp_trans);
        spin_unlock_bh(&bib_session_lock);
    } // else, the state remains unchanged
    
    return NF_ACCEPT;
}

/** ESTABLISHED state.
 * 
 * Handles V4 FIN, V6 FIN, V4 RST, & V6 RST packets.
 *
 * @param[in]   tuple   Tuple of the incoming packet.
 * @return  NF_ACCEPT if everything went OK, NF_DROP otherwise.
 */
int tcp_established_state_handle(struct sk_buff* skb, struct nf_conntrack_tuple *tuple)
{
    struct session_entry *session_entry_p;

    if ( packet_is_v4_fin(skb) )
    {
        spin_lock_bh(&bib_session_lock);
        session_entry_p = nat64_get_session_entry( tuple );
        
        if ( session_entry_p == NULL )
        {
            log_warning("ESTABLISHED state. Could NOT find an existing SESSION entry for an incoming V4 FIN packet.");
            spin_unlock_bh(&bib_session_lock);
            return NF_DROP;
        }

        nat64_update_session_state(session_entry_p, V4_FIN_RCV);
        spin_unlock_bh(&bib_session_lock);
    }
    else if ( packet_is_v6_fin(skb) )
    {
        spin_lock_bh(&bib_session_lock);
        session_entry_p = nat64_get_session_entry( tuple );
        
        if ( session_entry_p == NULL )
        {
            log_warning("ESTABLISHED state. Could NOT find an existing SESSION entry for an incoming V4 FIN packet.");
            spin_unlock_bh(&bib_session_lock);
            return NF_DROP;
        }

        nat64_update_session_state(session_entry_p, V6_FIN_RCV);
        spin_unlock_bh(&bib_session_lock);
    }
    else if ( packet_is_v4_rst(skb) ||  packet_is_v6_rst(skb) )
    {
        spin_lock_bh(&bib_session_lock);
        session_entry_p = nat64_get_session_entry( tuple );
        
        if ( session_entry_p == NULL )
        {
            log_warning("ESTABLISHED state. Could NOT find an existing SESSION entry for an incoming V4 FIN packet.");
            spin_unlock_bh(&bib_session_lock);
            return NF_DROP;
        }

        update_session_lifetime(session_entry_p, &config.to.tcp_trans);
        nat64_update_session_state(session_entry_p, TRANS);
        spin_unlock_bh(&bib_session_lock);
    }
    else
    {
        spin_lock_bh(&bib_session_lock);
        session_entry_p = nat64_get_session_entry( tuple );
        
        if ( session_entry_p == NULL )
        {
            log_warning("ESTABLISHED state. Could NOT find an existing SESSION entry for an incoming other packet.");
            spin_unlock_bh(&bib_session_lock);
            return NF_DROP;
        }

        update_session_lifetime(session_entry_p, &config.to.tcp_est);
        spin_unlock_bh(&bib_session_lock);
    }
    return NF_ACCEPT;
}

/** V4 FIN RCV state.
 * 
 * Handles V6 FIN packets.
 *
 * @param[in]   tuple   Tuple of the incoming packet.
 * @return  NF_ACCEPT if everything went OK, NF_DROP otherwise.
 */
int tcp_v4_fin_rcv_state_handle(struct sk_buff* skb, struct nf_conntrack_tuple *tuple)
{
    struct session_entry *session_entry_p;

    if ( packet_is_v6_fin(skb) )
    {        
        spin_lock_bh(&bib_session_lock);
        session_entry_p = nat64_get_session_entry( tuple );
        
        if ( session_entry_p == NULL )
        {
            log_warning("V4 FIN RCV state. Could NOT find an existing SESSION entry for an incoming V6 FIN packet.");
            spin_unlock_bh(&bib_session_lock);
            return NF_DROP;
        }

        update_session_lifetime(session_entry_p, &config.to.tcp_trans);
        nat64_update_session_state(session_entry_p, V4_FIN_V6_FIN_RCV);
        spin_unlock_bh(&bib_session_lock);
    }
    else
    {
        spin_lock_bh(&bib_session_lock);
        session_entry_p = nat64_get_session_entry( tuple );
        
        if ( session_entry_p == NULL )
        {
            log_warning("V4 FIN RCV state. Could NOT find an existing SESSION entry for an incoming other packet.");
            spin_unlock_bh(&bib_session_lock);
            return NF_DROP;
        }

        update_session_lifetime(session_entry_p, &config.to.tcp_est);
        spin_unlock_bh(&bib_session_lock);
    }
    return NF_ACCEPT;    
}

/** V6 FIN RCV state.
 * 
 * Handles V4 FIN packets.
 *
 * @param[in]   tuple   Tuple of the incoming packet.
 * @return  NF_ACCEPT if everything went OK, NF_DROP otherwise.
 */
int tcp_v6_fin_rcv_state_handle(struct sk_buff* skb, struct nf_conntrack_tuple *tuple)
{
    struct session_entry *session_entry_p;
    
    if ( packet_is_v4_fin(skb) )
    {        
        spin_lock_bh(&bib_session_lock);
        session_entry_p = nat64_get_session_entry( tuple );
        
        if ( session_entry_p == NULL )
        {
            log_warning("V6 FIN RCV state. Could NOT find an existing SESSION entry for an incoming V4 FIN packet.");
            spin_unlock_bh(&bib_session_lock);
            return NF_DROP;
        }

        update_session_lifetime(session_entry_p, &config.to.tcp_trans);
        nat64_update_session_state(session_entry_p, V4_FIN_V6_FIN_RCV);
        spin_unlock_bh(&bib_session_lock);
    }
    else
    {
        spin_lock_bh(&bib_session_lock);
        session_entry_p = nat64_get_session_entry( tuple );
        
        if ( session_entry_p == NULL )
        {
            log_warning("V6 FIN RCV state. Could NOT find an existing SESSION entry for an incoming other packet.");
            spin_unlock_bh(&bib_session_lock);
            return NF_DROP;
        }

        update_session_lifetime(session_entry_p, &config.to.tcp_est);
        spin_unlock_bh(&bib_session_lock);
    }
    return NF_ACCEPT;    
}

/** V6 FIN + V4 FIN RCV state.
 * 
 * Handles all packets.
 *
 * @param[in]   tuple   Tuple of the incoming packet.
 * @return  NF_ACCEPT if everything went OK, NF_DROP otherwise.
 */
int tcp_v4_fin_v6_fin_rcv_state_handle(struct sk_buff* skb, struct nf_conntrack_tuple *tuple)
{
    // Only the timeout can switch this state.
    return NF_ACCEPT;
}

/** TRANS state.
 * 
 * Handles not RST packets.
 *
 * @param[in]   tuple   Tuple of the incoming packet.
 * @return  NF_ACCEPT if everything went OK, NF_DROP otherwise.
 */
int tcp_trans_state_handle(struct sk_buff* skb, struct nf_conntrack_tuple *tuple)
{
    struct session_entry *session_entry_p = NULL;
    
    if ( !packet_is_v4_rst(skb) && !packet_is_v6_rst(skb) )
    {
        spin_lock_bh(&bib_session_lock);
        session_entry_p = nat64_get_session_entry( tuple );
        
        if ( session_entry_p == NULL )
        {
            pr_warning("V6 FIN RCV state. Could NOT find an existing SESSION entry for an incoming V4 FIN packet.");
            spin_unlock_bh(&bib_session_lock);
            return NF_DROP;
        }

        update_session_lifetime(session_entry_p, &config.to.tcp_est);
        nat64_update_session_state(session_entry_p, ESTABLISHED);
        spin_unlock_bh(&bib_session_lock);
    }

    return NF_ACCEPT;    
}

/** 
 * 
 *  
 * @param[in]   session_entry   The entry whose lifetime just expired.
 * @return TRUE: keep STE, FALSE: remove STE.
 * */
bool session_expired(struct session_entry *session_entry_p)
{		
	switch(session_entry_p->l4protocol) {
		case IPPROTO_UDP:
			return false;
		case IPPROTO_ICMP:
		case IPPROTO_ICMPV6:
			return false;
		case IPPROTO_TCP:
			switch( session_entry_p->current_state )
			{
				case CLOSED:
					return false;
				case V4_INIT:
					/* TODO:
					 * If the lifetime expires, an ICMP Port Unreachable error (Type 3, Code 3) containing the
					 * IPv4 SYN packet stored is sent back to the source of the v4 SYN, the Session Table Entry
					 * is deleted, and the state is moved to CLOSED. */
					// send_icmp_error_message(skb, DESTINATION_UNREACHABLE, ADDRESS_UNREACHABLE);
					nat64_update_session_state(session_entry_p, CLOSED);
					return false;
				case ESTABLISHED:
					send_probe_packet(session_entry_p);
					nat64_update_session_state(session_entry_p, TRANS);
					return true;
				case V6_INIT:
				case V4_FIN_RCV:
				case V6_FIN_RCV:
				case V4_FIN_V6_FIN_RCV:
				case TRANS:
					nat64_update_session_state(session_entry_p, CLOSED);
					return false;
				default:
					log_err("TCP. Invalid state found, remove STE.");
					return false;
			}
		default:
			log_err("Invalid protocol: %d.", session_entry_p->l4protocol);
			return false;
	}
}

/** Filtering of incoming TCP packets.
 * 
 *  Each Session Table Entry (STE) has two purposes: 
 *      - keep the session info, and, at the same time,
 *      - being the state machine for each connection.
 *
 *  @params[in] tuple   Tuple of incoming packet
 *  @return     NF_ACCEPT if everything went OK, NF_DROP otherwise.
 */
int tcp(struct sk_buff* skb, struct nf_conntrack_tuple *tuple)
{
    struct session_entry *session_entry_p;
    u_int8_t current_state;
    
    spin_lock_bh(&bib_session_lock);
    session_entry_p = nat64_get_session_entry( tuple );
    spin_unlock_bh(&bib_session_lock);

    // If NO session was found:
    if ( session_entry_p == NULL )
        return tcp_closed_state_handle(skb, tuple);

    // Act according the current state.
    // TODO BTW, estamos leyendo la sesión sin candado...
    spin_lock_bh(&bib_session_lock);
    current_state = session_entry_p->current_state;
    spin_unlock_bh(&bib_session_lock);
    switch( current_state )
    {
        case CLOSED:
            return tcp_closed_state_handle(skb, tuple);
        case V4_INIT:
            return tcp_v4_init_state_handle(skb, tuple);
        case V6_INIT:
            return tcp_v6_init_state_handle(skb, tuple);
        case ESTABLISHED:
            return tcp_established_state_handle(skb, tuple);
        case V4_FIN_RCV:
            return tcp_v4_fin_rcv_state_handle(skb, tuple);
        case V6_FIN_RCV:
            return tcp_v6_fin_rcv_state_handle(skb, tuple);
        case V4_FIN_V6_FIN_RCV:
            return tcp_v4_fin_v6_fin_rcv_state_handle(skb, tuple);
        case TRANS:
            return tcp_trans_state_handle(skb, tuple);
        default:
            pr_err("NAT64:  TCP. Invalid state found.");
            return NF_DROP;
    }

    return NF_DROP;
}


/*********************************************
 **                                         **
 **     MAIN FUNCTION                       **
 **                                         **
 *********************************************/

/** Decide if a packet must be processed, updating binding and session 
 *  information, and if it may be also filtered.
 *
 *  @param[in]  packet  Packet received by NAT64.
 *  @param[in]  tuple   Structure containing info from an incoming packet, 
 *                      specifically source transport address (X’,x) and 
 *                      destination transport address (Y’,y).
 * @return  NF_ACCEPT if everything went OK, NF_DROP otherwise.
 */
int filtering_and_updating(struct sk_buff* skb, struct nf_conntrack_tuple *tuple)
{
    if ( NFPROTO_IPV6 == tuple->L3_PROTOCOL ) {
        /// Errores de ICMP no deben afectar las tablas.
        if ( IPPROTO_ICMPV6 == tuple->L4_PROTOCOL && !is_icmp6_info(icmp6_hdr(skb)->icmp6_type) )
	{	
		log_debug("Packet is ICMPv6 info, ignoring...");
		return NF_ACCEPT;
	}
        /// Get rid of hairpinning loop and unwanted packets.
        if ( pool6_contains(&tuple->ipv6_src_addr) || !pool6_contains(&tuple->ipv6_dst_addr) )
        {	
		log_debug("Packet was rejected by pool6, dropping...");
		return NF_DROP;
	} 
    }
            
    if ( NFPROTO_IPV4 == tuple->L3_PROTOCOL ) {
        /// Errores de ICMP no deben afectar las tablas.
        if ( IPPROTO_ICMP == tuple->L4_PROTOCOL && !is_icmp_info(icmp_hdr(skb)->type) )
        {	
		log_debug("Packet is ICMPv4 info, ignoring...");
		return NF_ACCEPT;
	}    

        /// Get rid of unexpected packets
        if ( !pool4_contains(&tuple->ipv4_dst_addr) )
        {	
		log_debug("Packet was rejected by pool4, dropping...");
		return NF_DROP;
	}      
    }
            
    /// Process packet, according to its protocol.
    switch (tuple->L4_PROTOCOL) {
        case IPPROTO_UDP:
            if ( NFPROTO_IPV6 == tuple->L3_PROTOCOL )
                return ipv6_udp(skb, tuple);
            if ( NFPROTO_IPV4 == tuple->L3_PROTOCOL )
                return ipv4_udp(skb, tuple);
            log_warning("Error: Not IPv4 not IPv6: %d.", tuple->L3_PROTOCOL);
            break;
        case IPPROTO_TCP:
            return tcp(skb, tuple);
        case IPPROTO_ICMP:
            if ( NFPROTO_IPV6 == tuple->L3_PROTOCOL )
                return ipv6_icmp6(skb, tuple);
            if ( NFPROTO_IPV4 == tuple->L3_PROTOCOL )
                return ipv4_icmp4(skb, tuple);
            log_warning("Error: Not IPv4 not IPv6: %d.", tuple->L3_PROTOCOL);
            break;    
        default:
            return NF_DROP;
    }

    return NF_DROP;
}
