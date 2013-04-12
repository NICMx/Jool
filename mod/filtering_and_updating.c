#include "nat64/mod/filtering_and_updating.h"
#include "nat64/comm/constants.h"
#include "nat64/comm/config_proto.h"
#include "nat64/mod/config.h"
#include "nat64/mod/config_validation.h"
#include "nat64/mod/rfc6052.h"
#include "nat64/mod/pool4.h"
#include "nat64/mod/pool6.h"
#include "nat64/mod/send_packet.h"

#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/icmpv6.h>
#include <net/tcp.h>
#include <net/icmp.h>


/** Current valid configuration for the filtering and updating module. */
static struct filtering_config config;
static DEFINE_SPINLOCK(config_lock);

/** Esto se llama al insertar el módulo y se encarga de poner los valores por defecto
 *  
 *  @return zero: if initialization ran fine, nonzero: otherwhise. */
int filtering_init(void)
{
    spin_lock_bh(&config_lock);
    
    config.to.udp = UDP_DEFAULT;
    config.to.icmp = ICMP_DEFAULT;
    config.to.tcp_trans = TCP_TRANS;
    config.to.tcp_est = TCP_EST;

    config.drop_by_addr = FILT_DEF_ADDR_DEPENDENT_FILTERING;
    config.drop_external_tcp = FILT_DEF_DROP_EXTERNAL_CONNECTIONS;
    config.drop_icmp6_info = FILT_DEF_FILTER_ICMPV6_INFO;

    spin_unlock_bh(&config_lock);
    
    return 0;
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
 *  @return     ________. */
int clone_filtering_config(struct filtering_config *clone)
{
    spin_lock_bh(&config_lock);
    *clone = config;
    spin_unlock_bh(&config_lock);

    return 0;
} 

/** Sirve para modificar a config 
 *  
 *  @param[in]  operation   _____________
 *  @param[in]  new_config  The new configuration.
 *  @return response_code   ___________.
 *  */
int set_filtering_config(__u32 operation, struct filtering_config *new_config)
{
	int error = 0;

    spin_lock_bh(&config_lock);

    if (operation & DROP_BY_ADDR_MASK)
        config.drop_by_addr = new_config->drop_by_addr;
    if (operation & DROP_ICMP6_INFO_MASK)
        config.drop_icmp6_info = new_config->drop_icmp6_info;
    if (operation & DROP_EXTERNAL_TCP_MASK)
        config.drop_external_tcp = new_config->drop_external_tcp;
 
    if (operation & UDP_TIMEOUT_MASK) {
        if ( new_config->to.udp < UDP_MIN ) {
        	error = -EINVAL;
            log_err(ERR_UDP_TO_RANGE, "The UDP timeout must be at least %u.", UDP_MIN);
        } else {
        	config.to.udp = new_config->to.udp;
        }
    }
    if (operation & ICMP_TIMEOUT_MASK)
        config.to.icmp = new_config->to.icmp;
    if (operation & TCP_EST_TIMEOUT_MASK) {
        if ( new_config->to.tcp_est < TCP_EST ) {
        	error = -EINVAL;
        	log_err(ERR_TCPEST_TO_RANGE, "The TCP est timeout must be at least %u.", TCP_EST);
        } else {
        	config.to.tcp_est = new_config->to.tcp_est;
        }
    }
    if (operation & TCP_TRANS_TIMEOUT_MASK) {
        if ( new_config->to.tcp_trans < TCP_TRANS ) {
        	error = -EINVAL;
            log_err(ERR_TCPTRANS_TO_RANGE, "The TCP trans timeout must be at least %u.", TCP_TRANS);
        } else {
        	config.to.tcp_trans = new_config->to.tcp_trans;
        }
    }
  
    spin_unlock_bh(&config_lock);
    return error;
} 

static void update_session_lifetime(struct session_entry *session_entry_p, unsigned int *timeout)
{
    unsigned int ttl;

    spin_lock_bh(&config_lock);
    ttl = *timeout;
    spin_unlock_bh(&config_lock);

    session_entry_p->dying_time = jiffies_to_msecs(jiffies) + 1000 * ttl;
}

static bool filter_icmpv6_info(void)
{
    bool result;
    
    spin_lock_bh(&config_lock);
    result = config.drop_icmp6_info;
    spin_unlock_bh(&config_lock);
    
    return result;
}

static bool address_dependent_filtering(void)
{
    bool result;
    
    spin_lock_bh(&config_lock);
    result = config.drop_by_addr;
    spin_unlock_bh(&config_lock);
    
    return result;
}

static bool drop_external_connections(void)
{
    bool result;
    
    spin_lock_bh(&config_lock);
    result = config.drop_external_tcp;
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
        log_debug("  > bib_entry = NULL   :'( ");
    else
    	log_debug("  > bib_entry = (%pI6c , %u) -- (%pI4 , %u)",
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
 * @param[in]  addr  IPv4 Address
 * @param[in]  l4_id Port or ICMP ID
 * @param[out] ta    Transport Address
 * */
void transport_address_ipv4(struct in_addr addr, __u16 l4_id, struct ipv4_tuple_address *ta)
{ 
    ta->address = addr;
    ta->l4_id = l4_id;
}

/** Join a IPv6 address and a port (or ICMP ID) to create a Transport Address.
 *
 * @param[in]  addr  IPv6 Address
 * @param[in]  l4_id Port or ICMP ID
 * @param[out] ta    Transport Address
 * */
void transport_address_ipv6(struct in6_addr addr, __u16 l4_id, struct ipv6_tuple_address *ta)
{ 
    ta->address = addr;
    ta->l4_id = l4_id;
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
bool ipv4_pool_get_new_port(struct in_addr address, __u16 pi, u_int8_t protocol,
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
bool allocate_ipv4_transport_address(struct tuple *tuple, u_int8_t protocol,
        struct ipv4_tuple_address *result)
{
    struct bib_entry *bib_entry_t;

    // Check if the BIB has a previous entry from the same IPv6 source address (X’)
    bib_entry_t = bib_get_by_ipv6_only( &tuple->src.addr.ipv6, protocol );

    // If true, use the same IPv4 address (T). 
    if ( bib_entry_t != NULL )
    {
        struct ipv4_tuple_address temp;
        transport_address_ipv4(bib_entry_t->ipv4.address, tuple->src.l4_id, &temp);
        return pool4_get_similar(protocol, &temp, result);
    }
    else // Else, create a new BIB entry and ask the IPv4 pool for a new IPv4 address.
    {
        return pool4_get_any(protocol, tuple->src.l4_id, result);
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
bool allocate_ipv4_transport_address_digger(struct tuple *tuple, u_int8_t protocol,
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
        
        bib_entry_p = bib_get_by_ipv6_only(&tuple->src.addr.ipv6, proto[ii]);
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
        transport_address_ipv4(*address, tuple->src.l4_id, &temp);
        return pool4_get_similar(protocol, &temp, result);
    }
    else
    {
        // Use whichever address
        return pool4_get_any(protocol, tuple->src.l4_id, result);
    }
}

/** Determine if a packet is IPv4 .
 * 
 * @param[in]   packet  The incoming packet.
 * @return  true if it is OK, false otherwise.
 */
bool packet_is_ipv4(struct sk_buff* skb)
{
    if (skb == NULL) { 
        log_err(ERR_NULL, "skb == NULL");
        return false; 
    } else {
        return ( skb->protocol == htons(ETH_P_IP) );
    }
}

/** Determine if a packet is IPv6 .
 * 
 * @param[in]   packet  The incoming packet.
 * @return  true if it is OK, false otherwise.
 */
bool packet_is_ipv6(struct sk_buff* skb)
{
    if (skb == NULL) {
    	log_err(ERR_NULL, "skb == NULL");
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
    iph->hop_limit = 64; // TODO (fine) send_packet_ipv6 debería setear este valor con dst?
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
    send_packet_ipv6(NULL, skb);
    log_debug("Packet sent; catch it using a tool like Wireshark or tcpdump.");

    return true;
}

static bool extract_ipv4(struct in6_addr *src, struct in_addr *dst)
{
    struct ipv6_prefix prefix;
    if ( !pool6_peek(&prefix) )
        return false;

    return addr_6to4(src, &prefix, dst);
}

static bool append_ipv4(struct in_addr *src, struct in6_addr *dst)
{
    struct ipv6_prefix prefix;
    if ( !pool6_peek(&prefix) )
        return false;

    return addr_4to6(src, &prefix, dst);
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
int ipv6_udp(struct sk_buff *skb, struct tuple *tuple)
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
    transport_address_ipv6(tuple->src.addr.ipv6, tuple->src.l4_id, &ipv6_ta);

    // Check if a previous BIB entry exist, look for IPv6 source transport address (X’,x).
    spin_lock_bh(&bib_session_lock);
    bib_entry_p = bib_get_by_ipv6( &ipv6_ta, protocol );

    // If not found, try to create a new one.
    if ( bib_entry_p == NULL )
    {
        // TODO:    Define the checks that evaluate if resources availability
        //          and policy allows the creation of a new entry.

        // Find a similar transport address (T, t)
        if ( !allocate_ipv4_transport_address(tuple, protocol, &new_ipv4_transport_address) ) {
            icmpv6_send(skb, DESTINATION_UNREACHABLE, ADDRESS_UNREACHABLE, 0);
            log_warning("Could not 'allocate' a compatible transport address for the packet.");
            goto failure;
        }

        // Create the BIB entry
        bib_entry_p = bib_create(&new_ipv4_transport_address, &ipv6_ta);
        if ( bib_entry_p == NULL ) {
            icmpv6_send(skb, DESTINATION_UNREACHABLE, ADDRESS_UNREACHABLE, 0);
            log_err(ERR_ALLOC_FAILED, "Failed to allocate a BIB entry.");
            goto failure;
        }

        bib_is_local = true;
            
        // Add the BIB entry
        if (bib_add( bib_entry_p, protocol) != 0) {
            log_err(ERR_ADD_BIB_FAILED, "Could not add the BIB entry to the table.");
            goto failure;
        }
    }

    // Once we have a BIB entry do ...
    
    session_entry_p = session_get( tuple );

    // If session was not found, then try to create a new one.
    if ( session_entry_p == NULL )
    {
        // TODO:    Define the checks that evaluate if resources availability 
        //          and policy allows the creation of a new entry.

        // Translate address
        if ( !extract_ipv4(&tuple->dst.addr.ipv6, &ipv4_remote.address) ) // Z(Y')
        {
            log_err(ERR_EXTRACT_FAILED, "Could not translate the packet's address.");
            goto failure;
        }
        ipv4_remote.l4_id = tuple->dst.l4_id; // y

        // Create the session entry
        pair6.remote.address = tuple->src.addr.ipv6; // X'
        pair6.remote.l4_id = tuple->src.l4_id; // x
        pair6.local.address = tuple->dst.addr.ipv6; // Y'
        pair6.local.l4_id = tuple->dst.l4_id; // y
        pair4.local = bib_entry_p->ipv4; // (T, t)
        pair4.remote = ipv4_remote; // (Z, z) // (Z(Y’),y)
        session_entry_p = session_create(&pair4, &pair6, bib_entry_p, protocol);
        if ( session_entry_p == NULL )
        {
            log_err(ERR_ALLOC_FAILED, "Failed to allocate a session entry.");
            goto failure;
        }

        // Add the session entry
        if ( session_add(session_entry_p) != 0 )
        {            
            log_err(ERR_ADD_SESSION_FAILED, "Could not add the session entry to the table.");
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
        bib_remove(bib_entry_p, protocol);
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
int ipv4_udp(struct sk_buff* skb, struct tuple *tuple)
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
    transport_address_ipv4( tuple->dst.addr.ipv4, tuple->dst.l4_id, &ipv4_ta );

    // Check if a previous BIB entry exist, look for IPv4 destination transport address (T,t).
    spin_lock_bh(&bib_session_lock);
    bib_entry_p = bib_get_by_ipv4( &ipv4_ta, protocol );

    // Without state there's no way to know where should the packet be sent, so just die.
    if ( bib_entry_p == NULL )
    {
        log_warning("There is no BIB entry for the incoming IPv4 UDP packet.");
        goto icmp_and_fail;
    }
    
    if ( address_dependent_filtering() && !session_allow(tuple) )
    {
        log_info("Packet was blocked by address-dependent filtering.");
        icmp_send(skb, DESTINATION_UNREACHABLE, COMMUNICATION_ADMINISTRATIVELY_PROHIBITED, 0);
        goto failure;
    }

    // Searches for the Session Table Entry corresponding to the incoming tuple->
    session_entry_p = session_get( tuple );
    
    // If NO session was found:
    if ( session_entry_p == NULL )
    {
        // TODO:    Define the checks that evaluate if resources availability 
        //          and policy allows the creation of a new entry.
    
        // Translate address
        if ( !append_ipv4(&tuple->src.addr.ipv4, &ipv6_local.address) ) // Y’(W)
        {
            log_err(ERR_APPEND_FAILED, "Could not translate the packet's address.");
            goto icmp_and_fail;
        }
        ipv6_local.l4_id = tuple->src.l4_id; // w

        // Create the session entry
        pair6.remote = bib_entry_p->ipv6;   // (X', x)
        pair6.local = ipv6_local;           // (Y’(W), w)
        pair4.local.address = tuple->dst.addr.ipv4; // T
        pair4.local.l4_id = tuple->dst.l4_id; // t
        pair4.remote.address = tuple->src.addr.ipv4; // W
        pair4.remote.l4_id = tuple->src.l4_id; // w
        session_entry_p = session_create(&pair4, &pair6, bib_entry_p, protocol);
        if ( session_entry_p == NULL )
        {
        	log_err(ERR_ALLOC_FAILED, "Failed to allocate a session entry.");
            goto icmp_and_fail;
        }

        // Add the session entry
        if ( session_add(session_entry_p) != 0 )
        {
        	log_err(ERR_ADD_SESSION_FAILED, "Could not add the session entry to the table.");
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
        bib_remove(bib_entry_p, protocol);
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
int ipv6_icmp6(struct sk_buff *skb, struct tuple *tuple)
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
    
    if ( filter_icmpv6_info() )
    {
    	log_info("Packet is ICMPv6 info; dropping due to policy.");
        return NF_DROP;
    }

    // Pack source address into transport address
    transport_address_ipv6( tuple->src.addr.ipv6, tuple->icmp_id, &ipv6_source );
    
    // Search for an ICMPv6 Query BIB entry that matches the (X’,i1) pair.
    spin_lock_bh(&bib_session_lock);
    bib_entry_p = bib_get_by_ipv6( &ipv6_source, protocol );

    // If not found, try to create a new one.
    if ( bib_entry_p == NULL )
    {
        // TODO:    Define the checks that evaluate if resources availability 
        //          and policy allows the creation of a new entry.

        // Look in the BIB tables for a previous packet from the same origin (X')
        if (!allocate_ipv4_transport_address_digger(tuple, IPPROTO_ICMP, &new_ipv4_transport_address))
        {
        	log_warning("Could not 'allocate' a compatible transport address for the packet.");
            goto icmp_and_fail;
        }

        // Create the BIB entry
        bib_entry_p = bib_create(&new_ipv4_transport_address, &ipv6_source);
        if ( bib_entry_p == NULL )
        {
        	log_err(ERR_ALLOC_FAILED, "Failed to allocate a BIB entry.");
            goto icmp_and_fail;
        }

        bib_is_local = true;

        // Add the new BIB entry
        if ( bib_add(bib_entry_p, protocol) != 0 )
        {
        	log_err(ERR_ADD_BIB_FAILED, "Could not add the BIB entry to the table.");
            goto icmp_and_fail;
        }
    }

    // OK, we have a BIB entry to work with...

    /* Searche for an ICMP Query Session Table Entry corresponding to the incoming 
       3-tuple (X’,Y’,i1).  */
    session_entry_p = session_get( tuple );

    // If NO session was found:
    if ( session_entry_p == NULL )
    {
        // TODO:    Define the checks that evaluate if resources availability 
        //          and policy allows the creation of a new entry.

        // Translate address from IPv6 to IPv4
        if ( !extract_ipv4(&tuple->dst.addr.ipv6, &ipv4_remote_address) ) // Z(Y')
        {
        	log_err(ERR_EXTRACT_FAILED, "Could not translate the packet's address.");
            goto icmp_and_fail;
        }

        // Create the session entry
        pair6.remote.address = tuple->src.addr.ipv6;      // (X')
        pair6.remote.l4_id = tuple->icmp_id;              // (i1)
        pair6.local.address = tuple->dst.addr.ipv6;       // (Y')
        pair6.local.l4_id = tuple->icmp_id;               // (i1)
        pair4.local = bib_entry_p->ipv4;                  // (T, i2)
        pair4.remote.address = ipv4_remote_address;       // (Z(Y’))
        pair4.remote.l4_id = bib_entry_p->ipv4.l4_id;     // (i2)
        session_entry_p = session_create(&pair4, &pair6, bib_entry_p, protocol);
        if ( session_entry_p == NULL )
        {
        	log_err(ERR_ALLOC_FAILED, "Failed to allocate a session entry.");
            goto icmp_and_fail;
        }

        // Add the session entry
        if ( session_add( session_entry_p ) != 0 )
        {
        	log_err(ERR_ADD_SESSION_FAILED, "Could not add the session entry to the table.");
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
        bib_remove(bib_entry_p, protocol);
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
int ipv4_icmp4(struct sk_buff* skb, struct tuple *tuple)
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
    transport_address_ipv4( tuple->dst.addr.ipv4, tuple->icmp_id, &ipv4_ta );
    
    // Look for a previous BIB entry that contains (X) as the IPv4 address and (i2) as the ICMPv4 Identifier.
    spin_lock_bh(&bib_session_lock);
    bib_entry_p = bib_get_by_ipv4( &ipv4_ta, protocol );

    // If such an entry does not exist,
    if ( bib_entry_p == NULL )
    {   
        // TODO: Does the policy allow us to send this packet?
        icmp_send(skb, DESTINATION_UNREACHABLE, HOST_UNREACHABLE, 0);
        log_warning("There is no BIB entry for the incoming IPv4 ICMP packet.");
        goto failure;
    }

    // If we're applying address-dependent filtering in the IPv4 interface,
    if ( address_dependent_filtering() && !session_allow(tuple) )
    {
        icmp_send(skb, DESTINATION_UNREACHABLE, COMMUNICATION_ADMINISTRATIVELY_PROHIBITED, 0);
        log_info("Packet was blocked by address-dependent filtering.");
        goto failure;
    }

    // Search the Session Table Entry corresponding to the incoming tuple
    session_entry_p = session_get( tuple );
    
    // If NO session was found:
    if ( session_entry_p == NULL )
    {
        // TODO:    Define the checks that evaluate if resources availability 
        //          and policy allows the creation of a new entry.
    
        // Translation the address
        if ( !append_ipv4(&tuple->src.addr.ipv4, &ipv6_remote) ) // Y’(Z)
        {
        	log_err(ERR_APPEND_FAILED, "Could not translate the packet's address.");
            goto icmp_and_fail;
        }

        // Create the session entry.
        // TODO revisar estos valores; por ahí habían cosas locales mezcladas con remotas.
        pair6.remote.address = bib_entry_p->ipv6.address; // X'
        pair6.remote.l4_id = bib_entry_p->ipv6.l4_id; // i1
        pair6.local.address = ipv6_remote; // Y'(Z)
        pair6.local.l4_id = bib_entry_p->ipv6.l4_id; // i1
        pair4.local.address = tuple->dst.addr.ipv4; // T
        pair4.local.l4_id = tuple->icmp_id; // i2
        pair4.remote.address = tuple->src.addr.ipv4; // Z
        pair4.remote.l4_id = tuple->icmp_id; // i2
        session_entry_p = session_create(&pair4, &pair6, bib_entry_p, protocol);
        if ( session_entry_p == NULL )
        {
        	log_err(ERR_ALLOC_FAILED, "Failed to allocate a session entry.");
            goto icmp_and_fail;
        }

        // Add the session entry
        if ( session_add(session_entry_p) != 0 )
        {
        	log_err(ERR_ADD_SESSION_FAILED, "Could not add the session entry to the table.");
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
        bib_remove(bib_entry_p, protocol);
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
 * @return  true if everything went OK, false otherwise.
 */
static bool tcp_closed_state_handle(struct sk_buff* skb, struct tuple *tuple)
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

    //  V6 SYN packet: IPv6 -> IPv4
    if ( packet_is_v6_syn(skb) )
    {
        // Pack source address into transport address
        transport_address_ipv6( tuple->src.addr.ipv6, tuple->src.l4_id, &ipv6_ta );
        
        // Check if a previous BIB entry exist, look for IPv6 source transport address (X’,x).
        bib_entry_p = bib_get_by_ipv6( &ipv6_ta, protocol );

        // If bib does not exist, try to create a new one,
        if ( bib_entry_p == NULL )
        {
            /* TODO: Define if resources and policy permit the creation of a BIB entry*/            

            // Obtain a new BIB IPv4 transport address (T,t), put it in new_ipv4_transport_address.
            if ( !allocate_ipv4_transport_address_digger(tuple, protocol, &new_ipv4_transport_address) )
            {
                icmpv6_send(skb, DESTINATION_UNREACHABLE, ADDRESS_UNREACHABLE, 0);
                log_warning("Could not 'allocate' a compatible transport address for the packet.");
                goto failure;
            }

            // Create the BIB entry
            bib_entry_p = bib_create(&new_ipv4_transport_address, &ipv6_ta);
            if ( bib_entry_p == NULL ) {
                icmpv6_send(skb, DESTINATION_UNREACHABLE, ADDRESS_UNREACHABLE, 0);
                log_err(ERR_ALLOC_FAILED, "Failed to allocate a BIB entry.");
                goto failure;
            }
            bib_is_local = true;

            // Add the new BIB entry
            if ( bib_add( bib_entry_p, protocol) != 0 )
            {
                icmpv6_send(skb, DESTINATION_UNREACHABLE, ADDRESS_UNREACHABLE, 0);
                log_err(ERR_ADD_BIB_FAILED, "Could not add the BIB entry to the table.");
                goto failure;
            }
        }

        // Now that we have a BIB entry...

        // Translate address
        if ( !extract_ipv4(&tuple->dst.addr.ipv6, &ipv4_remote.address) ) // Z(Y')
        {
        	log_err(ERR_EXTRACT_FAILED, "Could not translate the packet's address.");
            goto icmp_and_fail;
        }
        ipv4_remote.l4_id = tuple->dst.l4_id; // y

        // Create the session entry.
        // TODO:     What about of checking Policy and Resources for the creation of a STE.
        pair6.remote.address = tuple->src.addr.ipv6; // X'
        pair6.remote.l4_id = tuple->src.l4_id; // x
        pair6.local.address = tuple->dst.addr.ipv6; // Y'
        pair6.local.l4_id = tuple->dst.l4_id; // y
        pair4.local = bib_entry_p->ipv4; // (T, t)
        pair4.remote = ipv4_remote; // (Z, z) // (Z(Y’),y)
        session_entry_p = session_create(&pair4, &pair6, bib_entry_p, protocol);
        if ( session_entry_p == NULL )
        {
        	log_err(ERR_ALLOC_FAILED, "Failed to allocate a session entry.");
            goto icmp_and_fail;
        }

        update_session_lifetime(session_entry_p, &config.to.tcp_trans);
        session_entry_p->state = V6_INIT;

        if ( session_add(session_entry_p) != 0 )
        {
        	log_err(ERR_ADD_SESSION_FAILED, "Could not add the session entry to the table.");
            goto icmp_and_fail;
        }
    }
    else if ( packet_is_v4_syn(skb) )
    {
        if ( drop_external_connections() )
        {
            log_info("Applying policy: Dropping externally initiated TCP connections.");
            return false;
        }

        // Pack addresses and ports into transport address
        transport_address_ipv4( tuple->dst.addr.ipv4, tuple->dst.l4_id, &ipv4_ta );

        // Translate address
        if (!append_ipv4(&tuple->src.addr.ipv4, &ipv6_local.address)) // Y'(Y)
        {
            log_err(ERR_APPEND_FAILED, "Could not translate the packet's address.");
            return false;
        }
        ipv6_local.l4_id = tuple->src.l4_id; // y

        // Look for the destination transport address (X,x) in the BIB
		bib_entry_p = bib_get_by_ipv4( &ipv4_ta, protocol );

        // TODO:    Define the checks that evaluate if resources availability 
        //          and policy allows the creation of a new entry.
        // If not found (not in use), even try to create a new SESSION entry!!!
        if ( bib_entry_p == NULL )
        {
            unsigned int temp = TCP_INCOMING_SYN;

            log_warning("Unknown TCP connections started from the IPv4 side is still unsupported. "
                    "Dropping packet...");
            return false;

            /*  Side:   <-------- IPv6 -------->  N  <------- IPv4 ------->
                Packet: dest(X',x) <-- src(Y',y)  A  dest(X,x) <-- src(Y,y)
                NAT64:    remote       local      T    local        remote
            */

            // Create the session entry
            // pair6.remote = Not_Available; // (X', x) INTENTIONALLY LEFT UNSPECIFIED!
            pair6.local = ipv6_local; // (Y', y)
            pair4.local.address = tuple->dst.addr.ipv4; // (X, x)  (T, t)
            pair4.local.l4_id = tuple->dst.l4_id;
            pair4.remote.address = tuple->src.addr.ipv4; // (Z(Y’),y) ; // (Z, z)
            pair4.remote.l4_id = tuple->src.l4_id;
            session_entry_p = session_create(&pair4, &pair6, NULL, protocol);
            if ( session_entry_p == NULL )
            {
                log_err(ERR_ALLOC_FAILED, "Failed to allocate a session entry.");
                goto icmp_and_fail;
            }
            session_entry_p->state = V4_INIT;
            update_session_lifetime(session_entry_p, &temp);

            /* TODO:    The packet is stored !!!
             *          The result is that the NAT64 will not drop the packet based on the filtering,
             *          nor create a BIB entry.  Instead, the NAT64 will only create the Session
             *          Table Entry and store the packet. The motivation for this is to support
             *          simultaneous open of TCP connections. */
        }
        else // if a bib entry exists
        {
            // TODO:    Define the checks that evaluate if resources availability 
            //          and policy allows the creation of a new entry.

            // Create the session entry
            pair6.remote = bib_entry_p->ipv6; // (X', x)
            pair6.local = ipv6_local; // (Y', y)
            pair4.local.address = tuple->dst.addr.ipv4; // (X, x)  (T, t)
            pair4.local.l4_id = tuple->dst.l4_id;
            pair4.remote.address = tuple->src.addr.ipv4; // (Z(Y’),y) ; // (Z, z)
            pair4.remote.l4_id = tuple->src.l4_id;
            session_entry_p = session_create(&pair4, &pair6, bib_entry_p, protocol);
            if ( session_entry_p == NULL )
            {
            	log_err(ERR_ALLOC_FAILED, "Failed to allocate a session entry.");
                goto icmp_and_fail;
            }
            session_entry_p->state = V4_INIT;

            if ( address_dependent_filtering() ) {
                unsigned int temp = TCP_INCOMING_SYN;
                update_session_lifetime(session_entry_p, &temp);
            } else {
                update_session_lifetime(session_entry_p, &config.to.tcp_trans);
            }
        }

        if ( session_add(session_entry_p) != 0 )
        {
        	log_err(ERR_ADD_SESSION_FAILED, "Could not add the session entry to the table.");
            goto icmp_and_fail;
        }
    }
    else // For any packet, other than SYN, belonging to this connection:
	{
		if ( packet_is_ipv6(skb) ) // IPv6
		{
			// Pack source address into transport address
			transport_address_ipv6( tuple->src.addr.ipv6, tuple->src.l4_id, &ipv6_ta );

			// Look if there is a corresponding entry in the TCP BIB
			bib_entry_p = bib_get_by_ipv6( &ipv6_ta, protocol );
		}
		else if( packet_is_ipv4(skb) ) // IPv4
		{
			// Pack addresses and ports into transport address
			transport_address_ipv4( tuple->dst.addr.ipv4, tuple->dst.l4_id, &ipv4_ta );

			// Look for the destination transport address (X,x) in the BIB
			bib_entry_p = bib_get_by_ipv4( &ipv4_ta, protocol );
		}

		return (bib_entry_p != NULL);
	}

    return true;

icmp_and_fail:
    icmp_send(skb, DESTINATION_UNREACHABLE, ADDRESS_UNREACHABLE, 0);
    // Fall through.

failure:
    kfree(session_entry_p);
    if ( bib_entry_p )
        bib_remove(bib_entry_p, protocol);
    if ( bib_is_local )
        kfree(bib_entry_p);
    return false;
}

/** V4 INIT state
 * 
 * Handle IPv6 SYN packets.
 *
 * @param[in]   session_entry_p   Session the packet participates in.
 * @return  true if everything went OK, false otherwise.
 */
static bool tcp_v4_init_state_handle(struct sk_buff* skb, struct session_entry *session_entry_p)
{
    if ( packet_is_v6_syn(skb) )
    {
        update_session_lifetime(session_entry_p, &config.to.tcp_est);
        session_entry_p->state = ESTABLISHED;
    } // else, the state remains unchanged.

    return true;
}

/** V6 INIT state.
 * 
 * Handle IPv4 & IPv6 SYN packets.
 *
 * @param[in]   session_entry_p   Session the packet participates in.
 * @return  true if everything went OK, false otherwise.
 */
static bool tcp_v6_init_state_handle(struct sk_buff* skb, struct session_entry *session_entry_p)
{
    if (packet_is_v4_syn(skb))
    {
        update_session_lifetime(session_entry_p, &config.to.tcp_est);
        session_entry_p->state = ESTABLISHED;
    }
    else if (packet_is_v6_syn(skb))
    {
        update_session_lifetime(session_entry_p, &config.to.tcp_trans);
    } // else, the state remains unchanged
    
    return true;
}

/** ESTABLISHED state.
 * 
 * Handles V4 FIN, V6 FIN, V4 RST, & V6 RST packets.
 *
 * @param[in]   session_entry_p   Session the packet participates in.
 * @return  true if everything went OK, false otherwise.
 */
static bool tcp_established_state_handle(struct sk_buff* skb, struct session_entry *session_entry_p)
{
    if ( packet_is_v4_fin(skb) )
    {
        session_entry_p->state = V4_FIN_RCV;
    }
    else if ( packet_is_v6_fin(skb) )
    {
        session_entry_p->state = V6_FIN_RCV;
    }
    else if ( packet_is_v4_rst(skb) ||  packet_is_v6_rst(skb) )
    {
        update_session_lifetime(session_entry_p, &config.to.tcp_trans);
        session_entry_p->state = TRANS;
    }
    else
    {
        update_session_lifetime(session_entry_p, &config.to.tcp_est);
    }

    return true;
}

/** V4 FIN RCV state.
 * 
 * Handles V6 FIN packets.
 *
 * @param[in]   session_entry_p   Session the packet participates in.
 * @return  true if everything went OK, false otherwise.
 */
static bool tcp_v4_fin_rcv_state_handle(struct sk_buff* skb, struct session_entry *session_entry_p)
{
    if ( packet_is_v6_fin(skb) )
    {
        update_session_lifetime(session_entry_p, &config.to.tcp_trans);
        session_entry_p->state = V4_FIN_V6_FIN_RCV;
    }
    else
    {
        update_session_lifetime(session_entry_p, &config.to.tcp_est);
    }
    return true;
}

/** V6 FIN RCV state.
 * 
 * Handles V4 FIN packets.
 *
 * @param[in]   session_entry_p   Session the packet participates in.
 * @return  true if everything went OK, false otherwise.
 */
static bool tcp_v6_fin_rcv_state_handle(struct sk_buff* skb, struct session_entry *session_entry_p)
{
    if ( packet_is_v4_fin(skb) )
    {        
        update_session_lifetime(session_entry_p, &config.to.tcp_trans);
        session_entry_p->state = V4_FIN_V6_FIN_RCV;
    }
    else
    {
        update_session_lifetime(session_entry_p, &config.to.tcp_est);
    }
    return true;
}

/** V6 FIN + V4 FIN RCV state.
 * 
 * Handles all packets.
 *
 * @param[in]   session_entry_p   Session the packet participates in.
 * @return  true if everything went OK, false otherwise.
 */
static bool tcp_v4_fin_v6_fin_rcv_state_handle(struct sk_buff *skb, struct session_entry *session_entry_p)
{
    // Only the timeout can change this state.
    return true;
}

/** TRANS state.
 * 
 * Handles not RST packets.
 *
 * @param[in]   session_entry_p   Session the packet participates in.
 * @return  true if everything went OK, false otherwise.
 */
static bool tcp_trans_state_handle(struct sk_buff *skb, struct session_entry *session_entry_p)
{
    if ( !packet_is_v4_rst(skb) && !packet_is_v6_rst(skb) )
    {
        update_session_lifetime(session_entry_p, &config.to.tcp_est);
        session_entry_p->state = ESTABLISHED;
    }

    return true;
}

/** 
 * 
 *  
 * @param[in]   session_entry   The entry whose lifetime just expired.
 * @return TRUE: keep STE, FALSE: remove STE.
 * */
bool session_expired(struct session_entry *session_entry_p)
{		
	switch(session_entry_p->l4_proto) {
		case IPPROTO_UDP:
			return false;
		case IPPROTO_ICMP:
		case IPPROTO_ICMPV6:
			return false;
		case IPPROTO_TCP:
			switch( session_entry_p->state )
			{
				case V4_INIT:
					/* TODO:
					 * If the lifetime expires, an ICMP Port Unreachable error (Type 3, Code 3) containing the
					 * IPv4 SYN packet stored is sent back to the source of the v4 SYN, the Session Table Entry
					 * is deleted, and the state is moved to CLOSED. */
					// send_icmp_error_message(skb, DESTINATION_UNREACHABLE, ADDRESS_UNREACHABLE);
					session_entry_p->state = CLOSED;
					return false;
				case ESTABLISHED:
					send_probe_packet(session_entry_p);
					session_entry_p->state = TRANS;
					return true;
				case V6_INIT:
				case V4_FIN_RCV:
				case V6_FIN_RCV:
				case V4_FIN_V6_FIN_RCV:
				case TRANS:
					session_entry_p->state = CLOSED;
					return false;
				default:
					// Because closed sessions are not supposed to be stored,
					// CLOSED is known to fall through here.
					log_err(ERR_INVALID_STATE, "Invalid state found; removing session entry.");
					return false;
			}
		default:
			log_err(ERR_L4PROTO, "Unsupported transport protocol: %u.", session_entry_p->l4_proto);
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
int tcp(struct sk_buff* skb, struct tuple *tuple)
{
    struct session_entry *session_entry_p;
    bool result;
    
    spin_lock_bh(&bib_session_lock);
    session_entry_p = session_get( tuple );

    // If NO session was found:
    if ( session_entry_p == NULL ) {
        result = tcp_closed_state_handle(skb, tuple);
        goto end;
    }

    // Act according the current state.
    switch( session_entry_p->state )
    {
        case V4_INIT:
        	result = tcp_v4_init_state_handle(skb, session_entry_p);
            break;
        case V6_INIT:
        	result = tcp_v6_init_state_handle(skb, session_entry_p);
            break;
        case ESTABLISHED:
        	result = tcp_established_state_handle(skb, session_entry_p);
            break;
        case V4_FIN_RCV:
        	result = tcp_v4_fin_rcv_state_handle(skb, session_entry_p);
            break;
        case V6_FIN_RCV:
        	result = tcp_v6_fin_rcv_state_handle(skb, session_entry_p);
            break;
        case V4_FIN_V6_FIN_RCV:
        	result = tcp_v4_fin_v6_fin_rcv_state_handle(skb, session_entry_p);
            break;
        case TRANS:
        	result = tcp_trans_state_handle(skb, session_entry_p);
            break;
        default:
        	// Because closed sessions are not supposed to be stored,
        	// CLOSED is known to fall through here.
            log_err(ERR_INVALID_STATE, "Invalid state found: %u.", session_entry_p->state);
            result = false;
    }
    /* Fall through. */

end:
    spin_unlock_bh(&bib_session_lock);
    return result ? NF_ACCEPT : NF_DROP;
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
int filtering_and_updating(struct sk_buff* skb, struct tuple *tuple)
{
	int result;
	
	log_debug("Step 2: Filtering and updating");
	
    if ( PF_INET6 == tuple->l3_proto ) {
        /// Errores de ICMP no deben afectar las tablas.
        if ( IPPROTO_ICMPV6 == tuple->l3_proto && !is_icmp6_info(icmp6_hdr(skb)->icmp6_type) )
		{
			log_debug("Packet is ICMPv6 info, ignoring...");
			return NF_ACCEPT;
		}
        /// Get rid of hairpinning loop and unwanted packets.
        if ( pool6_contains(&tuple->src.addr.ipv6) || !pool6_contains(&tuple->dst.addr.ipv6) )
        {
			log_info("Packet was rejected by pool6, dropping...");
			return NF_DROP;
		}
    }
            
    if ( PF_INET == tuple->l3_proto ) {
        /// Errores de ICMP no deben afectar las tablas.
        if ( IPPROTO_ICMP == tuple->l4_proto && !is_icmp_info(icmp_hdr(skb)->type) )
        {
			log_debug("Packet is ICMPv4 info, ignoring...");
			return NF_ACCEPT;
		}

        /// Get rid of unexpected packets
        if ( !pool4_contains(&tuple->dst.addr.ipv4) )
        {
			log_info("Packet was rejected by pool4, dropping...");
			return NF_DROP;
		}
    }

    /// Process packet, according to its protocol.
    switch (tuple->l4_proto) {
        case IPPROTO_UDP:
            if ( PF_INET6 == tuple->l3_proto )
                result = ipv6_udp(skb, tuple);
            else if ( PF_INET == tuple->l3_proto )
                result = ipv4_udp(skb, tuple);
            else {
				log_err(ERR_L3PROTO, "Not IPv4 nor IPv6: %u.", tuple->l3_proto);
				result = NF_DROP;
			}
            break;
        case IPPROTO_TCP:
            result = tcp(skb, tuple);
            break;
        case IPPROTO_ICMP:
        case IPPROTO_ICMPV6:
            if ( PF_INET6 == tuple->l3_proto )
                result = ipv6_icmp6(skb, tuple);
            else if ( PF_INET == tuple->l3_proto )
                result = ipv4_icmp4(skb, tuple);
			else {
				log_err(ERR_L3PROTO, "Not IPv4 nor IPv6: %u.", tuple->l3_proto);
				result = NF_DROP;
			}
            break;    
        default:
            log_err(ERR_L4PROTO, "Transport protocol not handled: %d", tuple->l4_proto);
            result = NF_DROP;
    }

	log_debug("Done: Step 2.");
    return result;
}
