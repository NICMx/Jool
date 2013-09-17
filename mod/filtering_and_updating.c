#include "nat64/mod/filtering_and_updating.h"
#include "nat64/comm/constants.h"
#include "nat64/comm/config_proto.h"
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
    /* No code. */
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
 **     SUPPORT FUNCTIONS                   **
 **                                         **
 *********************************************/


/** Join a IPv4 address and a port (or ICMP ID) to create a Transport Address.
 *
 * @param[in]  addr  IPv4 Address
 * @param[in]  l4_id Port or ICMP ID
 * @param[out] ta    Transport Address
 * */
static void transport_address_ipv4(struct in_addr addr, __u16 l4_id, struct ipv4_tuple_address *ta)
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
static void transport_address_ipv6(struct in6_addr addr, __u16 l4_id, struct ipv6_tuple_address *ta)
{ 
    ta->address = addr;
    ta->l4_id = l4_id;
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
static bool allocate_ipv4_transport_address(struct tuple *tuple, u_int8_t protocol,
        struct ipv4_tuple_address *result)
{
    struct bib_entry *bib_entry_t;

    /* Check if the BIB has a previous entry from the same IPv6 source address (X’) */
    bib_entry_t = bib_get_by_ipv6_only( &tuple->src.addr.ipv6, protocol );

    if ( bib_entry_t != NULL )
    {
    	/* Use the same IPv4 address (T). */
        struct ipv4_tuple_address temp;
        transport_address_ipv4(bib_entry_t->ipv4.address, tuple->src.l4_id, &temp);
        return pool4_get_similar(protocol, &temp, result);
    }
    else
    {
    	/* create a new BIB entry and ask the IPv4 pool for a new IPv4 address. */
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
static bool allocate_ipv4_transport_address_digger(struct tuple *tuple, u_int8_t protocol,
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
            break; /* We found one entry! */
        }
    }
    
    if ( address != NULL )
    {
        /* Use the same address */
        struct ipv4_tuple_address temp;
        transport_address_ipv4(*address, tuple->src.l4_id, &temp);
        return pool4_get_similar(protocol, &temp, result);
    }
    else
    {
        /* Use whichever address */
        return pool4_get_any(protocol, tuple->src.l4_id, result);
    }
}

/** Determine if a packet is IPv4 .
 * 
 * @param[in]   packet  The incoming packet.
 * @return  true if it is OK, false otherwise.
 */
static bool packet_is_ipv4(struct sk_buff* skb)
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
static bool packet_is_ipv6(struct sk_buff* skb)
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
static bool packet_is_v4_syn(struct sk_buff* skb)
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
static bool packet_is_v6_syn(struct sk_buff* skb)
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
static bool packet_is_v4_fin(struct sk_buff* skb)
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
static bool packet_is_v6_fin(struct sk_buff* skb)
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
static bool packet_is_v4_rst(struct sk_buff* skb)
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
static bool packet_is_v6_rst(struct sk_buff* skb)
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
static bool send_probe_packet(struct session_entry *entry)
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
    iph->hop_limit = 64; /* TODO (warning) set this value during send_packet_ipv6 using dst? */
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

    /* Send the packet */
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

static inline void apply_policies(void)
{
	/* TODO (later) decide whether resources and policy allow filtering to continue. */
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
static int ipv6_udp(struct sk_buff *skb, struct tuple *tuple)
{
    struct bib_entry *bib_entry_p;
    struct session_entry *session_entry_p;
    struct ipv4_tuple_address bib_ipv4_addr;
    struct in_addr destination_as_ipv4;
    struct ipv6_tuple_address source;
    struct ipv4_pair pair4;
    struct ipv6_pair pair6;
    u_int8_t protocol = IPPROTO_UDP;
    bool bib_is_local = false;
    
    /* Pack source address into transport address */
    transport_address_ipv6( tuple->src.addr.ipv6, tuple->src.l4_id, &source );

    /* Check if a previous BIB entry exist, look for IPv6 source transport address (X’,x). */
    spin_lock_bh(&bib_session_lock);
    bib_entry_p = bib_get_by_ipv6( &source, protocol );

    /* If not found, try to create a new one. */
    if ( bib_entry_p == NULL )
    {
        /* Find a similar transport address (T, t) */
        if ( !allocate_ipv4_transport_address(tuple, protocol, &bib_ipv4_addr) )
        {
            log_warning("Could not 'allocate' a compatible transport address for the packet.");
            goto bib_failure;
        }

        /* Create the BIB entry */
        bib_entry_p = bib_create(&bib_ipv4_addr, &source, false);
        if ( bib_entry_p == NULL )
        {
            log_err(ERR_ALLOC_FAILED, "Failed to allocate a BIB entry.");
            goto bib_failure;
        }

        bib_is_local = true;

        apply_policies();

        /* Add the BIB entry */
        if ( bib_add(bib_entry_p, protocol) != 0 )
        {
        	kfree(bib_entry_p);
            log_err(ERR_ADD_BIB_FAILED, "Could not add the BIB entry to the table.");
            goto bib_failure;
        }
    }

    /* Once we have a BIB entry do ... */
    
    session_entry_p = session_get( tuple );

    /* If session was not found, then try to create a new one. */
    if ( session_entry_p == NULL )
    {
        /* Translate address */
        if ( !extract_ipv4(&tuple->dst.addr.ipv6, &destination_as_ipv4) ) /* Z(Y') */
        {
            log_err(ERR_EXTRACT_FAILED, "Could not translate the packet's address.");
            goto session_failure;
        }

        /* Create the session entry */
        pair6.remote.address = tuple->src.addr.ipv6; /* X' */
        pair6.remote.l4_id = tuple->src.l4_id; /* x */
        pair6.local.address = tuple->dst.addr.ipv6; /* Y' */
        pair6.local.l4_id = tuple->dst.l4_id; /* y */
        pair4.local = bib_entry_p->ipv4; /* (T, t) */
        pair4.remote.address = destination_as_ipv4; /* Z or Z(Y’) */
        pair4.remote.l4_id = tuple->dst.l4_id; /* z or y */
        session_entry_p = session_create(&pair4, &pair6, protocol);
        if ( session_entry_p == NULL )
        {
            log_err(ERR_ALLOC_FAILED, "Failed to allocate a session entry.");
            goto session_failure;
        }

        apply_policies();

        /* Add the session entry */
        if ( session_add(session_entry_p) != 0 )
        {
        	kfree(session_entry_p);
            log_err(ERR_ADD_SESSION_FAILED, "Could not add the session entry to the table.");
            goto session_failure;
        }

        /* Cross-reference them. */
        session_entry_p->bib = bib_entry_p;
        list_add(&session_entry_p->entries_from_bib, &bib_entry_p->sessions);
    }
    
    /* Reset session entry's lifetime. */
    update_session_lifetime(session_entry_p, &config.to.udp); 
    spin_unlock_bh(&bib_session_lock);

    return NF_ACCEPT;

session_failure:
    if ( bib_is_local ) {
        bib_remove(bib_entry_p, protocol);
        pool4_return(protocol, &bib_entry_p->ipv4);
        kfree(bib_entry_p);
    }
    /* Fall through. */

bib_failure:
    spin_unlock_bh(&bib_session_lock);
    /* This is specified in section 3.5.1.1. */
    icmpv6_send(skb, ICMPV6_DEST_UNREACH, ICMPV6_ADDR_UNREACH, 0);
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
static int ipv4_udp(struct sk_buff* skb, struct tuple *tuple)
{
    struct bib_entry *bib_entry_p;
    struct session_entry *session_entry_p;
    struct in6_addr source_as_ipv6;
    struct ipv4_tuple_address destination;
    struct ipv4_pair pair4;
    struct ipv6_pair pair6;
    u_int8_t protocol = IPPROTO_UDP;
    /*
	 * We don't want to call icmp_send() while the spinlock is held, so this will tell whether and
	 * what should be sent.
	 */
	int icmp_error = -1;

    /* Pack source address into transport address */
    transport_address_ipv4( tuple->dst.addr.ipv4, tuple->dst.l4_id, &destination );

    spin_lock_bh(&bib_session_lock);

    /* Check if a previous BIB entry exist, look for IPv4 destination transport address (T,t). */
    bib_entry_p = bib_get_by_ipv4( &destination, protocol );
    if ( bib_entry_p == NULL )
    {
        log_warning("There is no BIB entry for the incoming IPv4 UDP packet.");
        icmp_error = ICMP_HOST_UNREACH;
        goto failure;
    }
    
    /* If we're applying address-dependent filtering in the IPv4 interface, */
    if ( address_dependent_filtering() && !session_allow(tuple) )
    {
        log_info("Packet was blocked by address-dependent filtering.");
        icmp_error = ICMP_PKT_FILTERED;
        goto failure;
    }

    /* Find the Session Table Entry corresponding to the incoming tuple */
    session_entry_p = session_get( tuple );
    
    if ( session_entry_p == NULL )
    {
        /* Translate address */
        if ( !append_ipv4(&tuple->src.addr.ipv4, &source_as_ipv6) ) /* Y’(W) */
        {
            log_err(ERR_APPEND_FAILED, "Could not translate the packet's address.");
            icmp_error = ICMP_HOST_UNREACH;
			goto failure;
        }

        /* Create the session entry */
        pair6.remote = bib_entry_p->ipv6; /* (X', x) */
        pair6.local.address = source_as_ipv6; /* Y’(W) */
        pair6.local.l4_id = tuple->src.l4_id; /* w */
        pair4.local.address = tuple->dst.addr.ipv4; /* T */
        pair4.local.l4_id = tuple->dst.l4_id; /* t */
        pair4.remote.address = tuple->src.addr.ipv4; /* W */
        pair4.remote.l4_id = tuple->src.l4_id; /* w */
        session_entry_p = session_create(&pair4, &pair6, protocol);
        if ( session_entry_p == NULL )
        {
        	log_err(ERR_ALLOC_FAILED, "Failed to allocate a session entry.");
        	icmp_error = ICMP_HOST_UNREACH;
			goto failure;
        }

        apply_policies();

        /* Add the session entry */
        if ( session_add(session_entry_p) != 0 )
        {
        	kfree(session_entry_p);
        	log_err(ERR_ADD_SESSION_FAILED, "Could not add the session entry to the table.");
        	icmp_error = ICMP_HOST_UNREACH;
			goto failure;
        }

        /* Cross-reference them. */
		session_entry_p->bib = bib_entry_p;
		list_add(&session_entry_p->entries_from_bib, &bib_entry_p->sessions);
    }
    
    /* Reset session entry's lifetime. */
    update_session_lifetime(session_entry_p, &config.to.udp);
    spin_unlock_bh(&bib_session_lock);
        
    return NF_ACCEPT;

failure:
    spin_unlock_bh(&bib_session_lock);

    /*
	 * This is is not specified most of the time, but I assume we're supposed to do it, in order
	 * to maintain symmetry with IPv6-UDP.
	 */
    if (icmp_error != -1)
    	icmp_send(skb, ICMP_DEST_UNREACH, icmp_error, 0);

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
static int ipv6_icmp6(struct sk_buff *skb, struct tuple *tuple)
{
    struct bib_entry *bib_entry_p;
    struct session_entry *session_entry_p;
    struct ipv4_tuple_address bib_ipv4_addr;
    struct in_addr destination_as_ipv4;
    struct ipv6_tuple_address source;
    struct ipv4_pair pair4;
    struct ipv6_pair pair6;
    u_int8_t protocol = IPPROTO_ICMP;
    bool bib_is_local = false;
    
    if ( filter_icmpv6_info() )
    {
    	log_info("Packet is ICMPv6 info; dropping due to policy.");
        return NF_DROP;
    }

    /* Pack source address into transport address */
    transport_address_ipv6( tuple->src.addr.ipv6, tuple->icmp_id, &source );
    
    /* Search for an ICMPv6 Query BIB entry that matches the (X’,i1) pair. */
    spin_lock_bh(&bib_session_lock);
    bib_entry_p = bib_get_by_ipv6( &source, protocol );

    /* If not found, try to create a new one. */
    if ( bib_entry_p == NULL )
    {
        /* Look in the BIB tables for a previous packet from the same origin (X') */
    	if ( !allocate_ipv4_transport_address_digger(tuple, protocol, &bib_ipv4_addr) )
        {
        	log_warning("Could not 'allocate' a compatible transport address for the packet.");
            goto bib_failure;
        }

        /* Create the BIB entry */
        bib_entry_p = bib_create(&bib_ipv4_addr, &source, false);
        if ( bib_entry_p == NULL )
        {
        	log_err(ERR_ALLOC_FAILED, "Failed to allocate a BIB entry.");
        	goto bib_failure;
        }

        bib_is_local = true;

        apply_policies();

        /* Add the new BIB entry */
        if ( bib_add(bib_entry_p, protocol) != 0 )
        {
        	kfree(bib_entry_p);
        	log_err(ERR_ADD_BIB_FAILED, "Could not add the BIB entry to the table.");
        	goto bib_failure;
        }
    }

    /* OK, we have a BIB entry to work with... */

    /* Search an ICMP STE corresponding to the incoming 3-tuple (X’,Y’,i1). */
    session_entry_p = session_get( tuple );

    /* If NO session was found: */
    if ( session_entry_p == NULL )
    {
        /* Translate address from IPv6 to IPv4 */
        if ( !extract_ipv4(&tuple->dst.addr.ipv6, &destination_as_ipv4) ) /* Z(Y') */
        {
        	log_err(ERR_EXTRACT_FAILED, "Could not translate the packet's address.");
            goto session_failure;
        }

        /* Create the session entry */
        pair6.remote.address = tuple->src.addr.ipv6;      /* (X') */
        pair6.remote.l4_id = tuple->icmp_id;              /* (i1) */
        pair6.local.address = tuple->dst.addr.ipv6;       /* (Y') */
        pair6.local.l4_id = tuple->icmp_id;               /* (i1) */
        pair4.local = bib_entry_p->ipv4;                  /* (T, i2) */
        pair4.remote.address = destination_as_ipv4;       /* (Z(Y’)) */
        pair4.remote.l4_id = bib_entry_p->ipv4.l4_id;     /* (i2) */
        session_entry_p = session_create(&pair4, &pair6, protocol);
        if ( session_entry_p == NULL )
        {
        	log_err(ERR_ALLOC_FAILED, "Failed to allocate a session entry.");
            goto session_failure;
        }

        apply_policies();

        /* Add the session entry */
        if ( session_add(session_entry_p) != 0 )
        {
        	kfree(session_entry_p);
        	log_err(ERR_ADD_SESSION_FAILED, "Could not add the session entry to the table.");
            goto session_failure;
        }

        /* Cross-reference them. */
        session_entry_p->bib = bib_entry_p;
        list_add(&session_entry_p->entries_from_bib, &bib_entry_p->sessions);
    }
    
    /* Reset session entry's lifetime. */
    update_session_lifetime(session_entry_p, &config.to.icmp);
    spin_unlock_bh(&bib_session_lock);

    return NF_ACCEPT;

session_failure:
    if ( bib_is_local ) {
        bib_remove(bib_entry_p, protocol);
        pool4_return(protocol, &bib_entry_p->ipv4);
        kfree(bib_entry_p);
    }
    /* Fall through. */

bib_failure:
    spin_unlock_bh(&bib_session_lock);
    /*
     * This is is not specified, but I assume we're supposed to do it, since otherwise this entire
     * thing is so similar to UDP.
     */
    icmpv6_send(skb, ICMPV6_DEST_UNREACH, ICMPV6_ADDR_UNREACH, 0);
    return NF_DROP;
}

/** Process an incoming ICMPv4 Query packet with source IPv4 address (Y), destination 
 *  IPv4 address (X), and ICMPv4 Identifier (i2)
 *  Second half of rfc 6146 section 3.5.3
 * 
 * @param[in]   tuple   Tuple obtained from incoming packet
 * @return  NF_ACCEPT if everything went OK, NF_DROP otherwise.
 */
static int ipv4_icmp4(struct sk_buff* skb, struct tuple *tuple)
{
    struct bib_entry *bib_entry_p;
    struct session_entry *session_entry_p;
    struct in6_addr source_as_ipv6;
    struct ipv4_tuple_address destination;
    struct ipv4_pair pair4;
    struct ipv6_pair pair6;
    u_int8_t protocol = IPPROTO_ICMP;
    /*
     * We don't want to call icmp_send() while the spinlock is held, so this will tell whether and
     * what should be sent.
     */
    int icmp_error = -1;
    
    /* Pack source address into transport address */
    transport_address_ipv4( tuple->dst.addr.ipv4, tuple->icmp_id, &destination );
    
    spin_lock_bh(&bib_session_lock);

    /* Find the packet's BIB entry. */
    bib_entry_p = bib_get_by_ipv4( &destination, protocol );
    if ( bib_entry_p == NULL )
    {
        log_warning("There is no BIB entry for the incoming IPv4 ICMP packet.");
        icmp_error = ICMP_HOST_UNREACH;
        goto failure;
    }

    /* If we're applying address-dependent filtering in the IPv4 interface, */
    if ( address_dependent_filtering() && !session_allow(tuple) )
    {
        log_info("Packet was blocked by address-dependent filtering.");
        icmp_error = ICMP_PKT_FILTERED;
        goto failure;
    }

    /* Search the Session Table Entry corresponding to the incoming tuple */
    session_entry_p = session_get( tuple );
    
    if ( session_entry_p == NULL )
    {
        /* Translate the address */
        if ( !append_ipv4(&tuple->src.addr.ipv4, &source_as_ipv6) ) /* Y’(Z) */
        {
        	log_err(ERR_APPEND_FAILED, "Could not translate the packet's address.");
        	icmp_error = ICMP_HOST_UNREACH;
			goto failure;
        }

        /* Create the session entry. */
        pair6.remote = bib_entry_p->ipv6; /* X', i1 */
        pair6.local.address = source_as_ipv6; /* Y'(Z) */
        pair6.local.l4_id = bib_entry_p->ipv6.l4_id; /* i1 */
        pair4.local.address = tuple->dst.addr.ipv4; /* T */
        pair4.local.l4_id = tuple->icmp_id; /* i2 */
        pair4.remote.address = tuple->src.addr.ipv4; /* Z */
        pair4.remote.l4_id = tuple->icmp_id; /* i2 */
        session_entry_p = session_create(&pair4, &pair6, protocol);
        if ( session_entry_p == NULL )
        {
        	log_err(ERR_ALLOC_FAILED, "Failed to allocate a session entry.");
        	icmp_error = ICMP_HOST_UNREACH;
        	goto failure;
        }

        apply_policies();

        /* Add the session entry */
        if ( session_add(session_entry_p) != 0 )
        {
        	kfree(session_entry_p);
        	log_err(ERR_ADD_SESSION_FAILED, "Could not add the session entry to the table.");
        	icmp_error = ICMP_HOST_UNREACH;
        	goto failure;
        }

        /* Cross-reference them. */
		session_entry_p->bib = bib_entry_p;
		list_add(&session_entry_p->entries_from_bib, &bib_entry_p->sessions);
    }

    /* Reset session entry's lifetime. */
    update_session_lifetime(session_entry_p, &config.to.icmp);
    spin_unlock_bh(&bib_session_lock);

    return NF_ACCEPT;

failure:
    spin_unlock_bh(&bib_session_lock);

	/*
	 * Sending an ICMP error is not specified, but I assume we're supposed to do it, since
	 * otherwise this entire thing is so similar to UDP.
	 */
    if (icmp_error != -1)
    	icmp_send(skb, ICMP_DEST_UNREACH, icmp_error, 0);

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

static bool tcp_closed_v6_syn(struct sk_buff* skb, struct tuple *tuple)
{
	struct bib_entry *bib_entry_p;
	struct session_entry *session_entry_p;
	struct ipv6_tuple_address source;
	struct ipv4_tuple_address bib_ipv4_addr;
	struct in_addr destination_as_ipv4;
	struct ipv6_pair pair6;
	struct ipv4_pair pair4;
	u_int8_t protocol = IPPROTO_TCP;
	bool bib_is_local = false;

	/* Pack source address into transport address */
	transport_address_ipv6(tuple->src.addr.ipv6, tuple->src.l4_id, &source);

	/* Check if a previous BIB entry exist, look for IPv6 source transport address (X’,x). */
	bib_entry_p = bib_get_by_ipv6(&source, protocol);

	/* If bib does not exist, try to create a new one, */
	if (bib_entry_p == NULL) {
		/* Obtain a new BIB IPv4 transport address (T,t), put it in new_ipv4_transport_address. */
		if (!allocate_ipv4_transport_address_digger(tuple, protocol, &bib_ipv4_addr)) {
			log_warning("Could not 'allocate' a compatible transport address for the packet.");
			goto bib_failure;
		}

		/* Create the BIB entry */
		bib_entry_p = bib_create(&bib_ipv4_addr, &source, false);
		if (bib_entry_p == NULL) {
			log_err(ERR_ALLOC_FAILED, "Failed to allocate a BIB entry.");
			goto bib_failure;
		}

		bib_is_local = true;

		apply_policies();

		/* Add the new BIB entry */
		if (bib_add(bib_entry_p, protocol) != 0) {
			log_err(ERR_ADD_BIB_FAILED, "Could not add the BIB entry to the table.");
			goto bib_failure;
		}
	}

	/* Now that we have a BIB entry... */

	/* Translate address*/
	if (!extract_ipv4(&tuple->dst.addr.ipv6, &destination_as_ipv4)) { /* Z(Y') */
		log_err(ERR_EXTRACT_FAILED, "Could not translate the packet's address.");
		goto session_failure;
	}

	/* Create the session entry. */
	pair6.remote.address = tuple->src.addr.ipv6; /* X' */
	pair6.remote.l4_id = tuple->src.l4_id; /* x */
	pair6.local.address = tuple->dst.addr.ipv6; /* Y' */
	pair6.local.l4_id = tuple->dst.l4_id; /* y */
	pair4.local = bib_entry_p->ipv4; /* (T, t) */
	pair4.remote.address = destination_as_ipv4; /* Z or Z(Y’) */
	pair4.remote.l4_id = tuple->dst.l4_id; /* z or y */

	session_entry_p = session_create(&pair4, &pair6, protocol);
	if (session_entry_p == NULL) {
		log_err(ERR_ALLOC_FAILED, "Failed to allocate a session entry.");
		goto session_failure;
	}

	update_session_lifetime(session_entry_p, &config.to.tcp_trans);
	session_entry_p->state = V6_INIT;

	apply_policies();

	if (session_add(session_entry_p) != 0) {
		kfree(session_entry_p);
		log_err(ERR_ADD_SESSION_FAILED, "Could not add the session entry to the table.");
		goto session_failure;
	}

	/* Cross-reference them. */
	session_entry_p->bib = bib_entry_p;
	list_add(&session_entry_p->entries_from_bib, &bib_entry_p->sessions);

	return true;

session_failure:
	if (bib_is_local) {
		bib_remove(bib_entry_p, protocol);
		pool4_return(protocol, &bib_entry_p->ipv4);
		kfree(bib_entry_p);
	}
	/* Fall through. */

bib_failure:
	/* TODO (later) We're sending this while the spinlock is held; this might be really slow. */
	icmpv6_send(skb, ICMPV6_DEST_UNREACH, ICMPV6_ADDR_UNREACH, 0);
	return false;
}

static bool tcp_closed_v4_syn(struct sk_buff* skb, struct tuple *tuple)
{
	struct bib_entry *bib_entry_p = NULL;
	struct session_entry *session_entry_p = NULL;
	struct ipv4_tuple_address destination;
	struct in6_addr ipv6_local;
	struct ipv6_pair pair6;
	struct ipv4_pair pair4;
	u_int8_t protocol = IPPROTO_TCP;

	if (drop_external_connections()) {
		log_info("Applying policy: Dropping externally initiated TCP connections.");
		return false;
	}

	/* Pack addresses and ports into transport address */
	transport_address_ipv4(tuple->dst.addr.ipv4, tuple->dst.l4_id, &destination);

	/* Translate address */
	if (!append_ipv4(&tuple->src.addr.ipv4, &ipv6_local)) { /* Y'(Y) */
		log_err(ERR_APPEND_FAILED, "Could not translate the packet's address.");
		goto failure;
	}

	/* Look for the destination transport address (X,x) in the BIB */
	bib_entry_p = bib_get_by_ipv4(&destination, protocol);

	if (bib_entry_p == NULL) {
		/* Try to create a new session entry anyway! */
		unsigned int temp = TCP_INCOMING_SYN;

		log_warning("Unknown TCP connections started from the IPv4 side is still unsupported. "
				"Dropping packet...");
		goto failure;

		/*
		 * Side:   <-------- IPv6 -------->  N  <------- IPv4 ------->
		 * Packet: dest(X',x) <--- src(Y',y) A  dest(X,x) <-- src(Y,y)
		 * NAT64:  remote              local T  local           remote
		 */

		/* Create the session entry */
		/* pair6.remote = Not_Available; (X', x) INTENTIONALLY LEFT UNSPECIFIED! */
		pair6.local.address = ipv6_local; /* (Y', y) */
		pair6.local.l4_id = tuple->src.l4_id;
		pair4.local.address = tuple->dst.addr.ipv4; /* (X, x)  (T, t) */
		pair4.local.l4_id = tuple->dst.l4_id;
		pair4.remote.address = tuple->src.addr.ipv4; /* (Z(Y’),y) or (Z, z) */
		pair4.remote.l4_id = tuple->src.l4_id;

		session_entry_p = session_create(&pair4, &pair6, protocol);
		if (session_entry_p == NULL) {
			log_err(ERR_ALLOC_FAILED, "Failed to allocate a session entry.");
			goto failure;
		}

		session_entry_p->state = V4_INIT;
		update_session_lifetime(session_entry_p, &temp);

		/* TODO (later) store the packet.
		 *          The result is that the NAT64 will not drop the packet based on the filtering,
		 *          nor create a BIB entry.  Instead, the NAT64 will only create the Session
		 *          Table Entry and store the packet. The motivation for this is to support
		 *          simultaneous open of TCP connections. */

	} else {

		/* BIB entry exists; create the session entry. */
		pair6.remote = bib_entry_p->ipv6; /* (X', x) */
		pair6.local.address = ipv6_local; /* (Y', y) */
		pair6.local.l4_id = tuple->src.l4_id;
		pair4.local.address = tuple->dst.addr.ipv4; /* (X, x)  (T, t) */
		pair4.local.l4_id = tuple->dst.l4_id;
		pair4.remote.address = tuple->src.addr.ipv4; /* (Z(Y’),y) or (Z, z) */
		pair4.remote.l4_id = tuple->src.l4_id;

		session_entry_p = session_create(&pair4, &pair6, protocol);
		if (session_entry_p == NULL) {
			log_err(ERR_ALLOC_FAILED, "Failed to allocate a session entry.");
			goto failure;
		}

		session_entry_p->state = V4_INIT;
		if (address_dependent_filtering()) {
			unsigned int temp = TCP_INCOMING_SYN;
			update_session_lifetime(session_entry_p, &temp);
		} else {
			update_session_lifetime(session_entry_p, &config.to.tcp_trans);
		}
	}

	apply_policies();

	if (session_add(session_entry_p) != 0) {
		kfree(session_entry_p);
		log_err(ERR_ADD_SESSION_FAILED, "Could not add the session entry to the table.");
		goto failure;
	}

	/* Cross-reference them. */
	session_entry_p->bib = bib_entry_p;
	list_add(&session_entry_p->entries_from_bib, &bib_entry_p->sessions);

	return true;

failure:
	icmp_send(skb, ICMP_DEST_UNREACH, ICMP_HOST_UNREACH, 0);
	return false;
}

/** CLOSED state
 *
 *  Handle SYN packets.
 *
 * @param[in]   packet  The incoming packet.
 * @param[in]   tuple   Tuple of the incoming packet.
 * @return  true if everything went OK, false otherwise.
 */
static bool tcp_closed_state_handle(struct sk_buff* skb, struct tuple *tuple)
{
	struct bib_entry *bib_entry_p = NULL;
	struct ipv6_tuple_address ipv6_ta;
	struct ipv4_tuple_address ipv4_ta;
	u_int8_t protocol = IPPROTO_TCP;

	/* SYN packets */
	if (packet_is_v6_syn(skb))
		return tcp_closed_v6_syn(skb, tuple);

	if (packet_is_v4_syn(skb))
		return tcp_closed_v4_syn(skb, tuple);

	/* Non-SYN packets */
	if (packet_is_ipv6(skb)) {
		/* Pack source address into transport address */
		transport_address_ipv6(tuple->src.addr.ipv6, tuple->src.l4_id, &ipv6_ta);

		/* Look if there is a corresponding entry in the TCP BIB */
		bib_entry_p = bib_get_by_ipv6(&ipv6_ta, protocol);
		if (!bib_entry_p)
			log_warning("BIB entry not found for %pI6c#%u.", &tuple->src.addr.ipv6, tuple->src.l4_id);

	} else if (packet_is_ipv4(skb)) {
		/* Pack addresses and ports into transport address */
		transport_address_ipv4(tuple->dst.addr.ipv4, tuple->dst.l4_id, &ipv4_ta);

		/* Look for the destination transport address (X,x) in the BIB */
		bib_entry_p = bib_get_by_ipv4(&ipv4_ta, protocol);
		if (!bib_entry_p)
			log_warning("BIB entry not found for %pI4#%u.", &tuple->dst.addr.ipv4, tuple->dst.l4_id);
	}

	return (bib_entry_p != NULL);
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
    } /* else, the state remains unchanged. */

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
    } /* else, the state remains unchanged */
    
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
    /* Only the timeout can change this state. */
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
					/* TODO (later) send the stored packet.
					 * If the lifetime expires, an ICMP Port Unreachable error (Type 3, Code 3) containing the
					 * IPv4 SYN packet stored is sent back to the source of the v4 SYN, the Session Table Entry
					 * is deleted, and the state is moved to CLOSED. */
					/* send_icmp_error_message(skb, DESTINATION_UNREACHABLE, ADDRESS_UNREACHABLE); */
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
					/*
					 * Because closed sessions are not supposed to be stored,
					 * CLOSED is known to fall through here.
					 */
					log_err(ERR_INVALID_STATE, "Invalid state found; removing session entry.");
					return false;
			}
			return false;
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
static int tcp(struct sk_buff* skb, struct tuple *tuple)
{
    struct session_entry *session_entry_p;
    bool result;
    
    spin_lock_bh(&bib_session_lock);
    session_entry_p = session_get( tuple );

    /* If NO session was found: */
    if ( session_entry_p == NULL ) {
        result = tcp_closed_state_handle(skb, tuple);
        goto end;
    }

    /* Act according the current state. */
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
        	/*
        	 * Because closed sessions are not supposed to be stored,
        	 * CLOSED is known to fall through here.
        	 */
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
        /* Errores de ICMP no deben afectar las tablas. */
        if ( IPPROTO_ICMPV6 == tuple->l3_proto && is_icmp6_error(icmp6_hdr(skb)->icmp6_type) )
		{
			log_debug("Packet is ICMPv6 info, ignoring...");
			return NF_ACCEPT;
		}
        /* Get rid of hairpinning loop and unwanted packets. */
        if ( pool6_contains(&tuple->src.addr.ipv6) || !pool6_contains(&tuple->dst.addr.ipv6) )
        {
			log_info("Packet was rejected by pool6, dropping...");
			return NF_DROP;
		}
    }
            
    if ( PF_INET == tuple->l3_proto ) {
        /* Errores de ICMP no deben afectar las tablas. */
        if ( IPPROTO_ICMP == tuple->l4_proto && is_icmp4_error(icmp_hdr(skb)->type) )
        {
			log_debug("Packet is ICMPv4 info, ignoring...");
			return NF_ACCEPT;
		}

        /* Get rid of unexpected packets */
        if ( !pool4_contains(&tuple->dst.addr.ipv4) )
        {
			log_info("Packet was rejected by pool4, dropping...");
			return NF_DROP;
		}
    }

    /* Process packet, according to its protocol. */
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
