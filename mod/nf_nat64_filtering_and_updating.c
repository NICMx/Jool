//~ #include "filtering_helper.h"
#include "nf_nat64_filtering_and_updating.h"
#include "nf_nat64_config.h"
#include "xt_nat64_module_conf_validation.h"
#include "nf_nat64_rfc6052.h"
#include "nf_nat64_constants.h"

#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/skbuff.h>

extern struct config_struct cs; /**< This struct holds the entire valid and running configuration. */


///// This functions must properly defined somewhere:
///// BEGIN

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
{ // Put this function and the one in filtering_tcp.c in common header file.
    ta->address = addr;
    ta->pi.port = pi; // Don't care if it's ICMP IP or PORT, they are of the same size.
}

/** Join a IPv6 address and a port (or ICMP ID) to create a Transport Address.
 *
 * @param[in]  addr IPv6 Address
 * @param[in]  pi   Port or ICMP ID
 * @param[out] ta   Transport Address
 * */
void transport_address_ipv6(struct in6_addr addr, __be16 pi, struct ipv6_tuple_address *ta)
{ // Put this function and the one in filtering_tcp.c in common header file.
    ta->address = addr;
    ta->pi.port = pi; // Don't care if it's ICMP IP or PORT, they are of the same size.
}

/** Retrieve a new transport address from IPv4 pool.
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
 * @param[in]   pi          Look for a port within the same range and parity.
 * @param[out]  new_ipv4_transport_address  New transport address obtained from the PROTOCOL's pool.
 * @return  true if everything went OK, false otherwise.
 * */
int ipv4_pool_get_new_transport_address( u_int8_t protocol,
    __be16 pi, struct ipv4_tuple_address *new_ipv4_transport_address);
int ipv4_pool_get_new_transport_address( u_int8_t protocol,
    __be16 pi, struct ipv4_tuple_address *new_ipv4_transport_address)
{
    /* WARNING! ACHTUNG! VORSICHT! 
     *      This function have a hard-coded response.
     * 
     *      Replace this by the right function from the IPv4 pool code.
     * */

    struct in_addr addr4;

    pr_debug("NAT64: UN-IMPLEMENTED FUNCTION: call to hard-coded function 'ipv4_pool_get_new_transport_address()'");

    if (!str_to_addr4(IPV4_DEF_POOL_FIRST, &addr4)) {
    	log_warning("Invalid IP address: %s", IPV4_DEF_POOL_FIRST);
    	return false;
    }

    transport_address_ipv4( addr4, htons(ntohs(pi) + 2), new_ipv4_transport_address );

    return true;
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
int ipv4_pool_get_new_port(
    struct in_addr address, __be16 pi,
    u_int8_t protocol,
    struct ipv4_tuple_address *new_ipv4_transport_address);
int ipv4_pool_get_new_port(
    struct in_addr address, __be16 pi,
    u_int8_t protocol,
    struct ipv4_tuple_address *new_ipv4_transport_address)
{
    /* WARNING! ACHTUNG! VORSICHT! 
     *      This function have a hard-coded response.
     * 
     *      Replace this by the right function from the IPv4 pool code.
     * */

    pr_debug("NAT64: UN-IMPLEMENTED FUNCTION: call to hard-coded function 'ipv4_pool_get_new_port()'");

    transport_address_ipv4( address, htons(ntohs(pi) + 2), new_ipv4_transport_address );

    return true;
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
bool  allocate_ipv4_transport_address(struct nf_conntrack_tuple *tuple, 
                                     u_int8_t protocol, 
                                     struct ipv4_tuple_address *new_ipv4_transport_address)
{
    struct bib_entry *bib_entry_t;
    
    int ret = 0;

    // Check if the BIB has a previous entry from the same IPv6 source address (X’)
    bib_entry_t = nat64_get_bib_entry_by_ipv6_only( &tuple->ipv6_src_addr, protocol );

    // If true, use the same IPv4 address (T). 
    if ( bib_entry_t != NULL )
    {
        // TODO: Should we include the protocol in this func.?
        // Obtain a new port (t) for the found IPv4 address (T).
        ret = ipv4_pool_get_new_port(bib_entry_t->ipv4.address, 
                                     tuple->src_port,
                                     protocol,                                         
                                     new_ipv4_transport_address);
        if ( ret == false )
        {
            /* If it is not possible to allocate an appropriate IPv4 transport
             address or create a BIB entry, then the packet is discarded. The
             NAT64 SHOULD send an ICMPv6 Destination Unreachable error message
             with Code 3 (Address Unreachable). */
            
            pr_warning("NAT64:  Could NOT get a new port, from the IPv4 pool, for the IPv4 address found.");
            pr_warning("        Dropping packet.");
                        
            return false;
        }       
    }
    else // Else, create a new BIB entry and ask the IPv4 pool for a new IPv4 address.
    {
        // Obtain a new BIB IPv4 transport address (T,t).
        ret = ipv4_pool_get_new_transport_address(protocol, tuple->src_port, new_ipv4_transport_address);
        if ( ret == false )
        {
            /* If it is not possible to allocate an appropriate IPv4 transport
             address or create a BIB entry, then the packet is discarded. The
             NAT64 SHOULD send an ICMPv6 Destination Unreachable error message
             with Code 3 (Address Unreachable). */
            
            pr_warning("NAT64:  Could NOT get a new IPv4 transport address from the IPv4 pool");
            pr_warning("        Dropping packet.");
                        
            return false;
        }
    }
    // Everything went OK, 
    return true;
}

/** Obtains a IPv4 transport address, looking for IPv4 address previously assingned
 *  to the Source's machine, search in the BIBs: TCP, UDP & ICMP.
 *
 *  RFC6146 - Sec. 3.5.2.3
 * 
 *  Check the posibility of join this func. and 'allocate_ipv4_transport_address'
 *
 * @param[in]   tuple       Packet's tuple containg the source address.
 * @param[in]   protocol    In what protocolo we should look at FIRST?
 * @param[out]  new_ipv4_transport_address  New transport address obtained from the PROTOCOL's pool.
 * @return  true if everything went OK, false otherwise.
 */
bool allocate_ipv4_transport_address_digger(struct nf_conntrack_tuple *tuple, 
                                     u_int8_t protocol, 
                                     struct ipv4_tuple_address *new_ipv4_transport_address)
{ // TODO: join this function and the one in filtering_tcp.h
    struct bib_entry *bib_entry_p;
    unsigned char ii = 0;
int jj = 0;    
    u_int8_t proto[] = {IPPROTO_ICMP, IPPROTO_TCP, IPPROTO_UDP};

    /*  If there exists another BIB entry in any of the BIBs that
        contains the same IPv6 source address (S’) and maps it to an IPv4
        address (T), then use (T) as the BIB IPv4 address for this new
        entry. Otherwise, use any IPv4 address assigned to the IPv4
        interface. */
    
    /*  Look in the three BIB tables for a previous packet from the same origin (S'),
     *  we will do this anyway. */
    for (ii = 0 ; ii < 3 ; ii++)
    {
pr_debug("-- ipv6 src addr = %pI6c , proto= %d", &tuple->ipv6_src_addr, proto[ii]);
        bib_entry_p = nat64_get_bib_entry_by_ipv6_only(&tuple->ipv6_src_addr, proto[ii]);
        
        if (bib_entry_p != NULL)
{
pr_debug("-- %d --  ii=%d  -- proto=%d  --  We found one", jj++, ii, proto[ii]);

            break; // We found one entry!
}
    }
pr_debug("-- %d --", jj++);
    
    // NOTE: this code was replaced by the following 'allocate_ipv4...' function:
    //~ // If no previous communication from the source (S') exist ...
    //~ if (bib_entry_p == NULL)
    //~ {
        //~ // Obtain a brand new BIB IPv4 transport address (T,t)
        //~ ret = ipv4_pool_get_new_transport_address(protocol, tuple->src_port, 
            //~ new_ipv4_transport_address);
        //~ if ( ret == false )
        //~ {
            //~ /* If it is not possible to allocate an appropriate IPv4 transport
             //~ address or create a BIB entry, then the packet is discarded. The
             //~ NAT64 SHOULD send an ICMPv6 Destination Unreachable error message
             //~ with Code 3 (Address Unreachable). */
            //~ 
            //~ pr_warning("NAT64:  Could NOT get a new IPv4 transport address from the IPv4 pool");
            //~ pr_warning("        Dropping packet.");
                        //~ 
            //~ return false;
        //~ }
    //~ }

    // Define BIB IPv4 transport address. 
    /* Obtain a new BIB IPv4 transport address (T,t), put it in new_ipv4_transport_address.
     * Use the protocol proto[] hint. */
    return allocate_ipv4_transport_address(tuple, proto[ii], new_ipv4_transport_address);

}


/** Extract IPv4 embedded in IPv6, as indicated by RFC6052.
 * 
 * Section 3.5.4 of RFC 6146.
 * 
 * @param[in]   ipv6    IPv6 representation of the destination address
 * @param[out]  ipv4    IPv4 representation of the destination address
 * @return  true if everything went OK, false otherwise.
 * */
int extract_ipv4_from_ipv6 (struct in6_addr ipv6, struct in_addr *ipv4)
{
    /* ATTENTION:
     *      Only the first IPv6 prefix is checked.
     *      What happens with the rest???    */
    (*ipv4) = nat64_extract_ipv4(&ipv6, cs.ipv6_net_prefixes[0]->maskbits);
    
    return true;
}

/** Reverse Translation from IPv4 address to IPv6. 
 * 
 * Embed IPv4 address in IPv6, as indicated by RFC6052.
 * Section 3.5.4 of RFC 6146.
 * 
 * @param[in]   ipv4    IPv4 representation of the destination address
 * @param[out]  ipv6    IPv6 representation of the destination address
 * @return  true if everything went OK, false otherwise.
 */
int embed_ipv4_in_ipv6 (struct in_addr ipv4, struct in6_addr *ipv6)
{
    /* ATTENTION:
     *      Only the first IPv6 prefix is used.
     *      What happens with the rest???    */
    //~ struct in6_addr nat64_append_ipv4(struct in6_addr * addr, struct in_addr * addr4, int prefix);
    (*ipv6) = nat64_append_ipv4(&cs.ipv6_net_prefixes[0]->addr, &ipv4, cs.ipv6_net_prefixes[0]->maskbits);    

    return true;
}


/** Send an ICMP error message, with a specific Type & Code, to the original 
 *  sender of the packet (tuple->source).
 * 
 * @param[in]   tuple   Tuple containing info about the communication.
 * @param[in]   type    Type of message.
 * @param[in]   code    Code of the message.
 */
bool send_icmp_error_message(struct nf_conntrack_tuple *tuple, u_int8_t type, u_int8_t code);
bool send_icmp_error_message(struct nf_conntrack_tuple *tuple, u_int8_t type, u_int8_t code)
{
    // TODO: Create me!!
    
    pr_debug("NAT64: UN-IMPLEMENTED FUNCTION: call to 'send_icmp_error_message()'");
    if ( tuple->L3_PROTOCOL == NFPROTO_IPV4 )
    {
        pr_debug("NAT64: Sending ICMPv4 error message to: %pI4#%d  ", &tuple->ipv4_src_addr, ntohs( tuple->icmp_id) );
    }
    else
    {
        pr_debug("NAT64: Sending ICMPv6 error message to: %pI6c#%d ", &tuple->ipv6_src_addr, ntohs( tuple->icmp_id) );
    }
    pr_debug("NAT64: Use a network tool (i.e. tcpdump, wireshark) to catch this packet.");
    
    return true;
}

/** Obtain a free ICMPv4 Identifier (i1).
 *  
 *  Any identifier value for which no other entry exists with the 
 *  same (IPv4 address, ICMPv4 Identifier) pair.
 * 
 * @param[in]   address IPv4 address used as reference.
 * @param[out]  pi      Free ICMPv4 Identifier.
 * @return  true if everything went OK, false otherwise.
 */ 
int get_icmpv4_identifier(struct in_addr *address, __be16 *pi);
int get_icmpv4_identifier(struct in_addr *address, __be16 *pi)
{
    /* WARNING! ACHTUNG! VORSICHT! 
     *      This function have a hard-coded response.
     * 
     *      Replace this by the right function from the IPv4 pool code.
     * */

    // TODO: implement this!
    pr_debug("NAT64: UN-IMPLEMENTED FUNCTION: call to 'get_icmpv4_identifier()'");
#define INIT_TUPLE_ICMP_ID          10
         
    (*pi) = htons(INIT_TUPLE_ICMP_ID);
     
    return true;
}

/** Determine if a packet is IPv4 .
 * 
 * @param[in]   packet  The incoming packet.
 * @return  true if it is OK, false otherwise.
 */
bool packet_is_ipv4(struct sk_buff* skb)
{
pr_debug("  in packet_is_ipv4()");
    if (skb == NULL) { pr_warning("  Error in packet_is_ipv4(): skb == NULL "); return false; }
    else
    {
    	switch (ntohs(skb->protocol)) {
    	case ETH_P_IP:
    		pr_debug("	packet_is_ipv4 - Es IPv4");
    		break;
    	case ETH_P_IPV6:
    		pr_debug("	packet_is_ipv4 - Es IPv6");
    		break;
    	default:
    		pr_debug("	packet_is_ipv4 - Esta corrupto");
    		break;
    	}

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
    // TODO: Look in kernel code if already exist a function that does this.
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
    // TODO: Look in kernel code if already exist a function that does this.
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
    // TODO: Look in kernel code if already exist a function that does this.
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
    // TODO: Look in kernel code if already exist a function that does this.
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
    // TODO: Look in kernel code if already exist a function that does this.
	struct tcphdr *hdr = tcp_hdr(skb);
	if (!hdr)
		return false;
    return packet_is_ipv6(skb) && hdr->rst;
}

#include <net/route.h>
#include <net/ip.h>
#include <net/tcp.h>
/* Send a packet to IPv4 destination
 * 
 * Codigo de Miguel */
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

/** Send a probe packet to at least one of the endpoints involved in the TCP connection.
 * 
 * @param[in]   packet  The incoming packet.
 * @return  true if it is OK, false otherwise.
 */
bool send_probe_packet(struct sk_buff* skb)
{
	// Init packet
	int tcplen;
	//~ struct sk_buff * skb;
	struct tcphdr *th;
	struct iphdr *iph;
	struct in_addr	ipv4_addr1;
	struct in_addr	ipv4_addr2;
	
	// TODO: From where are these values taken?
	static char			*ipv4_address1 = "192.168.1.1";
	static char			*ipv4_address2 = "192.168.2.1";
	

    if (str_to_addr4(ipv4_address1, &ipv4_addr1)) {
    	log_warning("Invalid IP address: %s", ipv4_address1);
    	return false;
    }
    printk("guarde la ip 1 \n");

    if (str_to_addr4(ipv4_address2, &ipv4_addr2)) {
    	log_warning("Invalid IP address: %s", ipv4_address2);
    	return false;
    }
	printk("guarde la ip 2 \n");

 	skb = alloc_skb(MAX_TCP_HEADER, GFP_ATOMIC); 
	if (skb == NULL)
		return -1; 

    /* Reserve space for headers and set control bits. */
	skb_reserve(skb, MAX_TCP_HEADER);
	skb->csum = 0;
	skb_reset_transport_header(skb);
	th = (struct tcphdr *) skb_push(skb, sizeof(struct tcphdr));
	
	// TODO: From where are these values taken?
	th->source = htons(20);  
	th->dest = htons(5000);
	
	th->check =  0;
	th->urg_ptr = 0;
 	th->seq = htonl(0);
	th->ack_seq = htonl(0); 
	th->res1 = 0;
   	th->fin=0;
	th->syn=0;
	th->rst=0;
	th->psh=0;
	th->urg=0;
	th->ece=0;
	th->cwr=0;
	th->ack=1;
    th->window = htons(8192);
	th->doff = (sizeof(struct tcphdr))/4;

	printk("llene el l4 header\n");

	skb_push(skb, sizeof(struct iphdr));
	skb_reset_network_header(skb);
	iph = ip_hdr(skb);

	iph->version = 4;
    iph->ihl = 5;
    iph->tos = 0;
    iph->tot_len = htons(skb->len);

	iph->id = 0;
	iph->ttl = 64;

    iph->protocol = IPPROTO_TCP;
    iph->saddr = ipv4_addr1.s_addr;
    iph->daddr = ipv4_addr2.s_addr;

	printk("llene el l3 header\n");

	tcplen = skb->len - ip_hdrlen(skb);
	th->check = csum_tcpudp_magic(iph->saddr, iph->daddr,tcplen, iph->protocol, 
								csum_partial(th,tcplen, 0));
    skb->ip_summed = CHECKSUM_UNNECESSARY;

	// Send the packet
	nat64_send_packet_ipv4(skb);
	printk("se mando el paquete\n");
	pr_debug("NAT64: Catch the packet using a tool like Wireshark or tcpdump\n");

    return true;
}





/* Funciones de limpieza. */

bool clean_function_simple(struct session_entry *session)
{
    // delete session entry
    return nat64_remove_session_entry(session);
}

//~ bool clean_function_return_icmp_packet(struct session_entry *session)
//~ {
    //~ struct nf_conntrack_tuple tuple;
//~ 
    //~ tuple.
    //~ 
    //~ // send ICMP type 3 code 3 containing the stored packet.
    //~ send_icmp_error_message(&tuple, DESTINATION_UNREACHABLE, ADDRESS_UNREACHABLE);
    //~ pr_debug("NAT64:  Sending ICMPv6 message: DESTINATION_UNREACHABLE, ADDRESS_UNREACHABLE");
//~ 
    //~ // delete session entry
    //~ return nat64_remove_session_entry(session);
//~ }






/** Global structure containing the actual valid configuration of the NAT. */
extern struct config_struct cs;

///// END

            
/*  Definición de niveles de debug:
- debug: info para programadores.
- info: info para admins que solo se consultaría raramente.
- notice: info para admins que se consultaría para testear el funcionamiento del sistema.
- warning: potenciales errores de configuración - el sistema nota, a través de validaciones, que lo que le pide el admin no tiene mucho sentido pero el sistema puede seguir funcionando.
- error: fatales que no permitan que el sistema siga funcionando            */


/**
 * An IPv6 incoming packet with an incoming tuple with source transport
 * address (X’,x) and destination transport address (Y’,y).
 * 
 * The result is a BIB entry as follows: (X’,x) <--> (T,t)
 *              
 * @param[in]   tuple   Tuple of the incoming packet.
 * @return  NF_ACCEPT if everything went OK, NF_DROP otherwise.
 */         
int ipv6_udp(struct nf_conntrack_tuple *tuple)
{
    struct bib_entry *bib_entry_p;
    struct session_entry *session_entry_p;
    struct ipv4_tuple_address new_ipv4_transport_address;
    struct ipv4_tuple_address ipv4_remote; // ( Z(Y'), y)
    struct ipv6_tuple_address ipv6_ta; // Transport Address temporal var.
    struct ipv6_tuple_address ipv6_ta_local; // Transport Address temporal var.
    struct ipv6_tuple_address ipv6_ta_remote; // Transport Address temporal var.
    u_int8_t protocol;
    
    int ret = 0;
    
    protocol = IPPROTO_UDP;

    // Pack source address into transport address
    transport_address_ipv6(tuple->ipv6_src_addr, tuple->src_port, &ipv6_ta);
    
    // Check if a previous BIB entry exist, look for IPv6 source transport address (X’,x).
    bib_entry_p = nat64_get_bib_entry_by_ipv6( &ipv6_ta, protocol );
    
    // TODO:    Define the checks that evaluate if resources availability 
    //          and policy allows the creation of a new entry.
    // If not found, try to create a new one.
    if ( bib_entry_p == NULL )
    {
        // TODO: Should we replace this kmalloc by a call to the func 'nat64_create_bib_entry' ?
        // Allocate memory for a new BIB entry
        bib_entry_p = (struct bib_entry *)kmalloc(sizeof(struct bib_entry), GFP_KERNEL);
        if ( bib_entry_p == NULL )
        {
            /* If it is not possible to allocate an appropriate IPv4 transport
            address or create a BIB entry, then the packet is discarded. The
            NAT64 SHOULD send an ICMPv6 Destination Unreachable error message
            with Code 3 (Address Unreachable). */

            // TODO: Check in RFC6146 if we should send the ICMPv6 error message.
            
            pr_warning("NAT64:  Could NOT create a new BIB entry for a incoming IPv6 UDP packet.");
            pr_warning("        Dropping packet.");
                        
            return NF_DROP;
        }

        // Pack source address into transport address
        //~ transport_address_ipv6(&ipv6_ta, tuple->ipv6_src_addr, tuple->src_port);
        
        // Set BIB IPv6 transport address (X',x).
        bib_entry_p->ipv6 = ipv6_ta;
    
        // Define BIB IPv4 transport address. 
        // Obtain a new BIB IPv4 transport address (T,t), put it in new_ipv4_transport_address.
        //~ ret = allocate_ipv4_transport_address(&bib, tuple, protocol, &new_ipv4_transport_address);
        ret = allocate_ipv4_transport_address(tuple, protocol, &new_ipv4_transport_address);
        if ( ret == false )
        {
            /* If it is not possible to allocate an appropriate IPv4 transport
             address or create a BIB entry, then the packet is discarded. The
             NAT64 SHOULD send an ICMPv6 Destination Unreachable error message
             with Code 3 (Address Unreachable). */

            // TODO: Should we send the ICMPv6 error message ?
            
            pr_warning("NAT64:  Could NOT allocate a new IPv4 transport address for a incoming IPv6 UDP packet.");
            pr_warning("        Dropping packet.");
        
            kfree(bib_entry_p);
            
            return NF_DROP;
        }
        
        // Set BIB IPv4 transport address (T,t).
        bib_entry_p->ipv4 = new_ipv4_transport_address;

pr_debug("About to add an bib entry");
pr_debug("bib_entry = (%pI6c , %d) -- (%pI4 , %d)",
    &bib_entry_p->ipv6.address, ntohs(bib_entry_p->ipv6.pi.port),
    &bib_entry_p->ipv4.address, ntohs(bib_entry_p->ipv4.pi.port) );
            
        // Add the new BIB entry
		INIT_LIST_HEAD(&bib_entry_p->session_entries);
        ret = nat64_add_bib_entry( bib_entry_p, protocol);
pr_debug("despues de add bib \n");        
        if (ret == false)
        {
            
            pr_warning("NAT64:  Could NOT add a new BIB entry for a incoming IPv6 UDP packet.");
            pr_warning("        Dropping packet.");
            
            kfree(bib_entry_p);
            
            return NF_DROP;
        }
    }
    
    // Once we have a BIB entry do ...
    
    // PERSONAL NOTE: This should look for the IPv6 incoming 5-tuple
    // Searches for the Session Table Entry corresponding to the incoming 5-tuple->
    //~ session_entry_p = get_session_entry_by_tuple( tuple, protocol );
pr_debug("aqui se llama nat64_get_session_entry , tuple= %p \n", tuple );
    session_entry_p = nat64_get_session_entry( tuple );
pr_debug("aqui se llamooo nat64_get_session_entry  \n");

    // If session was not found, then try to create a new one.
    if ( session_entry_p == NULL )
    {
        // TODO:    Define the checks that evaluate if resources availability 
        //          and policy allows the creation of a new entry.

        // Allocate memory for a new Session entry
        session_entry_p = (struct session_entry *) kmalloc( sizeof(struct session_entry),GFP_KERNEL );
        if (session_entry_p == NULL)
        {
            pr_warning("NAT64:  Could NOT create a new SESSION entry for a incoming IPv6 UDP packet.");
            pr_warning("        Dropping packet.");
            
            // TOCHECK: Should we delete the previously created BIB entry ????
            nat64_remove_bib_entry( bib_entry_p, protocol);
            return NF_DROP;
        }
            
        // Translate address from IPv6 to IPv4 
        ret = extract_ipv4_from_ipv6 (tuple->ipv6_dst_addr, &ipv4_remote.address); // Z(Y')
        if (ret == false)
        {
            pr_warning("NAT64:  Could NOT extract IPv4 from IPv6 destination address,");
            pr_warning("        while creating a SESSION entry. Dropping packet.");
            
            // TOCHECK: Should we delete the previously created BIB & SESSION entries ????
            kfree(session_entry_p);
            nat64_remove_bib_entry( bib_entry_p, protocol);
            return NF_DROP;
        }
        ipv4_remote.pi.port = tuple->dst_port; // y

        // Pack addresses into transport address
        transport_address_ipv6( tuple->ipv6_dst_addr, tuple->dst_port, &ipv6_ta_local );
        transport_address_ipv6( tuple->ipv6_src_addr, tuple->src_port, &ipv6_ta_remote );
        
        // Fill the session entry ipv6.remote.address
        session_entry_p->ipv6.remote = ipv6_ta_remote; // (X', x)
        session_entry_p->ipv6.local = ipv6_ta_local; // (Y', y)
        session_entry_p->ipv4.local = bib_entry_p->ipv4; // (T, t)
        session_entry_p->ipv4.remote = ipv4_remote; // Z, z; // (Z(Y’),y)
        session_entry_p->l4protocol = protocol; //  

        session_entry_p->bib = bib_entry_p;     // Owner bib_entry of this session.
        session_entry_p->is_static = false;     // This is a dynamic entry.

        // Add the session entry
pr_debug("  About to add an session_entry with: nat64_add_session_entry, ptr=%p \n", session_entry_p);
        ret = nat64_add_session_entry(session_entry_p);
pr_debug("  se llamO nat64_add_session_entry\n");
        if (ret == false)
        {
pr_debug("  ret == false \n");
            
            pr_warning("NAT64:  Could NOT add a new session entry for a incoming IPv6 UDP packet.");
            pr_warning("        Dropping packet.");
            
            // TOCHECK: Should we delete the previously created BIB & SESSION entries ????
            kfree(session_entry_p);
            nat64_remove_bib_entry( bib_entry_p, protocol);
            return NF_DROP;
        }
    }
    
    // Reset session entry's lifetime.
    //~ ret =
    nat64_update_session_lifetime(session_entry_p, UDP_DEFAULT_); 
    //~ if (ret == false)
    //~ {
            //~ pr_warning("NAT64:  Could NOT renew the session entry's lifetime for a incoming IPv6 UDP packet.");
            //~ pr_warning("        Dropping packet.");
            //~ 
            //~ // TOCHECK: Should we delete the previously created BIB & SESSION entries ????
            //~ nat64_remove_session_entry(session_entry_p);
            //~ nat64_remove_bib_entry( bib_entry_p, protocol);
            //~ return NF_DROP;
    //~ }
        
    // WHAT IS THE CORRECT RETURN VALUE ????
    return NF_ACCEPT;
}

/*// Segunda mitad de 3.5.1
private int ipv4_udp(tuple):
*/
/** Process an incoming UDP packet, with an incoming tuple with source IPv4 transport 
 *  address (W,w) and destination IPv4 transport address (T,t)
 * 
 * @param[in]   tuple   Tuple obtained from incoming packet
 * @return  NF_ACCEPT if everything went OK, NF_DROP otherwise.
 */
int ipv4_udp(struct nf_conntrack_tuple *tuple)
{
    struct bib_entry *bib_entry_p;
    struct session_entry *session_entry_p;
    struct ipv6_tuple_address ipv6_local; 
    struct ipv4_tuple_address ipv4_ta; 
    struct ipv4_tuple_address ipv4_ta_local; 
    struct ipv4_tuple_address ipv4_ta_remote; 
    
    int ret;
    u_int8_t protocol;
    
    protocol = IPPROTO_UDP;

    // Pack source address into transport address
    transport_address_ipv4( tuple->ipv4_dst_addr,tuple->dst_port, &ipv4_ta );

pr_debug("Transport address ipv4 = (%pI4 , %d) ", 
&ipv4_ta.address, ntohs(ipv4_ta.pi.port) );


    // Check if a previous BIB entry exist, look for IPv4 destination transport address (T,t).
    bib_entry_p = nat64_get_bib_entry_by_ipv4( &ipv4_ta, protocol );

    // TODO:    Define the checks that evaluate if resources availability 
    //          and policy allows the creation of a new entry.
    // If not found, try to create a new one.
    if ( bib_entry_p == NULL )
    {               
        // TOCHECK: Does the policy allow us to send this packet?
        // There's NOT a previous communication from IPv6 towar this IPv4 destination, so...
        send_icmp_error_message(tuple, DESTINATION_UNREACHABLE, HOST_UNREACHABLE); 
        // TOCHECK: Which code ???? , HOST_UNREACHABLE?, RFC doesn't specify that.
        
        pr_warning("NAT64:  A BIB entry does NOT exist for a incoming IPv4 UDP packet.");
        pr_warning("        Dropping packet.");
        
        // Discard packet.
        return NF_DROP;
    }
    
    // If we're applying address-dependent filtering in the IPv4 interface,
    if ( cs.address_dependent_filtering == true )
    {
        // Check if the incoming packet is allowed, according to the 
        // Address-Dependent Filtering rule.
        
        /*  Search for a Session Table Entry(STE) with an source IPv4 transport 
            address equal to (T,t) and a STE destination IPv4 address equal to W,
            i.e., the destination IPv4 transport address (T,t) in the incoming 
            packet and the source IPv4 address (W) in the incoming packet. */

        // Personal Note:   This function behaves different to the one used for IPv6.
        //                  The next get_session_entry is also different to this one.  
        //                  This should look for the IPv4 incoming tuple 
        //                  but we don't care the source port (w), as we're 
        //                  applying address-dependent filtering.
        //                  May be we want a different function named something 
        //                  like 'get_session_entry_for_address_dependent_filtering(tuple)'
        // Searches for the Session Table Entry corresponding to the incoming tuple->

        if (!nat64_is_allowed_by_address_filtering( tuple ))
    	{
        // If NO session was found:
            /* an ICMP error message MAY be sent to the original sender of 
             * the packet, having Type 3 (Destination Unreachable) and Code 13
             * (Communication Administratively Prohibited). */
            // TOCHECK: Does the policy allow us to send this packet?
            send_icmp_error_message(tuple, DESTINATION_UNREACHABLE, COMMUNICATION_ADMINISTRATIVELY_PROHIBITED );

            pr_warning("NAT64:  A previous Session entry does NOT exist for a incoming IPv4 UDP packet.");
            pr_warning("        Using address-dependent filtering.");
            pr_warning("        Dropping packet.");

            // the packet is discarded.
            return NF_DROP;
        }
        /* If STE was found (there may be more than one), packet processing continues. */
    }

    /*  Search for the Session Table Entry containing the a source IPv4 
        transport address equal to (T,t) and a destination IPv4 transport 
        address equal to (W,w). */
    // Searches for the Session Table Entry corresponding to the incoming tuple->
    //~ session_entry_p = get_session_entry_by_tuple( tuple, protocol );
    session_entry_p = nat64_get_session_entry( tuple );
    
    // If NO session was found:
    if ( session_entry_p == NULL )
    {
        // TODO:    Define the checks that evaluate if resources availability 
        //          and policy allows the creation of a new entry.
    
        // Create a new UDP Session Table Entry.
        session_entry_p = (struct session_entry *) kmalloc( sizeof(struct session_entry), GFP_KERNEL );
        if (session_entry_p == NULL)
        {
            pr_warning("NAT64:  Could NOT create a new SESSION entry for a incoming IPv4 packet.");
            pr_warning("        Dropping packet.");
            
            // WHAT IS THE CORRECT RETURN VALUE ????
            return NF_DROP;
        }
        
        // Reverse Translation from IPv4 address to IPv6 
        ret = embed_ipv4_in_ipv6 (tuple->ipv4_src_addr, &ipv6_local.address); // Y’(W)
        if (ret == false)
        {
            pr_warning("NAT64:  Could NOT translate IPv4 on IPv6,");
            pr_warning("        while creating a SESSION entry for a IPv4 UDP packet.");
            pr_warning("        Dropping packet.");
            
            // TOCHECK: Should we delete the previously created BIB & SESSION entries ????
            kfree(session_entry_p);
            nat64_remove_bib_entry( bib_entry_p, protocol);
            return NF_DROP;
        }
        ipv6_local.pi.port = tuple->src_port; // w

        // Pack addresses into transport address
        transport_address_ipv4( tuple->ipv4_dst_addr,tuple->dst_port, &ipv4_ta_local );
        transport_address_ipv4( tuple->ipv4_src_addr,tuple->src_port, &ipv4_ta_remote );

        // Fill the session entry with the following information:
        session_entry_p->ipv6.remote = bib_entry_p->ipv6;   // (X', x)
        session_entry_p->ipv6.local = ipv6_local;           // (Y’(W), w)   
        session_entry_p->ipv4.local = ipv4_ta_local; // (T, t)
        session_entry_p->ipv4.remote = ipv4_ta_remote; // (W,w)
        session_entry_p->l4protocol = protocol; //  

        // Add the session entry
        ret = nat64_add_session_entry(session_entry_p);
        if (ret == false)
        {
            pr_warning("NAT64:  Could NOT add a new session entry for a incoming IPv4 UDP packet.");
            pr_warning("        Dropping packet.");
            
            // TOCHECK: Should we delete the previously created SESSION entry ????
            kfree(session_entry_p);

            //~ tryToDeleteBib(bib) // Nota 1
            // TOCHECK: Are you sure you want to do this ????
            // nat64_remove_bib_entry( bib_entry_p, protocol);
            
            // the packet is discarded.
            return NF_DROP;
        }
    }
    
    nat64_update_session_lifetime(session_entry_p, UDP_DEFAULT_); 
        
    return NF_ACCEPT; 
}

// Primera mitad de 3.5.3
/** Process an incoming ICMPv6 Informational packet, which has an incoming 
 *  tuple with IPv6 source address (X’), IPv6 destination address (Y’), and 
 *  ICMPv6 Identifier (i1)
 * 
 * @param[in]   tuple   Tuple obtained from incoming packet
 * @return  NF_ACCEPT if everything went OK, NF_DROP otherwise.
 */
int ipv6_icmp6(struct nf_conntrack_tuple *tuple)
{
    struct bib_entry *bib_entry_p;
    struct bib_entry *bib_entry_t;
    struct session_entry *session_entry_p;
    struct ipv4_tuple_address new_ipv4_transport_address;
    struct ipv6_tuple_address ipv6_source;

    struct in_addr ipv4_remote_address;
    __be16 pi;
    u_int8_t protocol;
    int ret;
    
    protocol = IPPROTO_ICMP;
    ipv4_remote_address.s_addr = 0x00000000;
    pi = 0;
    
    // Are we filtering ICMPv6 Informational packets?
    if ( cs.filter_informational_icmpv6 == true )
    {
        /*  If the local security policy determines that ICMPv6 Informational
            packets are to be filtered, the packet is silently discarded. */
        return NF_DROP;
    }

    // Pack source address into transport address
    transport_address_ipv6( tuple->ipv6_src_addr, tuple->src_port, &ipv6_source );
    
    // Search for an ICMPv6 Query BIB entry that matches the (X’,i1) pair.
    bib_entry_p = nat64_get_bib_entry_by_ipv6( &ipv6_source, protocol );

    // If not found, try to create a new one.
    if ( bib_entry_p == NULL )
    {   
        // TODO:    Define the checks that evaluate if resources availability 
        //          and policy allows the creation of a new entry.
            
        // Allocate memory for a new BIB entry
        bib_entry_p = (struct bib_entry *)kmalloc(sizeof(struct bib_entry),GFP_KERNEL);
        if ( bib_entry_p == NULL )
        {
            /*  If it is not possible to allocate space for create a BIB entry, 
                WHAT SHOULD WE DO???? , it's NOT defined in the RFC. */
            
            pr_warning("NAT64:  Could NOT create a new BIB entry for a incoming IPv6 ICMP packet.");
            pr_warning("        Dropping packet.");
                        
            return NF_DROP;
        }

        // Set BIB IPv6 address to packet's source address (X').
        bib_entry_p->ipv6.address = tuple->ipv6_src_addr;

        // The BIB ICMPv6 Identifier is set to packet's ID (i1)
        bib_entry_p->ipv6.pi.id = tuple->icmp_id;

        //~ // BTW, lo referente a IPv4 debe ocurrir dentro de bib_session.
    
        // Define BIB IPv4 transport address. 


        // TODO: Replace this IF by the new function: 

        /*  If there exists another BIB entry in any of the BIBs that
            contains the same IPv6 address (X’) and maps it to an IPv4
            address (T), then use (T) as the BIB IPv4 address for this new
            entry. Otherwise, use any IPv4 address assigned to the IPv4
            interface. */
        // Look in the UDP & TCP BIB tables for a previous packet from the same origin (X')
        bib_entry_t = nat64_get_bib_entry_by_ipv6_only(&tuple->ipv6_src_addr, IPPROTO_UDP);
        if (bib_entry_t == NULL)
        {
            // If no lucky with UDP, try now with TCP
            bib_entry_t = nat64_get_bib_entry_by_ipv6_only( &tuple->ipv6_src_addr, IPPROTO_TCP);
            if (bib_entry_t == NULL)
            {
                // If no previous communication from the source (X') exist ...

                // Obtain a new BIB IPv4 transport address (T,i1), put it in new_ipv4_transport_address.
                ret = allocate_ipv4_transport_address(tuple, protocol, &new_ipv4_transport_address);
                if ( ret == false )
                {
                    /* If it is not possible to allocate an appropriate IPv4 transport
                     address or create a BIB entry, then the packet is discarded. */
                    
                    pr_warning("NAT64:  Could NOT allocate a new IPv4 transport address for a incoming IPv6 ICMP packet.");
                    pr_warning("        Dropping packet.");
                
                    // Should we free the previously allocated BIB entry?
                    kfree(bib_entry_p);
                    
                    return NF_DROP;
                }                
                bib_entry_p->ipv4 = new_ipv4_transport_address;
            }
            else
            {
                // Use the same IPv4 (T) translated address that was assigned to TCP
                bib_entry_p->ipv4.address = bib_entry_t->ipv4.address;
         
                // Get a valid ICMPv4 identifier
                ret = get_icmpv4_identifier(&bib_entry_p->ipv4.address, &pi);
                if (ret == false)
                {
                    pr_warning("NAT64:  Could NOT get a valid ICMPv4 identifier for a incoming IPv6 ICMP packet.");
                    pr_warning("        Dropping packet.");
                
                    // Should we free the previously allocated BIB entry?
                    kfree(bib_entry_p);
                    
                    return NF_DROP;
                }
                bib_entry_p->ipv4.pi.id = pi;
            }
        }
        else
        {
            // Use the same IPv4 (T) translated address that was assigned to UDP
            bib_entry_p->ipv4.address = bib_entry_t->ipv4.address;
         
            // Get a valid ICMPv4 identifier
            ret = get_icmpv4_identifier(&bib_entry_p->ipv4.address, &pi);
            if (ret == false)
            {
                pr_warning("NAT64:  Could NOT get a valid ICMPv4 identifier for a incoming IPv6 ICMP packet.");
                pr_warning("        Dropping packet.");
            
                // Should we free the previously allocated BIB entry?
                kfree(bib_entry_p);
                
                return NF_DROP;
            }
            bib_entry_p->ipv4.pi.id = pi;
        }

pr_debug("About to add an bib entry");
pr_debug("bib_entry = (%pI6c , %d) -- (%pI4 , %d)",
    &bib_entry_p->ipv6.address, ntohs(bib_entry_p->ipv6.pi.id),
    &bib_entry_p->ipv4.address, ntohs(bib_entry_p->ipv4.pi.id) );
        
        // Add the new BIB entry
		INIT_LIST_HEAD(&bib_entry_p->session_entries);
        ret = nat64_add_bib_entry(bib_entry_p, protocol);
pr_debug("After nat64_add_bib_entry");
        if ( ret == false )
        {
pr_debug("ret == false");            
            pr_warning("NAT64:  Could NOT add a new BIB entry for a incoming IPv6 ICMP packet.");
            pr_warning("        Dropping packet.");
            
            // Should we free the previously allocated BIB entry?
            kfree(bib_entry_p);
            
            return NF_DROP;
        }
    }

    // OK, we have a BIB entry to work with...

pr_debug("nat64_get_session_entry()");
    /* Searche for an ICMP Query Session Table Entry corresponding to the incoming 
       3-tuple (X’,Y’,i1).  */
    session_entry_p = nat64_get_session_entry( tuple );
pr_debug("after nat64_get_session_entry()");

    // If NO session was found:
    if ( session_entry_p == NULL )
    {
pr_debug("Doh! session_entry_p == NULL ");        
        // TODO:    Define the checks that evaluate if resources availability 
        //          and policy allows the creation of a new entry.

        // Allocate memory for a new Session entry
        session_entry_p = (struct session_entry *) kmalloc( sizeof(struct session_entry), GFP_KERNEL );
        if (session_entry_p == NULL)
        {
            pr_warning("NAT64:  Could NOT create a new SESSION entry for a incoming IPv6 ICMP packet.");
            pr_warning("        Dropping packet.");
            
            // TOCHECK: Should we delete the previously created BIB entry ????
            nat64_remove_bib_entry( bib_entry_p, protocol );
            return NF_DROP;
        }
        
        // Translate address from IPv6 to IPv4 
        ret = extract_ipv4_from_ipv6 (tuple->ipv6_dst_addr, &ipv4_remote_address); // Z(Y')
        if (ret == false)
        {
            pr_warning("NAT64:  Could NOT extract IPv4 from IPv6 destination address,");
            pr_warning("        while creating a SESSION entry. Dropping packet.");
            
            // TOCHECK: Should we delete the previously created BIB & SESSION entries ????
            kfree(session_entry_p);
            nat64_remove_bib_entry( bib_entry_p, protocol);
            // Should we DROP the package ????
            return NF_DROP;
        }

        // NOTICE:  We store the ICMP ID (i1) in the ipv6.remote part of the STE.
        //          We do it in ipv4.local for (i2).
        //          Is this fine?

        // Fill the session entry
        session_entry_p->ipv6.remote.address = tuple->ipv6_src_addr;        // (X')
        session_entry_p->ipv6.local.address = tuple->ipv6_dst_addr;         // (Y')
        session_entry_p->ipv6.remote.pi.id = tuple->icmp_id;           // (i1)
        session_entry_p->ipv6.local.pi.id = tuple->icmp_id;           // (i1)
        session_entry_p->ipv4.local.address = bib_entry_p->ipv4.address;    // (T)
        session_entry_p->ipv4.local.pi.id = bib_entry_p->ipv4.pi.id;// (i2)
        session_entry_p->ipv4.remote.pi.id = bib_entry_p->ipv4.pi.id;// (i2)
        session_entry_p->ipv4.remote.address = ipv4_remote_address;         // (Z(Y’))
        session_entry_p->l4protocol = protocol; //  

        session_entry_p->bib = bib_entry_p;     // Owner bib_entry of this session.
        session_entry_p->is_static = false;     // This is a dynamic entry.

pr_debug("About to add a session_entry with nat64_add_session_entry() ");                
        // Add the session entry
        ret = nat64_add_session_entry( session_entry_p );
pr_debug("After add a session_entry with nat64_add_session_entry() ");                
        if (ret == false)
        {
pr_debug("Doh! ret == NULL ");        
            pr_warning("NAT64:  Could NOT add a new session entry for a incoming IPv6 ICMP packet.");
            pr_warning("        Dropping packet.");

            //~ tryToDeleteBib(bib) // Nota 1
            
            // TOCHECK: Should we delete the previously created BIB & SESSION entries ????
            kfree(session_entry_p);
            nat64_remove_bib_entry( bib_entry_p, protocol);

            return NF_DROP;
        }
    }
    
    // Reset session entry's lifetime.
    nat64_update_session_lifetime(session_entry_p, ICMP_DEFAULT_);    

    return NF_ACCEPT; 
}

// Segunda mitad de 3.5.3
/** Process an incoming ICMPv4 Query packet with source IPv4 address (Y), destination 
 *  IPv4 address (X), and ICMPv4 Identifier (i2)
 * 
 * @param[in]   tuple   Tuple obtained from incoming packet
 * @return  NF_ACCEPT if everything went OK, NF_DROP otherwise.
 */
int ipv4_icmp4(struct nf_conntrack_tuple *tuple)
{
    struct bib_entry *bib_entry_p;
    struct session_entry *session_entry_p;
    struct in6_addr ipv6_remote;
    struct ipv4_tuple_address ipv4_ta;
    struct ipv4_tuple_address ipv4_ta_local;
    struct ipv4_tuple_address ipv4_ta_remote;
    struct ipv6_tuple_address ipv6_ta_local;
    struct ipv6_tuple_address ipv6_ta_remote;
    
    int ret;
    u_int8_t protocol;
    
    protocol = IPPROTO_ICMP;

    // Pack source address into transport address
    transport_address_ipv4( tuple->ipv4_dst_addr, tuple->icmp_id, &ipv4_ta );

pr_debug("call to: ipv4_icmp4()");
pr_debug("tuple = src(%pI4 , %d) -- dst(%pI4 , %d)",
    &tuple->ipv4_src_addr, ntohs( tuple->icmp_id ),
    &tuple->ipv4_dst_addr, ntohs( tuple->dst_port ) );
    
    // Look for a previous BIB entry that contains (X) as the IPv4 address and (i2) as the ICMPv4 Identifier.
    bib_entry_p = nat64_get_bib_entry_by_ipv4( &ipv4_ta, protocol );

    // If such an entry does not exist,
    if ( bib_entry_p == NULL )
    {   
        // TOCHECK: Does the policy allow us to send this packet?
        
        // There's NOT a previous communication from IPv6 towar this IPv4 destination, so...
        // Send an ICMP error message to the original sender of the packet, 
        // with Type 3 (Destination Unreachable) & Code 1 (Host Unreachable)
        send_icmp_error_message(tuple, DESTINATION_UNREACHABLE, HOST_UNREACHABLE);
        
        pr_warning("NAT64:  A BIB entry does NOT exist for a incoming IPv4 ICMP packet.");
        pr_warning("        Dropping packet.");
        
        // Discard packet.
        return NF_DROP;
    }

    // If we're applying address-dependent filtering in the IPv4 interface,
    if ( cs.address_dependent_filtering == true )
    {
        /*  The incoming packet is allowed according to the Address-
            Dependent Filtering rule. */
        /*  To do this, it searches for a Session
            Table Entry with an STE source IPv4 address equal to X, an STE
            ICMPv4 Identifier equal to i2, and a STE destination IPv4 address
            equal to Y. If such an entry is found (there may be more than
            one), packet processing continues.*/
        // Personal Note:   This function behaves different to the one used for IPv6.
        //                  The next get_session_entry is also different to this one.  
        //                  This should look for the IPv4 incoming tuple 
        //                  but we don't care the source port (w), as we're 
        //                  applying address-dependent filtering.
        //                  May be we want a different function named something 
        //                  like 'get_session_entry_for_address_dependent_filtering(tuple)'
        // Searches for the Session Table Entry corresponding to the incoming tuple, 
        // but don't care the source port (w), as we're applying address-dependent filtering.
        if ( !nat64_is_allowed_by_address_filtering( tuple ) )
        {
            /* If the packet is discarded, then an ICMP error message
                MAY be sent to the original sender of the packet. The ICMP error
                message, if sent, has Type 3 (Destination Unreachable) and Code 13
                (Communication Administratively Prohibited).*/
            // TOCHECK: Does the policy allow us to send this packet?
            send_icmp_error_message(tuple, DESTINATION_UNREACHABLE, COMMUNICATION_ADMINISTRATIVELY_PROHIBITED );
            
            pr_warning("NAT64:  A previous Session entry does NOT exist for a incoming IPv4 UDP packet.");
            pr_warning("        Using address-dependent filtering.");
            pr_warning("        Dropping packet.");

            // the packet is discarded.
            return NF_DROP;
        }
        /* If STE was found (there may be more than one), packet processing continues. */
    }

    /*  Searches for a Session Table Entry (STE) with source IPv4 address (X), 
        ICMPv4 Identifier (i2), and destination IPv4 address (Y). */
    // Searches for the Session Table Entry corresponding to the incoming tuple
    //~ session_entry_p = get_session_entry_by_tuple( tuple , protocol );
pr_debug("call to nat64_get_session_entry()");
    session_entry_p = nat64_get_session_entry( tuple );
pr_debug("after have called to nat64_get_session_entry()");
    
    // If NO session was found:
    if ( session_entry_p == NULL )
    {
pr_debug("Doh! session_entry_p == NULL ");        
        // TODO:    Define the checks that evaluate if resources availability 
        //          and policy allows the creation of a new entry.
    
        // Create a new UDP Session Table Entry.
        session_entry_p = (struct session_entry *) kmalloc( sizeof(struct session_entry), GFP_KERNEL );
        if (session_entry_p == NULL)
        {
            pr_warning("NAT64:  Could NOT create a new SESSION entry for a incoming ICMP IPv4 packet.");
            pr_warning("        Dropping packet.");
            
            // WHAT IS THE CORRECT RETURN VALUE ????
            return NF_DROP;
        }
        
        // Reverse Translation from IPv4 address to IPv6 
        ret = embed_ipv4_in_ipv6 (tuple->ipv4_src_addr, &ipv6_remote); // Y’(Z)
        if (ret == false)
        {
            pr_warning("NAT64:  Could NOT translate IPv4 on IPv6,");
            pr_warning("        while creating a SESSION entry for a IPv4 ICMP packet.");
            pr_warning("        Dropping packet.");
            
            // TOCHECK: Should we delete the previously created BIB & SESSION entries ????
            kfree(session_entry_p);
            nat64_remove_bib_entry( bib_entry_p, protocol);
            return NF_DROP;
        }

        // NOTICE:  We store the ICMP ID (i1) in both local & remote parts of the STE.
        //          For (i2), we do it in the same way.
        //          Is this fine?

        // Pack addresses into transport address
        transport_address_ipv4( tuple->ipv4_src_addr, tuple->icmp_id, &ipv4_ta_remote );
        transport_address_ipv4( tuple->ipv4_dst_addr, tuple->icmp_id, &ipv4_ta_local );
        transport_address_ipv6( ipv6_remote, bib_entry_p->ipv6.pi.id, &ipv6_ta_local );
        transport_address_ipv6( bib_entry_p->ipv6.address, bib_entry_p->ipv6.pi.id, &ipv6_ta_remote );
        
        // Fill the session entry with the following information:
        session_entry_p->ipv4.remote = ipv4_ta_remote; // (Z, i2)
        session_entry_p->ipv4.local = ipv4_ta_local; // (T, i2)
        session_entry_p->ipv6.remote = ipv6_ta_remote;  // (X', i1)
        session_entry_p->ipv6.local = ipv6_ta_local;    // (Y'(Z), i1)
        session_entry_p->l4protocol = protocol; //

pr_debug("Add a session_entry nat64_add_session_entry() ");
        // Add the session entry
        ret = nat64_add_session_entry(session_entry_p);
pr_debug("After add a session_entry nat64_add_session_entry() ");
        if (ret == false)
        {
pr_debug("Doh! ret == false ");                    
            pr_warning("NAT64:  Could NOT add a new session entry for a incoming IPv4 ICMP packet.");
            pr_warning("        Dropping packet.");

            //~ tryToDeleteBib(bib) // Nota 1
            
            // TOCHECK: Should we delete the previously created BIB & SESSION entries ????
            kfree(session_entry_p);
            nat64_remove_bib_entry( bib_entry_p, protocol);

            return NF_DROP;
        }
    }

    // Reset session entry's lifetime.
    //~ ret =
    nat64_update_session_lifetime(session_entry_p, ICMP_DEFAULT_);    
    //~ if (ret == false)
    //~ {
            //~ pr_warning("NAT64:  Could NOT renew the session entry's lifetime for a incoming IPv4 ICMP packet.");
            //~ pr_warning("        Dropping packet.");
            //~ 
            //~ // TOCHECK: Should we delete the previously created BIB & SESSION entries ????
            //~ nat64_remove_session_entry(session_entry_p);
            //~ nat64_remove_bib_entry( bib_entry_p, protocol);
            //~ return NF_DROP;
    //~ }

    return NF_ACCEPT; 
}


/*********************************************
 **                                         **
 **     TCP STATES                          **
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
    struct bib_entry *bib_entry_p;
    struct session_entry *session_entry_p;

    struct ipv4_tuple_address new_ipv4_transport_address;
    struct ipv6_tuple_address ipv6_ta;
    struct ipv4_tuple_address ipv4_ta;

    struct ipv4_tuple_address ipv4_remote;
    struct ipv4_tuple_address ipv4_ta_local;
    struct ipv4_tuple_address ipv4_ta_remote;
    struct ipv6_tuple_address ipv6_local;
    struct ipv6_tuple_address ipv6_ta_local;
    struct ipv6_tuple_address ipv6_ta_remote;
    //~ struct in6_addr ipv6_ta;
    u_int8_t protocol;
    int ret;

    protocol = IPPROTO_TCP;

    // if packet is not a V4 SYN nor a V6 SYN:
    if ( !packet_is_v4_syn(skb) && !packet_is_v6_syn(skb) )
    {
        // For any packet, other than SYN, belonging to this connection:

    	// Pack source address into transport address
		transport_address_ipv6( tuple->ipv6_dst_addr, tuple->dst_port, &ipv6_ta );

        // Look if there is a corresponding entry in the TCP BIB
        bib_entry_p = nat64_get_bib_entry_by_ipv6( &ipv6_ta, protocol );
        
        // If such an entry does not exist,
        if ( bib_entry_p == NULL )
        {   // Discard packet.
            return NF_DROP;
        }

        // FIXME: Who should translate this packet, NAT64 or netfilter?
        // Else, the packet SHOULD be translated and forwarded if the security policy allows doing so.
        return NF_ACCEPT;
    }
    
    //  V6 SYN packet: IPv6 -> IPv4
    //~ if ( NFPROTO_IPV6 == packet.buffer->protocol )
    if ( packet_is_v6_syn(skb) )
    {
        // Pack source address into transport address
        transport_address_ipv6( tuple->ipv6_src_addr, tuple->src_port, &ipv6_ta );
        
        // Check if a previous BIB entry exist, look for IPv6 source transport address (X’,x).
        bib_entry_p = nat64_get_bib_entry_by_ipv6( &ipv6_ta, protocol );

        // If bib does not exist, try to create a new one,
        if ( bib_entry_p == NULL )
        {
            /* TODO: Define if resources and policy permit the creation of a BIB entry*/            

            // Allocate memory for a new BIB entry
            bib_entry_p = (struct bib_entry *)kmalloc(sizeof(struct bib_entry), GFP_KERNEL);
            if ( bib_entry_p == NULL )
            {
                /* If it is not possible to allocate an appropriate IPv4 transport
                address or create a BIB entry, then the packet is discarded. The
                NAT64 SHOULD send an ICMPv6 Destination Unreachable error message
                with Code 3 (Address Unreachable). */

                // TODO: Check in RFC6146 if we should send the ICMPv6 error message.
                
                pr_warning("NAT64:  CLOSED State. Could NOT create a new BIB entry for an incoming IPv6 TCP packet.");
                pr_warning("        Dropping packet.");
                            
                return NF_DROP;
            }

            // Pack source address into transport address
            //~ transport_address_ipv6(&ipv6_ta, tuple->ipv6_src_addr, tuple->src_port);
            
            // Set BIB IPv6 transport address (X',x).
            bib_entry_p->ipv6 = ipv6_ta;
            
            // Obtain a new BIB IPv4 transport address (T,t), put it in new_ipv4_transport_address.
            ret = allocate_ipv4_transport_address_digger(tuple, protocol, 
                                     &new_ipv4_transport_address);
            if ( ret == false )
            {
                /* If it is not possible to allocate an appropriate IPv4 transport
                 address the packet is discarded. Send an ICMPv6 Destination Unreachable
                 error message with Code 3 (Address Unreachable). */
                send_icmp_error_message(tuple, DESTINATION_UNREACHABLE, ADDRESS_UNREACHABLE);
                pr_debug("NAT64:  CLOSED State. Sending ICMPv6 message: DESTINATION_UNREACHABLE, ADDRESS_UNREACHABLE");
                
                pr_warning("NAT64:  CLOSED State. Could NOT allocate a new IPv4 transport address for an incoming IPv6 packet.");
                pr_warning("        Dropping packet.");
            
                return NF_DROP;
            }

            // Set BIB IPv4 transport address (T,t).
            bib_entry_p->ipv4 = new_ipv4_transport_address;

            // Add the new BIB entry
            INIT_LIST_HEAD(&bib_entry_p->session_entries);
            ret = nat64_add_bib_entry( bib_entry_p, protocol);
            if (ret == false)
            {
                
                pr_warning("NAT64:  CLOSED State. Could NOT add a new BIB entry for an incoming IPv6 TCP packet.");
                pr_warning("        Dropping packet.");
                
                kfree(bib_entry_p);
                
                return NF_DROP;
            }
        }

        // Now that we have a BIB entry...

        // Try to create a new Session Entry
        // TOCHECK:     What about of checking Policy and Resources for the creation of a STE.

        // Allocate memory for a new Session entry
        session_entry_p = (struct session_entry *) kmalloc( sizeof(struct session_entry), GFP_KERNEL );
        if (session_entry_p == NULL)
        {
            pr_warning("NAT64:  CLOSED State. Could NOT create a new SESSION entry for an incoming IPv6 TCP packet.");
            pr_warning("        Dropping packet.");
            
            // TOCHECK: Should we delete the previously created BIB entry ????
            nat64_remove_bib_entry( bib_entry_p, protocol);
            return NF_DROP;
        }

        // Translate address from IPv6 to IPv4 
        ret = extract_ipv4_from_ipv6 (tuple->ipv6_dst_addr, &ipv4_remote.address); // Z(Y')
        if (ret == false)
        {
            pr_warning("NAT64:  CLOSED State. Could NOT extract IPv4 from IPv6 destination address,");
            pr_warning("        while creating a SESSION entry. Dropping packet.");
            
            // TOCHECK: Should we delete the previously created BIB & SESSION entries ????
            kfree(session_entry_p);
            nat64_remove_bib_entry( bib_entry_p, protocol);
            return NF_DROP;
        }
        ipv4_remote.pi.port = tuple->dst_port; // y

        // Pack addresses and ports into transport address
        transport_address_ipv6( tuple->ipv6_dst_addr, tuple->dst_port, &ipv6_ta_local );
        transport_address_ipv6( tuple->ipv6_src_addr, tuple->src_port, &ipv6_ta_remote );
        
        // Fill the session entry 
        session_entry_p->ipv6.remote = ipv6_ta_remote; // (X', x)
        session_entry_p->ipv6.local = ipv6_ta_local; // (Y', y)

        session_entry_p->ipv4.local = bib_entry_p->ipv4; // (T, t)

        session_entry_p->ipv4.remote = ipv4_remote; // Z, z; // (Z(Y’),y)
        session_entry_p->l4protocol = protocol; //  

        // session.lifetime = TCP_TRANS
        nat64_update_session_lifetime(session_entry_p, TCP_TRANS);

        // session.state = V6_INIT
        session_entry_p->current_state = V6_INIT;

        session_entry_p->bib = bib_entry_p;     // Owner bib_entry of this session.
        session_entry_p->is_static = false;     // This is a dynamic entry.


        ret = nat64_add_session_entry(session_entry_p);
        if (ret == false)
        {
            pr_warning("NAT64:  CLOSED State. Could NOT add a new session entry for an incoming IPv6 UDP packet.");
            pr_warning("        Dropping packet.");
            
            // TOCHECK: Should we delete the previously created BIB & SESSION entries ????
            kfree(session_entry_p);
            nat64_remove_bib_entry( bib_entry_p, protocol);

            return NF_DROP;
        }
    }
    else if ( packet_is_v4_syn(skb) )
    {
        // TODO:    add this option to the user space app.
        // Should we drop externally initiated TCP connections ?
        if ( cs.drop_externally_initiated_tcp_connections )
        {
			pr_debug("NAT64: Applying policy: Drop externally initiated TCP connections.");
            return NF_DROP;
        }

        // Pack addresses and ports into transport address
        transport_address_ipv4( tuple->ipv4_dst_addr, tuple->dst_port, &ipv4_ta );

        // Look for the destination transport address (X,x) in the BIB 
        bib_entry_p = nat64_get_bib_entry_by_ipv4( &ipv4_ta, protocol );

        // TODO:    Define the checks that evaluate if resources availability 
        //          and policy allows the creation of a new entry.
        // If not found (not in use), even try to create a new SESSION entry!!!
        if ( bib_entry_p == NULL )
        {           
            /*  Side:   <-------- IPv6 -------->  N  <------- IPv4 ------->
                Packet: dest(X',x) <-- src(Y',y)  A  dest(X,x) <-- src(Y,y)
                NAT64:    remote       local      T    local        remote
            */

            // Try to create a new Session Entry
            // TOCHECK:     What about of checking Policy and Resources for the creation of a STE.

            // Allocate memory for a new Session entry
            session_entry_p = (struct session_entry *) kmalloc( sizeof(struct session_entry), GFP_KERNEL );
            if (session_entry_p == NULL)
            {
                pr_warning("NAT64:  CLOSED State. Could NOT create a new SESSION entry for an incoming IPv4 TCP packet.");
                pr_warning("        Dropping packet.");
                
                // TOCHECK: Should we delete the previously created BIB entry ????
                nat64_remove_bib_entry( bib_entry_p, protocol);
                return NF_DROP;
            }

            // Translate address from IPv4 to IPv6 
            ret = embed_ipv4_in_ipv6(tuple->ipv4_src_addr, &ipv6_local.address); // Y'(Y)
            if (ret == false)
            {
                pr_warning("NAT64:  CLOSED State. Could NOT embed IPv4 in IPv6 destination address,");
                pr_warning("        while creating a SESSION entry. Dropping packet.");
                
                return NF_DROP;
            }
            ipv6_local.pi.port = tuple->src_port; // y
            
            // Pack addresses and ports into transport address
            transport_address_ipv4( tuple->ipv4_dst_addr, tuple->dst_port, &ipv4_ta_local );
            transport_address_ipv4( tuple->ipv4_src_addr, tuple->src_port, &ipv4_ta_remote );

            // Fill the session entry
            session_entry_p->ipv4.local = ipv4_ta_local; // (X, x)  (T, t)
            session_entry_p->ipv4.remote = ipv4_ta_remote; // (Z(Y’),y) ; // (Z, z)

            // session_entry_p->ipv6.remote = Not_Available; // (X', x) INTENTIONALLY LEFT UNSPECIFIED!
            session_entry_p->ipv6.local = ipv6_local; // (Y', y)

            session_entry_p->l4protocol = protocol; //  
            
            session_entry_p->current_state = V4_INIT;

            session_entry_p->bib = bib_entry_p;     // Owner bib_entry of this session.
            session_entry_p->is_static = false;     // This is a dynamic entry.

            
            // session.lifetime = TCP_INCOMING_SYN
            nat64_update_session_lifetime(session_entry_p, TCP_INCOMING_SYN);
            
            /* TODO:    The packet is stored.  
             *          The result is that the NAT64 will not drop the packet based on the filtering, 
             *          nor create a BIB entry.  Instead, the NAT64 will only create the Session 
             *          Table Entry and store the packet. The motivation for this is to support 
             *          simultaneous open of TCP connections. */
        }
        else // if a bib entry exists
        {
            // TODO:    Define the checks that evaluate if resources availability 
            //          and policy allows the creation of a new entry.

            /* ATTENTION: 
             *     Should we look for a previous session?
             *          Check the RFC6146
             * */
            
            // Try to create a new Session Entry
            // Allocate memory for a new Session entry
            session_entry_p = (struct session_entry *) kmalloc( sizeof(struct session_entry), GFP_KERNEL );
            if (session_entry_p == NULL)
            {
                pr_warning("NAT64:  CLOSED State. Could NOT create a new SESSION entry for an incoming IPv4 TCP packet.");
                pr_warning("        Dropping packet.");
                
                // TOCHECK: Should we delete the previously created BIB entry ????
                nat64_remove_bib_entry( bib_entry_p, protocol);
                return NF_DROP;
            }

            // Translate address from IPv4 to IPv6 
            ret = embed_ipv4_in_ipv6(tuple->ipv4_src_addr, &ipv6_local.address); // Y'(Y)
            if (ret == false)
            {
                pr_warning("NAT64:  CLOSED State. Could NOT embed IPv4 in IPv6 destination address,");
                pr_warning("        while creating a SESSION entry. Dropping packet.");
                
                return NF_DROP;
            }
            ipv6_local.pi.port = tuple->src_port; // y

            // Pack addresses and ports into transport address
            transport_address_ipv4( tuple->ipv4_dst_addr, tuple->dst_port, &ipv4_ta_local );
            transport_address_ipv4( tuple->ipv4_src_addr, tuple->src_port, &ipv4_ta_remote );

            // Fill the session entry
            session_entry_p->ipv4.local = ipv4_ta_local; // (X, x)  (T, t)
            session_entry_p->ipv4.remote = ipv4_ta_remote; // (Z(Y’),y) ; // (Z, z)
            
            session_entry_p->ipv6.remote = bib_entry_p->ipv6; // (X', x)
            session_entry_p->ipv6.local = ipv6_local; // (Y', y)

            session_entry_p->l4protocol = protocol; //  

            session_entry_p->bib = bib_entry_p;     // Owner bib_entry of this session.
            session_entry_p->is_static = false;     // This is a dynamic entry.


            // session.state = V4_INIT
            session_entry_p->current_state = V4_INIT;

            if ( cs.address_dependent_filtering )
                nat64_update_session_lifetime(session_entry_p, TCP_INCOMING_SYN);
            else
                nat64_update_session_lifetime(session_entry_p, TCP_TRANS);
        }

        ret = nat64_add_session_entry(session_entry_p);
        if (ret == false)
        {
            pr_warning("NAT64:  CLOSED State. Could NOT add a new session entry for an incoming IPv4 TCP packet.");
            pr_warning("        Dropping packet.");
            
            // TOCHECK: Should we delete the previously created BIB & SESSION entries ????
            kfree(session_entry_p);
            // nat64_remove_bib_entry( bib_entry_p, protocol);

            return NF_DROP;
        }

    }
    return NF_ACCEPT;
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
    struct session_entry *session_entry_p;

    u_int8_t protocol;

    protocol = IPPROTO_TCP;

    // If packet is a V6 SYN
    if ( packet_is_v6_syn(skb) )
    {
        // Searches for the Session Table Entry corresponding to the incoming tuple
        session_entry_p = nat64_get_session_entry( tuple );
        
        // If NO session was found:
        if ( session_entry_p == NULL )
        {
            pr_warning("NAT64:  V4 INIT state. Could NOT find an existing SESSION entry for an incoming V6 SYN packet.");
            pr_warning("        Dropping packet.");
            
            return NF_DROP;
        }

        // TODO:    Define a maximum session lifetime, and replace this TCP_EST
        // Set session lifetime.
        nat64_update_session_lifetime(session_entry_p, TCP_EST);

        // TODO: Packet is translated. 
        // TODO: Packet is forwarded.  

        // The state is moved to ESTABLISHED.
        session_entry_p->current_state = ESTABLISHED;
    }
    else // Any other packet,
    {
        // TODO: if the security policy allows doing so,
        {
            // TODO: should be translated and forwarded

            // The state remains unchanged
        }
    }
    
    /* TODO: 
     *      If the lifetime expires, an ICMP Port Unreachable error (Type 3, Code 3) containing the 
     *      IPv4 SYN packet stored is sent back to the source of the v4 SYN, the Session Table Entry 
     *      is deleted, and the state is moved to CLOSED. */
    
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

    u_int8_t protocol;

    protocol = IPPROTO_TCP;


    // If a V4 SYN is received (with or without the ACK flag set)
    if (packet_is_v4_syn(skb))
    {
        // Searches for the Session Table Entry corresponding to the incoming tuple
        session_entry_p = nat64_get_session_entry( tuple );
        
        // If NO session was found:
        if ( session_entry_p == NULL )
        {
            pr_warning("NAT64:  V6 INIT state. Could NOT find an existing SESSION entry for an incoming V4 SYN packet.");
            pr_warning("        Dropping packet.");
            
            return NF_DROP;
        }

        // The state is moved to ESTABLISHED.
        session_entry_p->current_state = ESTABLISHED;

        // TODO:    Define a maximum session lifetime, and replace this TCP_EST
        // Set session lifetime.
        nat64_update_session_lifetime(session_entry_p, TCP_EST);
    }
    else
    {
        // If a V6 SYN packet is received
        if (packet_is_v6_syn(skb))
        {
            // Searches for the Session Table Entry corresponding to the incoming tuple
            session_entry_p = nat64_get_session_entry( tuple );
            
            // If NO session was found:
            if ( session_entry_p == NULL )
            {
                pr_warning("NAT64:  V6 INIT state. Could NOT find an existing SESSION entry for an incoming V6 SYN packet.");
                pr_warning("        Dropping packet.");
                
                return NF_DROP;
            }

            // TODO:    Define a maximum session lifetime, and replace this TCP_TRANS
            // Set session lifetime.
            nat64_update_session_lifetime(session_entry_p, TCP_TRANS);

            // The state remains unchanged.

            // TODO: packet is translated and forwarded
       
        }
        else // Any other packet,
        {
            // TODO: if the security policy allows doing so,
            {
                // TODO: should be translated and forwarded

                // The state remains unchanged
            }
        }
    }
    
    // TODO: If the lifetime expires, the Session Table Entry is deleted, and the state is moved to CLOSED.
    /*
    if (  )
    {
        if ( nat64_remove_session_entry(session_entry_p) == false )
        {
            pr_warning("NAT64:  V6 INIT state. Could NOT delete an existing SESSION entry for an expired lifetime.");
            pr_warning("        Dropping packet.");
        }
        
        // The state is moved to CLOSED.
        session_entry_p->current_state = CLOSED;
    }
     * */
    
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
    u_int8_t protocol;

    protocol = IPPROTO_TCP;

    // if packet is a V4 FIN:
    if ( packet_is_v4_fin(skb) )
    {
        // Searches for the Session Table Entry corresponding to the incoming tuple
        session_entry_p = nat64_get_session_entry( tuple );
        
        // If NO session was found:
        if ( session_entry_p == NULL )
        {
            pr_warning("NAT64:  ESTABLISHED state. Could NOT find an existing SESSION entry for an incoming V4 FIN packet.");
            pr_warning("        Dropping packet.");
            
            return NF_DROP;
        }

        // TODO: Packet is translated. 
        // TODO: Packet is forwarded.  

        // The state is moved to V4_FIN_RCV.
        session_entry_p->current_state = V4_FIN_RCV;
    }
    // else if packet is a V6 FIN:
    else if ( packet_is_v6_fin(skb) )
    {
        // Searches for the Session Table Entry corresponding to the incoming tuple
        session_entry_p = nat64_get_session_entry( tuple );
        
        // If NO session was found:
        if ( session_entry_p == NULL )
        {
            pr_warning("NAT64:  ESTABLISHED state. Could NOT find an existing SESSION entry for an incoming V4 FIN packet.");
            pr_warning("        Dropping packet.");
            
            return NF_DROP;
        }

        // TODO: Packet is translated. 
        // TODO: Packet is forwarded.  

        // The state is moved to V6_FIN_RCV.
        session_entry_p->current_state = V6_FIN_RCV;

    }
    // else if packet is a V4 RST or a V6 RST:
    else if ( packet_is_v4_rst(skb) ||  packet_is_v6_rst(skb) )
    {
        // Searches for the Session Table Entry corresponding to the incoming tuple
        session_entry_p = nat64_get_session_entry( tuple );
        
        // If NO session was found:
        if ( session_entry_p == NULL )
        {
            pr_warning("NAT64:  ESTABLISHED state. Could NOT find an existing SESSION entry for an incoming V4 FIN packet.");
            pr_warning("        Dropping packet.");
            
            return NF_DROP;
        }

        // TODO: Packet is translated. 
        // TODO: Packet is forwarded.  

        // Set session lifetime.
        nat64_update_session_lifetime(session_entry_p, TCP_TRANS);
        
        // The state is moved to TRANS.
        session_entry_p->current_state = TRANS;
    }
    // else:
    else
    {
        // Searches for the Session Table Entry corresponding to the incoming tuple
        session_entry_p = nat64_get_session_entry( tuple );
        
        // If NO session was found:
        if ( session_entry_p == NULL )
        {
            pr_warning("NAT64:  ESTABLISHED state. Could NOT find an existing SESSION entry for an incoming other packet.");
            pr_warning("        Dropping packet.");
            
            return NF_DROP;
        }

        // TODO: Packet is translated. 
        // TODO: Packet is forwarded.  

        // TODO:    Define a maximum session lifetime, and replace this TCP_EST
        // Set session lifetime.
        nat64_update_session_lifetime(session_entry_p, TCP_EST);
    }
    
    /* TODO:    
     *      If the lifetime expires, then the NAT64 SHOULD send a probe packet
     *      (as defined next) to at least one of the endpoints of the TCP connection.
     *      The probe packet is a TCP segment for the connection
     *      with no data.  The sequence number and the acknowledgment number are
     *      set to zero.  All flags but the ACK flag are set to zero.  The state
     *      is moved to TRANS. */
    /*
    // If the lifetime has expired
    if (  )
    {
        // Searches for the Session Table Entry corresponding to the incoming tuple
        session_entry_p = get_session_entry_by_tuple( tuple, protocol );
        
        // If NO session was found:
        if ( session_entry_p == NULL )
        {
            pr_warning("NAT64:  ESTABLISHED state. Could NOT find an existing SESSION entry for an expired lifetime.");
            pr_warning("        Dropping packet.");
            
            return NF_DROP;
        }

        // TODO:    send a probe packet to at least one of the endpoints of the TCP connection.
        send_probe_packet(packet);
         
        // The state is moved to TRANS.
        session_entry_p->current_state = TRANS;
    }
    */

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
    u_int8_t protocol;

    protocol = IPPROTO_TCP;

    // if packet is a V6 FIN:
    if ( packet_is_v6_fin(skb) )
    {        
        // Searches for the Session Table Entry corresponding to the incoming tuple
        session_entry_p = nat64_get_session_entry( tuple );
        
        // If NO session was found:
        if ( session_entry_p == NULL )
        {
            pr_warning("NAT64:  V4 FIN RCV state. Could NOT find an existing SESSION entry for an incoming V6 FIN packet.");
            pr_warning("        Dropping packet.");
            
            return NF_DROP;
        }

        // TODO: Packet is translated. 
        // TODO: Packet is forwarded.  

        // Set session lifetime.
        nat64_update_session_lifetime(session_entry_p, TCP_TRANS);

       // The state is moved to V6 FIN + V4 FIN RCV.
        session_entry_p->current_state = V4_FIN_V6_FIN_RCV;
    }
    // else:
    else // Any packet other than the V6 FIN
    {
        // Searches for the Session Table Entry corresponding to the incoming tuple
        session_entry_p = nat64_get_session_entry( tuple );
        
        // If NO session was found:
        if ( session_entry_p == NULL )
        {
            pr_warning("NAT64:  V4 FIN RCV state. Could NOT find an existing SESSION entry for an incoming other packet.");
            pr_warning("        Dropping packet.");
            
            return NF_DROP;
        }

        // TODO: Packet is translated. 
        // TODO: Packet is forwarded.  

        // Set session lifetime.
        nat64_update_session_lifetime(session_entry_p, TCP_EST);

        // The state remains unchanged as V4 FIN RCV.
    }

    // TODO: If the lifetime expires, the Session Table Entry is deleted, and the state is moved to CLOSED.
    /*
    if (  )
    {
        if ( nat64_remove_session_entry(session_entry_p) == false )
        {
            pr_warning("NAT64:  V4 FIN RCV state. Could NOT delete an existing SESSION entry for an expired lifetime.");
            pr_warning("        Dropping packet.");
        }
        
        // The state is moved to CLOSED.
        session_entry_p->current_state = CLOSED;
    }
     * */

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
    u_int8_t protocol;

    protocol = IPPROTO_TCP;
    
    // if packet is a V4 FIN:
    if ( packet_is_v4_fin(skb) )
    {        
        // Searches for the Session Table Entry corresponding to the incoming tuple
        session_entry_p = nat64_get_session_entry( tuple );
        
        // If NO session was found:
        if ( session_entry_p == NULL )
        {
            pr_warning("NAT64:  V6 FIN RCV state. Could NOT find an existing SESSION entry for an incoming V4 FIN packet.");
            pr_warning("        Dropping packet.");
            
            return NF_DROP;
        }

        // TODO: Packet is translated. 
        // TODO: Packet is forwarded.  

        // Set session lifetime.
        nat64_update_session_lifetime(session_entry_p, TCP_TRANS);

        // The state is moved to V6 FIN + V4 FIN RCV.
        session_entry_p->current_state = V4_FIN_V6_FIN_RCV;
    }
    // else:
    else // Any packet other than the V4 FIN
    {
        // Searches for the Session Table Entry corresponding to the incoming tuple
        session_entry_p = nat64_get_session_entry( tuple );
        
        // If NO session was found:
        if ( session_entry_p == NULL )
        {
            pr_warning("NAT64:  V6 FIN RCV state. Could NOT find an existing SESSION entry for an incoming other packet.");
            pr_warning("        Dropping packet.");
            
            return NF_DROP;
        }

        // TODO: Packet is translated. 
        // TODO: Packet is forwarded.  

        // Set session lifetime.
        nat64_update_session_lifetime(session_entry_p, TCP_EST);

        // The state remains unchanged as V6 FIN RCV.
    }

    // TODO: If the lifetime expires, the Session Table Entry is deleted, and the state is moved to CLOSED.
    /*
    if (  )
    {
        if ( nat64_remove_session_entry(session_entry_p) == false )
        {
            pr_warning("NAT64:  V6 FIN RCV state. Could NOT delete an existing SESSION entry for an expired lifetime.");
            pr_warning("        Dropping packet.");
        }
        
        // The state is moved to CLOSED.
        session_entry_p->current_state = CLOSED;
    }
     * */

    return NF_ACCEPT;    
}

/** V6 FIN + V4 FIN RCV state.
 * 
 * Handles all packets.
 *
 * @param[in]   tuple   Tuple of the incoming packet.
 * @return  NF_ACCEPT if everything went OK, NF_DROP otherwise.
 */
int tcp_V4_FIN_V6_FIN_RCV_state_handle(struct sk_buff* skb, struct nf_conntrack_tuple *tuple)
{
    // struct session_entry *session_entry_p;
    
    // TODO: Packet is translated. 
    // TODO: Packet is forwarded.  

    // TODO: If the lifetime expires, the Session Table Entry is deleted, and the state is moved to CLOSED.
    /*
    if (  )
    {
        if ( nat64_remove_session_entry(session_entry_p) == false )
        {
            pr_warning("NAT64:  V6 FIN + V4 FIN RCV state. Could NOT delete an existing SESSION entry for an expired lifetime.");
            pr_warning("        Dropping packet.");
        }
        
        // The state is moved to CLOSED.
        session_entry_p->current_state = CLOSED;
    }
     * */

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
    struct session_entry *session_entry_p;
    u_int8_t protocol;

    protocol = IPPROTO_TCP;
    
    // Any packet other than the RST
    if ( ! packet_is_v4_rst(skb) && ! packet_is_v6_rst(skb) )
    {        
        // Searches for the Session Table Entry corresponding to the incoming tuple
        session_entry_p = nat64_get_session_entry( tuple );
        
        // If NO session was found:
        if ( session_entry_p == NULL )
        {
            pr_warning("NAT64:  V6 FIN RCV state. Could NOT find an existing SESSION entry for an incoming V4 FIN packet.");
            pr_warning("        Dropping packet.");
            
            return NF_DROP;
        }

        // Set session lifetime.
        nat64_update_session_lifetime(session_entry_p, TCP_EST);

        // The state is moved to ESTABLISHED.
        session_entry_p->current_state = ESTABLISHED;
    }
    // else:
    else 
    {
        //~ if packet is a RST:
            //~ delete session entry
    }

    // TODO: If the lifetime expires, the Session Table Entry is deleted, and the state is moved to CLOSED.
    /*
    if (  )
    {
        if ( nat64_remove_session_entry(session_entry_p) == false )
        {
            pr_warning("NAT64:  TRANS state. Could NOT delete an existing SESSION entry for an expired lifetime.");
            pr_warning("        Dropping packet.");
        }
        
        // The state is moved to CLOSED.
        session_entry_p->current_state = CLOSED;
    }
     * */

    return NF_ACCEPT;    
}

/*********************************************
 **                                         **
 **     TCP SECTION                         **
 **                                         **
 *********************************************/

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
    u_int8_t protocol;
    unsigned char current_state;

    protocol = IPPROTO_TCP;
    
    //  SessionEntry session = locateSessionEntryByTuple(inTuple, TCP)
    session_entry_p = nat64_get_session_entry( tuple );

//  return (session exists) ? session.main_function(tuple, session) : closed_state_function(tuple)
    // If NO session was found:
    if ( session_entry_p == NULL )
    {
        return tcp_closed_state_handle(skb, tuple);
    }   
    else 
    {
        // Retrieve the current state
        current_state = session_entry_p->current_state;

        // Act according the current state.
        switch( current_state )
        {
                case CLOSED:
                        return tcp_closed_state_handle(skb, tuple);
                        break;
                case V4_INIT:
                        return tcp_v4_init_state_handle(skb, tuple);
                        break;
                case V6_INIT:
                        return tcp_v6_init_state_handle(skb, tuple);
                        break;
                case ESTABLISHED:
                        return tcp_established_state_handle(skb, tuple);
                        break;
                case V4_FIN_RCV:
                        return tcp_v4_fin_rcv_state_handle(skb, tuple);
                        break;
                case V6_FIN_RCV:
                        return tcp_v6_fin_rcv_state_handle(skb, tuple);
                        break;
                case V4_FIN_V6_FIN_RCV:
                        return tcp_V4_FIN_V6_FIN_RCV_state_handle(skb, tuple);
                        break;
                case TRANS:
                        return tcp_trans_state_handle(skb, tuple);
                        break;
                default:
                        // TODO: What should we do?
                        pr_warning("NAT64:  TCP. Invalid state found.");
                        pr_warning("        Dropping packet.");

                        return NF_DROP;
        }
        
        //~ return tcp_session_main_handle(tuple, session_entry_p); 
    }

    return NF_DROP;
}


/*********************************************
 **                                         **
 **     MAIN FUNCTION                       **
 **                                         **
 *********************************************/

/** 
 *  Decide if a packet must be processed, updating binding and session 
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
pr_debug("f&u: Errores de ICMP no deben afectar las tablas.");
    /// Errores de ICMP no deben afectar las tablas.
    if ( IPPROTO_ICMP == tuple->L4_PROTOCOL )
        return NF_ACCEPT; 

pr_debug("f&u: Get rid of hairpinning loop and unwanted packets.");
    /// Get rid of hairpinning loop and unwanted packets.
    if ( NFPROTO_IPV6 == tuple->L3_PROTOCOL )
        if (  addr_has_pref64(&tuple->ipv6_src_addr) || 
            ! addr_has_pref64(&tuple->ipv6_dst_addr) )
            return NF_DROP; 
            
pr_debug("f&u: Get rid of un-expected packets");
    /// Get rid of un-expected packets
    if ( NFPROTO_IPV4 == tuple->L3_PROTOCOL )
        if ( ! addr_in_pool(&tuple->ipv4_dst_addr) )
            return NF_DROP;  
            
pr_debug("f&u: Process packet, according to its protocol.");
    /// Process packet, according to its protocol.
    switch (tuple->L4_PROTOCOL) {
        case IPPROTO_UDP:
            if ( NFPROTO_IPV6 == tuple->L3_PROTOCOL )
                return ipv6_udp(tuple);
            if ( NFPROTO_IPV4 == tuple->L3_PROTOCOL )
                return ipv4_udp(tuple);
            break;
        case IPPROTO_TCP:
            return tcp(skb, tuple);
            //~ if ( NFPROTO_IPV6 == packet.buffer->protocol )
                //~ return ipv6_tcp(tuple);
            //~ if ( NFPROTO_IPV4 == packet.buffer->protocol )     
                //~ return ipv4_tcp(tuple);
            break;
        case IPPROTO_ICMP:  // FIXME: This packages are discarded in the first IF !!!!
            if ( NFPROTO_IPV6 == tuple->L3_PROTOCOL )
                return ipv6_icmp6(tuple);
            if ( NFPROTO_IPV4 == tuple->L3_PROTOCOL )
                return ipv4_icmp4(tuple);
            break;    
        default:
            return NF_DROP;
            break;
    }

pr_debug("f&u: return NF_DROP");

    return NF_DROP;
}


