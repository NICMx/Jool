/** Unitary tests for the code used for validations.
 *
 * LEVEL:   kernel space
 * STAGE:   filtering
 * FILE:    xt_nat64_module_conf_validation.c
 * PATH:    /home/nat64/Dropbox/Nat64/work/pseudocodigo/codigo-Rob/
 * */
 
#include <linux/module.h>   /* Needed by all modules */
#include <linux/kernel.h>   /* Needed for KERN_INFO */
#include <linux/init.h>     /* Needed for the macros */
#include <linux/printk.h>   /* pr_* */
#include <linux/ipv6.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Roberto <r.aceves@itesm.mx>"); 
MODULE_DESCRIPTION("Unitary tests for the Filtering\'s part of NAT64");
MODULE_ALIAS("nat64_test_filtering");

#include "nat64/mod/unit_test.h"
#include "nat64/comm/str_utils.h"
#include "nat64/mod/pool4.h"
#include "nat64/mod/config.h"
#include "filtering_and_updating.c"



bool str_to_addr6_verbose(const char *str, struct in6_addr *addr)
{
	if (str_to_addr6(str, addr) != ERR_SUCCESS)
	{
		log_warning("Cannot parse '%s' as a valid IPv6 address", str);
		return false;
	}
	return true;
}
bool str_to_addr4_verbose(const char *str, struct in_addr *addr)
{
	if (str_to_addr4(str, addr) != ERR_SUCCESS)
	{
		log_warning("Cannot parse '%s' as a valid IPv4 address", str);
		return false;
	}
	return true;
}

#define INIT_TUPLE_IPV4_SRC_ADDR    "192.168.2.1"
#define INIT_TUPLE_IPV6_SRC_ADDR    "2001:db8:c0ca:1::1"
#define INIT_TUPLE_IPV4_DST_ADDR    "192.168.2.44"
#define INIT_TUPLE_IPV6_DST_ADDR    "64:ff9b::192.168.2.44"
#define INIT_TUPLE_IPV6_ICMP_ID     1024
#define INIT_TUPLE_IPV4_ICMP_ID     INIT_TUPLE_IPV6_ICMP_ID
#define INIT_TUPLE_IPV6_SRC_PORT    1080
#define INIT_TUPLE_IPV6_DST_PORT    1081
#define INIT_TUPLE_IPV4_SRC_PORT    1024
#define INIT_TUPLE_IPV4_DST_PORT    1081
bool init_tuple_for_test_ipv6(struct tuple *tuple, u_int8_t l4protocol)
{
    if (!str_to_addr6_verbose(INIT_TUPLE_IPV6_SRC_ADDR, &tuple->src.addr.ipv6))
    	return false;
    if (!str_to_addr6_verbose(INIT_TUPLE_IPV6_DST_ADDR, &tuple->dst.addr.ipv6))
    	return false;

    tuple->l3_proto = PF_INET6;
    tuple->l4_proto = l4protocol;
    
    if ( l4protocol == IPPROTO_ICMPV6 || l4protocol == IPPROTO_ICMP)
    {
        tuple->icmp_id = INIT_TUPLE_IPV6_ICMP_ID;
        tuple->dst.l4_id = INIT_TUPLE_IPV6_ICMP_ID;
    }
    else
    {
        tuple->src.l4_id = INIT_TUPLE_IPV6_SRC_PORT;
        tuple->dst.l4_id = INIT_TUPLE_IPV6_DST_PORT;
    }

    return true;
}
bool init_tuple_for_test_ipv4(struct tuple *tuple, u_int8_t l4protocol)
{
    if (!str_to_addr4_verbose(INIT_TUPLE_IPV4_DST_ADDR, &tuple->src.addr.ipv4)) // ?
    	return false;
    if (!str_to_addr4_verbose(INIT_TUPLE_IPV4_SRC_ADDR, &tuple->dst.addr.ipv4)) // ?
		return false;

    tuple->l3_proto = PF_INET;
    tuple->l4_proto = l4protocol;

    if ( l4protocol == IPPROTO_ICMP )
    {
        tuple->icmp_id = INIT_TUPLE_IPV4_ICMP_ID;
        tuple->dst.l4_id = INIT_TUPLE_IPV4_ICMP_ID;
    }
    else
    {
        tuple->src.l4_id = INIT_TUPLE_IPV4_DST_PORT; // ?
        tuple->dst.l4_id = INIT_TUPLE_IPV4_SRC_PORT; // ?
    }

    return true;
}

#define SKB_PAYLOAD 22
struct sk_buff* init_skb_for_test(  struct tuple *tuple, u_int8_t protocol )
{
    __u32 l3_len;
    __u32 l4_len;
    struct tcphdr *tcp_header;
    struct udphdr *udp_header;
    struct icmphdr *icmp_header;
    struct iphdr *ip_header = NULL;
    
    struct sk_buff *skb;

    switch(protocol)
    {
        case IPPROTO_TCP:
            l4_len = sizeof(struct tcphdr);
            break;
        case IPPROTO_UDP:
            l4_len = sizeof(struct udphdr);
            break;
        case IPPROTO_ICMP:
            l4_len = sizeof(struct icmphdr);
            break;
        default:
            log_warning("Invalid protocol 1: %u", protocol);
            return NULL;
    }

    l3_len = sizeof(struct iphdr);
    skb = alloc_skb(LL_MAX_HEADER + l3_len + l4_len + SKB_PAYLOAD, GFP_ATOMIC);
    if (!skb)
    {
        log_warning("  New packet allocation failed.");
        return NULL;
    }

    skb_reserve(skb, LL_MAX_HEADER);
    skb_put(skb, l3_len + l4_len + SKB_PAYLOAD);

    skb_reset_mac_header(skb);
    skb_reset_network_header(skb);
    skb_set_transport_header(skb, l3_len);

    ip_header = ip_hdr(skb);
    memset(ip_header, 0, sizeof(struct iphdr));

    switch(protocol)
    {
        case IPPROTO_TCP:
            tcp_header = tcp_hdr(skb);
            memset(tcp_header, 0, l4_len);

            tcp_header->source = tuple->src.l4_id;
            tcp_header->dest = tuple->dst.l4_id;
            break;
        case IPPROTO_UDP:
            udp_header = udp_hdr(skb);
            memset(udp_header, 0, l4_len);
            
            udp_header->source = tuple->src.l4_id;
            udp_header->dest = tuple->dst.l4_id;
            udp_header->len = htons(sizeof(struct udphdr) + SKB_PAYLOAD);
            udp_header->check = 0;
            break;
        case IPPROTO_ICMP:
            icmp_header = icmp_hdr(skb);
            memset(icmp_header, 0, l4_len);

			icmp_header->type = ICMP_ECHO;
			//~ icmp_header->type = ICMP_ECHOREPLY;
			//~ icmp6_header->icmp6_type = ICMPV6_ECHO_REQUEST;
			//~ icmp6_header->icmp6_type = ICMPV6_ECHO_REPLY;
            break;
        default:
            log_warning("Invalid protocol 2: %u", protocol);
            kfree_skb(skb);
            return NULL;
    }

    ip_header->version = 4;
    ip_header->ihl = (sizeof(struct iphdr)) /4 ;
    ip_header->tos = 0;
    ip_header->tot_len = htons(l3_len + l4_len + SKB_PAYLOAD);
    ip_header->id = htons(111);
    ip_header->frag_off = 0;
    ip_header->ttl = 64;
    ip_header->protocol = protocol;
    ip_header->check = 0;
    //~ skb_forward_csum(skb);

    ip_header->saddr = tuple->src.addr.ipv4.s_addr;
    ip_header->daddr = tuple->dst.addr.ipv4.s_addr;

    skb->protocol = htons(ETH_P_IP);

    return skb;
}

#define IPV6_INJECT_BIB_ENTRY_SRC_ADDR  "2001:db8:c0ca:1::1"
#define IPV6_INJECT_BIB_ENTRY_SRC_PORT  1080
#define IPV4_INJECT_BIB_ENTRY_DST_ADDR  "192.168.2.1"
#define IPV4_INJECT_BIB_ENTRY_DST_PORT  1082
#define INIT_TUPLE_ICMP_ID              10
bool inject_bib_entry( u_int8_t l4protocol )
{
    struct ipv4_tuple_address ta_ipv4;
    struct ipv6_tuple_address ta_ipv6;

    struct in_addr addr4;
    struct in6_addr addr6;

    struct bib_entry *bib_e;

    if (!str_to_addr4_verbose(IPV4_INJECT_BIB_ENTRY_DST_ADDR, &addr4))
    	return false;
    if (!str_to_addr6_verbose(IPV6_INJECT_BIB_ENTRY_SRC_ADDR, &addr6))
    	return false;

    if ( l4protocol == IPPROTO_ICMP || l4protocol == IPPROTO_ICMPV6 )
    {
        transport_address_ipv4( addr4, INIT_TUPLE_ICMP_ID, &ta_ipv4 );
        transport_address_ipv6( addr6, INIT_TUPLE_ICMP_ID, &ta_ipv6 );
    }
    else
    {
        transport_address_ipv4( addr4, IPV4_INJECT_BIB_ENTRY_DST_PORT, &ta_ipv4 );
        transport_address_ipv6( addr6, IPV6_INJECT_BIB_ENTRY_SRC_PORT, &ta_ipv6 );
    }

    bib_e = bib_create( &ta_ipv4, &ta_ipv6);
    if (!bib_e)
    {
    	log_warning("Could not allocate the BIB entry.");
    	return false;
    }
    
    if (bib_add( bib_e, l4protocol ) != ERR_SUCCESS)
    {
    	log_warning("Could not insert the BIB entry to the table.");
		return false;
    }

    return true;
}

#define IPV6_INIT_SESSION_ENTRY_SRC_ADDR  "2001:db8:c0ca:1::1"
#define IPV6_INIT_SESSION_ENTRY_SRC_PORT  1080
#define IPV6_INIT_SESSION_ENTRY_DST_ADDR  "64:ff9b::192.168.2.44"
#define IPV6_INIT_SESSION_ENTRY_DST_PORT  1080
#define IPV4_INIT_SESSION_ENTRY_SRC_ADDR  "192.168.2.1"
#define IPV4_INIT_SESSION_ENTRY_SRC_PORT  1082
#define IPV4_INIT_SESSION_ENTRY_DST_ADDR  "192.168.2.44"
#define IPV4_INIT_SESSION_ENTRY_DST_PORT  1082
bool init_session_entry( u_int8_t l4protocol, struct session_entry *se )
{
    struct in_addr src4;
    struct in_addr dst4;
    struct in6_addr src6;
    struct in6_addr dst6;
    
    if (!str_to_addr6_verbose(IPV6_INIT_SESSION_ENTRY_SRC_ADDR, &src6))
    	return false;
    if (!str_to_addr6_verbose(IPV6_INIT_SESSION_ENTRY_DST_ADDR, &dst6))
		return false;
    if (!str_to_addr4_verbose(IPV4_INIT_SESSION_ENTRY_SRC_ADDR, &src4))
		return false;
    if (!str_to_addr4_verbose(IPV4_INIT_SESSION_ENTRY_DST_ADDR, &dst4))
		return false;

    se->ipv6.remote.address = src6; // X'
    se->ipv6.remote.l4_id = IPV6_INIT_SESSION_ENTRY_SRC_PORT; // x
    se->ipv6.local.address = dst6; // Y'
    se->ipv6.local.l4_id = IPV6_INIT_SESSION_ENTRY_DST_PORT; // y
    se->ipv4.local.address = src4; // (T, t)
    se->ipv4.local.l4_id = IPV4_INIT_SESSION_ENTRY_SRC_PORT; // (T, t)
    se->ipv4.remote.address = dst4; // (Z, z) // (Z(Y’),y)
    se->ipv4.remote.l4_id = IPV4_INIT_SESSION_ENTRY_DST_PORT; // (Z, z) // (Z(Y’),y)

    se->is_static = false;
    se->dying_time = 0;
    se->bib = NULL;
    INIT_LIST_HEAD(&se->entries_from_bib);
    INIT_LIST_HEAD(&se->all_sessions);
    se->l4_proto = l4protocol;
    se->state = CLOSED;

    return true;
}



#define IPV4_TRANSPORT_ADDR     "192.168.1.4"
#define IPV4_TRANSPORT_PORT     1081
bool test_transport_address_ipv4( void )
{
    struct in_addr addr;
    struct ipv4_tuple_address ta;
    bool success = true;

    if (!str_to_addr4_verbose(IPV4_TRANSPORT_ADDR, &addr))
    	return false;
    transport_address_ipv4( addr, IPV4_TRANSPORT_PORT, &ta );
    
    success &= assert_equals_ipv4(&ta.address, &addr,
        "Check that the address part of an IPv4 transport address is correct.");
    success &= assert_equals_u16(ta.l4_id, IPV4_TRANSPORT_PORT,
        "Check that the port part of an IPv4 transport address is correct.");

    return success;
}


#define IPV6_TRANSPORT_ADDR     "2001:db8:c0ca:1::1"
#define IPV6_TRANSPORT_PORT     1081
bool test_transport_address_ipv6( void )
{
    struct in6_addr addr6;
    struct ipv6_tuple_address ta;
    bool success = true;

    // Build an IPv6 transport address from address & port
    if (!str_to_addr6_verbose(IPV6_TRANSPORT_ADDR, &addr6))
		return false;
    transport_address_ipv6( addr6, IPV6_TRANSPORT_PORT, &ta );
    
    success &= assert_equals_ipv6(&ta.address, &addr6 ,
        "Check that the address part of an IPv6 transport address is correct.");
    success &= assert_equals_u16( ta.l4_id, IPV6_TRANSPORT_PORT ,
        "Check that the port part of an IPv6 transport address is correct.");
    
    return success;
}


#define IPV6_EXTRACT_ADDR     "64:ff9b::192.168.2.3"
#define IPV4_EXTRACTED_ADDR     "192.168.2.3"
bool test_extract_ipv4_from_ipv6( void )
{
    struct in6_addr addr6;
    struct in_addr extracted4;
    struct in_addr correct4;
    bool success = true;

    if (!pool6_init())
    	return false;
    if (!str_to_addr6_verbose(IPV6_EXTRACT_ADDR, &addr6))
		return false;
    if (!str_to_addr4_verbose(IPV4_EXTRACTED_ADDR, &correct4))
		return false;

    success &= assert_true(extract_ipv4(&addr6, &extracted4),
        "Check that an IPv4 address can be extracted from an IPv6 address.");
    success &= assert_equals_ipv4(&extracted4, &correct4, 
        "Assert that the extraction of the IPv4 address was correct.");

    pool6_destroy();

    return success;
}


#define IPV6_EMBEDDED_ADDR      "64:ff9b::192.168.2.3"
#define IPV4_EMBEDDABLE_ADDR    "192.168.2.3"
bool test_embed_ipv4_in_ipv6( void )
{
    struct in_addr embeddable4;
    struct in6_addr embed6;
    struct in6_addr embedded6;
    bool success = true;

    if (!pool6_init())
		return false;
    if (!str_to_addr4_verbose(IPV4_EMBEDDABLE_ADDR, &embeddable4))
		return false;
    if (!str_to_addr6_verbose(IPV6_EMBEDDED_ADDR, &embedded6))
		return false;
    
    success &= assert_true(append_ipv4( &embeddable4, &embed6 ) , 
        "Check that we can embed an IPv4 address inside of an IPv6 address correctly.");
    success &= assert_equals_ipv6( &embed6 , &embedded6 , 
        "Verify that the IPv4 was embedded into a IPv6 address is correct.");
    
    pool6_destroy();

    return success;
}


#define IPV6_ALLOCATE_PORT  1024
#define IPV4_ALLOCATED_ADDR     "192.168.2.1"
bool test_allocate_ipv4_transport_address( void )
{
	u_int8_t protocols[] = { IPPROTO_ICMP, IPPROTO_TCP, IPPROTO_UDP };
	__u16 expected_ports[] = { IPV6_ALLOCATE_PORT, IPV6_ALLOCATE_PORT, IPV6_ALLOCATE_PORT };

    struct in_addr expected_addr;
    
    struct tuple tuple;
    struct ipv4_tuple_address new_ipv4_transport_address;

    bool success = true;
    int i;

    success &= pool6_init();
    success &= pool4_init(true);
    success &= bib_init();
    success &= str_to_addr4_verbose(IPV4_ALLOCATED_ADDR, &expected_addr);
    success &= inject_bib_entry( IPPROTO_ICMP );
    success &= inject_bib_entry( IPPROTO_TCP );
    success &= inject_bib_entry( IPPROTO_UDP );
    if (!success)
    	return false;

    for (i = 0; i < ARRAY_SIZE(protocols); i++)
    {
		init_tuple_for_test_ipv6(&tuple, protocols[i]);

		success &= assert_true(allocate_ipv4_transport_address(&tuple, protocols[i], &new_ipv4_transport_address),
			"Check that we can allocate a brand new IPv4 transport address.");
		success &= assert_equals_ipv4(&expected_addr , &new_ipv4_transport_address.address,
			"Check that the allocated IPv4 address is correct.");
		success &= assert_equals_u16( expected_ports[i], new_ipv4_transport_address.l4_id,
			"Check that the allocated IPv4 port is correct.");
    }

    bib_destroy();
    pool4_destroy();
    pool6_destroy();

    return success;
}


#define IPV4_ALLOCATED_PORT_DIGGER  1024
bool test_allocate_ipv4_transport_address_digger( void )
{
    struct in_addr expected_addr;
    struct tuple tuple;
    struct ipv4_tuple_address new_ipv4_transport_address;
    bool success = true;

    bib_init();
    pool4_init(true);

    success &= inject_bib_entry( IPPROTO_ICMP );
    success &= inject_bib_entry( IPPROTO_TCP );
    success &= init_tuple_for_test_ipv6(&tuple, IPPROTO_UDP);
    success &= str_to_addr4_verbose(IPV4_ALLOCATED_ADDR, &expected_addr);
    if (!success)
    	return false;
    
    success &= assert_true( allocate_ipv4_transport_address_digger(&tuple, IPPROTO_UDP, &new_ipv4_transport_address),
        "Check that we can allocate a brand new IPv4 transport address for UDP.");
    success &= assert_true( ipv4_addr_equals(&new_ipv4_transport_address.address, &expected_addr) ,
        "Check that the allocated IPv4 address is correct for UDP.");
    success &= assert_equals_u16( IPV4_ALLOCATED_PORT_DIGGER, new_ipv4_transport_address.l4_id,
        "Check that the allocated IPv4 port is correct for UDP.");

    pool4_destroy();
    bib_destroy();

    return success;
}


bool test_ipv6_udp( void )
{
    u_int8_t protocol = IPPROTO_UDP;
    struct tuple tuple;
    struct sk_buff *skb;
    bool success = true;

    if (!init_tuple_for_test_ipv6( &tuple, protocol ))
    	return false;
    skb = init_skb_for_test( &tuple, protocol );
    if (!skb)
    	return false;

    success &= assert_equals_int(NF_ACCEPT, ipv6_udp( skb, &tuple ), 
		"See if we can process correctly an IPv6 UDP packet.");

    kfree_skb(skb);
    return success;
}

bool test_ipv4_udp( void )
{
    u_int8_t protocol = IPPROTO_UDP;
    struct tuple tuple;
    struct sk_buff* skb;
    bool success = true;

    skb = init_skb_for_test( &tuple, protocol );
    if (!skb)
    	return false;

    success &= init_tuple_for_test_ipv4( &tuple , protocol );
    success &= assert_equals_int(NF_DROP, ipv4_udp( skb, &tuple ), 
		"See if we discard an IPv4 UDP packet, which tries to start a communication.");

    success &= init_tuple_for_test_ipv6( &tuple , protocol );
    success &= assert_equals_int(NF_ACCEPT, ipv6_udp( skb, &tuple ), 
		"See if we can process correctly an IPv6 UDP packet.");

    success &= init_tuple_for_test_ipv4( &tuple , protocol  );
    success &= assert_equals_int(NF_ACCEPT, ipv4_udp( skb, &tuple ), 
		"See if we can process correctly an expected IPv4 UDP packet.");

    kfree_skb(skb);

    return success;
}

bool test_ipv6_icmp6( void )
{
    u_int8_t protocol = IPPROTO_ICMP;
    struct tuple tuple;
    struct sk_buff *skb;
    bool success = true;

    success &= init_tuple_for_test_ipv6( &tuple , protocol );
    skb = init_skb_for_test( &tuple, protocol );
    success &= assert_not_null(skb, "init_skb_for_test");
    if (!success)
    	return false;

    success &= assert_equals_int(NF_ACCEPT, ipv6_icmp6(skb, &tuple),
		"See if we can process correctly an IPv6 ICMP packet.");

    kfree_skb(skb);
      
    return success;
}

bool test_ipv4_icmp4( void )
{
    u_int8_t protocol;
    struct tuple tuple;
    struct sk_buff* skb = NULL;
    bool success = true;

    protocol = IPPROTO_ICMP;
    success &= init_tuple_for_test_ipv4( &tuple , protocol );
    skb = init_skb_for_test( &tuple, protocol );
    success &= assert_not_null(skb, "init_skb_for_test");
    success &= assert_equals_int(NF_DROP, ipv4_icmp4( skb, &tuple ), 
		"See if we discard an IPv4 ICMP packet, which tries to start a communication.");
    kfree_skb(skb);

    protocol = IPPROTO_ICMP;
    success &= init_tuple_for_test_ipv6( &tuple , protocol );
    skb = init_skb_for_test( &tuple, protocol );
    success &= assert_not_null(skb, "init_skb_for_test");        
    success &= assert_equals_int(NF_ACCEPT, ipv6_icmp6(skb, &tuple ), 
		"See if we can process correctly an IPv6 ICMP packet.");
    kfree_skb(skb);

    protocol = IPPROTO_ICMP;
    success &= init_tuple_for_test_ipv4( &tuple , protocol );
    skb = init_skb_for_test( &tuple, protocol );
    success &= assert_not_null(skb, "init_skb_for_test");        
    success &= assert_equals_int(NF_ACCEPT, ipv4_icmp4( skb, &tuple ), 
		"See if we can process correctly an expected IPv4 ICMP packet.");
    kfree_skb(skb);

    return success;
}
/*
#define BUFFER_SIZE_ICMP 22
bool test_send_icmp_error_message( void )
{
    struct tuple tuple;
    u_int8_t protocol;
    u_int8_t type;
    u_int8_t code;

    struct sk_buff *skb = NULL;

    bool success = true;

    protocol = IPPROTO_ICMP;

    // Init tuple
    init_tuple_for_test_ipv4( &tuple , protocol );
    // Init skb
    //~ if ( (skb = init_skb_for_test( &tuple, protocol ) ) == NULL )
    //~ skb = init_skb_for_test( &tuple, protocol );
    //~ success &= assert_not_null(skb, "init_skb_for_test");        

    //~ l3_len = sizeof(struct iphdr);
    //~ skb = alloc_skb(LL_MAX_HEADER + l3_len + sizeof(struct icmphdr) + BUFFER_SIZE_ICMP, GFP_ATOMIC);
    //~ if (!skb) {
        //~ log_warning("  New packet allocation failed.");
        //~ return NULL;
    //~ }

    //~ skb_reserve(skb, LL_MAX_HEADER);
    //~ skb_put(skb, l3_len + sizeof(struct icmphdr) + BUFFER_SIZE_ICMP);
    //~ skb_reset_mac_header(skb);
    //~ skb_reset_network_header(skb);
    //~ skb_set_transport_header(skb, l3_len);
    //~ icmp_header = icmp_hdr(skb);
    //~ memset(ip_header, 0, sizeof(struct iphdr));
    //~ memset(icmp_header, 0, sizeof(struct icmphdr));     
    //~ skb->protocol = htons(ETH_P_IP);


    log_debug("Test if we can send an ICMP error packet: DESTINATION_UNREACHABLE, HOST_UNREACHABLE");
    type = DESTINATION_UNREACHABLE;
    code = HOST_UNREACHABLE;
    send_icmp_error_message( skb, type, code);

    log_debug("Test if we can send an ICMP error packet: DESTINATION_UNREACHABLE, ADDRESS_UNREACHABLE");
    type = DESTINATION_UNREACHABLE;
    code = ADDRESS_UNREACHABLE;
    send_icmp_error_message( skb, type, code);

    log_debug("Test if we can send an ICMP error packet: DESTINATION_UNREACHABLE, COMMUNICATION_ADMINISTRATIVELY_PROHIBITED");
    type = DESTINATION_UNREACHABLE;
    code = COMMUNICATION_ADMINISTRATIVELY_PROHIBITED;
    send_icmp_error_message( skb, type, code);

    kfree_skb(skb);


    // Init tuple
    init_tuple_for_test_ipv6( &tuple , protocol );
    // Init skb
    skb = init_skb_for_test( &tuple, protocol );
    success &= assert_not_null(skb, "init_skb_for_test");        

    log_debug("Test if we can send an ICMPv6 error packet: DESTINATION_UNREACHABLE, HOST_UNREACHABLE");
    type = DESTINATION_UNREACHABLE;
    code = HOST_UNREACHABLE;
    send_icmp_error_message( skb, type, code);

    log_debug("Test if we can send an ICMPv6 error packet: DESTINATION_UNREACHABLE, ADDRESS_UNREACHABLE");
    type = DESTINATION_UNREACHABLE;
    code = ADDRESS_UNREACHABLE;
    send_icmp_error_message( skb, type, code);

    log_debug("Test if we can send an ICMPv6 error packet: DESTINATION_UNREACHABLE, COMMUNICATION_ADMINISTRATIVELY_PROHIBITED");
    type = DESTINATION_UNREACHABLE;
    code = COMMUNICATION_ADMINISTRATIVELY_PROHIBITED;
    send_icmp_error_message( skb, type, code);
    
    kfree_skb(skb);

    
    return success;
}
*/

#define INIT_TUPLE_IPV6_HAIR_LOOP_DST_ADDR    "2001:db8:c0ca:1::1"
#define INIT_TUPLE_IPV6_HAIR_LOOP_SRC_ADDR    "64:ff9b::192.168.2.44"
#define INIT_TUPLE_IPV4_NOT_POOL_DST_ADDR     "192.168.100.44"
bool test_filtering_and_updating( void )
{
    u_int8_t protocol;
    struct tuple tuple;
    struct sk_buff *skb;
    struct in_addr addr4;
    struct in6_addr addr6;
    
    bool success = true;

    log_debug(" >>> Errores de ICMP no deben afectar las tablas ");
    protocol = IPPROTO_ICMP;
    success &= init_tuple_for_test_ipv4( &tuple , protocol );
    skb = init_skb_for_test( &tuple, protocol );
    success &= assert_not_null(skb, "init_skb_for_test");        
    icmp_hdr(skb)->type = ICMP_DEST_UNREACH; // Error packet
    // Process a tuple generated from a incoming IPv6 packet:
    success &= assert_equals_int(NF_ACCEPT,  filtering_and_updating( skb, &tuple),
		"See if we can forward an IPv4 ICMP packet.");
    kfree_skb(skb);

    log_debug(" >>> Get rid of hairpinning loop ");
    protocol = IPPROTO_UDP;
    success &= init_tuple_for_test_ipv6( &tuple , protocol );
    skb = init_skb_for_test( &tuple, protocol );
    success &= assert_not_null(skb, "init_skb_for_test");        
    // Add pref64
    success &= str_to_addr6_verbose(INIT_TUPLE_IPV6_HAIR_LOOP_SRC_ADDR , &addr6);
    tuple.src.addr.ipv6 = addr6;
    success &= assert_equals_int(NF_DROP,  filtering_and_updating( skb, &tuple), 
		"See if we can get rid of hairpinning loop in IPv6.");
    kfree_skb(skb);

    log_debug(" >>> Get rid of unwanted packets ");
    success &= init_tuple_for_test_ipv6( &tuple , protocol );
    skb = init_skb_for_test( &tuple, protocol );
    success &= assert_not_null(skb, "init_skb_for_test");        
    // Unwanted packet
    success &= str_to_addr6_verbose(INIT_TUPLE_IPV6_HAIR_LOOP_DST_ADDR , &addr6);
    tuple.dst.addr.ipv6 = addr6;
    success &= assert_equals_int(NF_DROP,  filtering_and_updating( skb, &tuple), 
		"See if we can get rid of unwanted packets in IPv6.");
    kfree_skb(skb);

    log_debug(" >>> Get rid of un-expected packets, destined to an address not in pool");
    success &= init_tuple_for_test_ipv4( &tuple , protocol );
    skb = init_skb_for_test( &tuple, protocol );
    success &= assert_not_null(skb, "init_skb_for_test");        
    // Packet destined to an address not in pool
    success &= str_to_addr4_verbose(INIT_TUPLE_IPV4_NOT_POOL_DST_ADDR , &addr4);
    tuple.dst.addr.ipv4 = addr4;
    success &= assert_equals_int(NF_DROP,  filtering_and_updating( skb, &tuple), 
		"See if we can get rid of packet destined to an address not in pool.");
    kfree_skb(skb);

    log_debug(" >>> IPv4 incoming packet --> reject");
    success &= init_tuple_for_test_ipv4( &tuple , protocol );
    skb = init_skb_for_test( &tuple, protocol );
    success &= assert_not_null(skb, "init_skb_for_test");        
    success &= assert_equals_int(NF_DROP,  filtering_and_updating( skb, &tuple), 
		"See if we can do reject an incoming IPv4 UDP packet.");
    kfree_skb(skb);

    log_debug(" >>> IPv6 incoming packet --> accept");
    success &= init_tuple_for_test_ipv6( &tuple , protocol );
    skb = init_skb_for_test( &tuple, protocol );
    success &= assert_not_null(skb, "init_skb_for_test");        
    success &= assert_equals_int(NF_ACCEPT, filtering_and_updating( skb, &tuple),
    		"See if we can do filtering and updating on an incoming IPv6 UDP packet.");
    kfree_skb(skb);

    log_debug(" >>> IPv4 incoming packet --> accept");
    success &= init_tuple_for_test_ipv4( &tuple , protocol );
    skb = init_skb_for_test( &tuple, protocol );
    success &= assert_not_null(skb, "init_skb_for_test");        
    success &= assert_equals_int(NF_ACCEPT,  filtering_and_updating( skb, &tuple), 
		"See if we can do filtering and updating on an incoming IPv4 UDP packet.");
    kfree_skb(skb);
    
    return success;
}

enum {  PACKET_TYPE_V6_SYN=1, PACKET_TYPE_V4_SYN,
        PACKET_TYPE_V6_RST,   PACKET_TYPE_V4_RST,
        PACKET_TYPE_V6_FIN,   PACKET_TYPE_V4_FIN    };
#define BUFFER_SIZE   22    
struct sk_buff *init_packet_type_for_test(unsigned char type)
{
    __u32 l3_len;
    struct tcphdr *tcp_header;
    struct sk_buff *skb;

    switch (type) {
        case PACKET_TYPE_V6_SYN:
        case PACKET_TYPE_V6_RST:
        case PACKET_TYPE_V6_FIN:
            l3_len = sizeof(struct ipv6hdr);
            break;

        case PACKET_TYPE_V4_SYN:
        case PACKET_TYPE_V4_RST:
        case PACKET_TYPE_V4_FIN:
            l3_len = sizeof(struct iphdr);
            break;
         default:
            log_warning("  test_filtering.c: Invalid packet type in init_packet_type_for_test().");
            return NULL;
    }

    skb = alloc_skb(LL_MAX_HEADER + l3_len + sizeof(struct tcphdr) + BUFFER_SIZE, GFP_ATOMIC);
    if (!skb) {
        log_warning("  New packet allocation failed.");
        return NULL;
    }

    skb_reserve(skb, LL_MAX_HEADER);
    skb_put(skb, l3_len + sizeof(struct tcphdr) + BUFFER_SIZE);

    skb_reset_mac_header(skb);
    skb_reset_network_header(skb);
    skb_set_transport_header(skb, l3_len);

    tcp_header = tcp_hdr(skb);

    memset(tcp_header, 0, sizeof(struct tcphdr));
    switch (type)
    {
        case PACKET_TYPE_V6_SYN:
            tcp_header->syn = 1;
            skb->protocol = htons(ETH_P_IPV6);
            break;
        case PACKET_TYPE_V4_SYN:
            tcp_header->syn = 1;
            skb->protocol = htons(ETH_P_IP);
            break;
        case PACKET_TYPE_V6_RST:
            tcp_header->rst = 1;
            skb->protocol = htons(ETH_P_IPV6);
            break;
        case PACKET_TYPE_V4_RST:
            tcp_header->rst = 1;
            skb->protocol = htons(ETH_P_IP);
            break;
        case PACKET_TYPE_V6_FIN:
            tcp_header->fin = 1;
            skb->protocol = htons(ETH_P_IPV6);
            break;
        case PACKET_TYPE_V4_FIN:
            tcp_header->fin = 1;
            skb->protocol = htons(ETH_P_IP);
            break;
        default:
            log_warning("  test_filtering.c: Invalid packet type in init_packet_type_for_test().");
            kfree_skb(skb);
            return NULL;
    }

    return skb;
}


bool test_packet_is_ipv4( void )
{
    struct sk_buff *buffer;
    bool success = true;

    // Set packet type to V4 SYN
    if ((buffer = init_packet_type_for_test( PACKET_TYPE_V4_SYN )) == NULL)
        return false;

    success &= assert_true( packet_is_ipv4( buffer ), "Test if we detect an IPv4 packet.");

    kfree_skb(buffer);
    return success;
}

bool test_packet_is_ipv6( void )
{
    struct sk_buff *skb;
    bool success = true;

    // Set packet type to V6 SYN
    if ((skb = init_packet_type_for_test( PACKET_TYPE_V6_SYN )) == NULL)
        return false;

    success &= assert_true( packet_is_ipv6( skb ), "Test if we detect an IPv6 packet.");

    kfree_skb(skb);
    return success;
}

bool test_packet_is_v4_syn( void )
{
    struct sk_buff *skb;
    bool success = true;

    // Set packet type to V4 SYN
    if ((skb = init_packet_type_for_test( PACKET_TYPE_V4_SYN )) == NULL)
        return false;

    success &= assert_true(packet_is_v4_syn( skb ), "Test if we detect a V4 SYN packet.");

    kfree_skb(skb);
    return success;
}

bool test_packet_is_v6_syn( void )
{
    struct sk_buff *skb;
    bool success = true;

    // Set packet type to V6 SYN
    if ((skb = init_packet_type_for_test( PACKET_TYPE_V6_SYN )) == NULL)
        return false;

    success &= assert_true( packet_is_v6_syn( skb ), "Test if we detect a V6 SYN packet.");

    kfree_skb(skb);
    return success;
}

bool test_packet_is_v4_fin( void )
{
    struct sk_buff *skb;
    bool success = true;

    // Set packet type to V4 FIN
    if ((skb = init_packet_type_for_test( PACKET_TYPE_V4_FIN )) == NULL)
        return false;

    success &= assert_true(packet_is_v4_fin( skb ), "Test if we detect a V4 FIN packet.");

    kfree_skb(skb);
    return success;
}

bool test_packet_is_v6_fin( void )
{
    struct sk_buff *skb;
    bool success = true;

    // Set packet type to V6 FIN
    if ((skb = init_packet_type_for_test( PACKET_TYPE_V6_FIN )) == NULL)
        return false;

    success &= assert_true( packet_is_v6_fin( skb ), "Test if we detect a V6 FIN packet.");

    kfree_skb(skb);
    return success;
}

bool test_packet_is_v4_rst( void )
{
    struct sk_buff *skb;
    bool success = true;

    // Set packet type to V4 RST
    if ((skb = init_packet_type_for_test( PACKET_TYPE_V4_RST )) == NULL)
        return false;

    success &= assert_true(packet_is_v4_rst( skb ), "Test if we detect a V4 RST packet.");

    kfree_skb(skb);
    return success;
}

bool test_packet_is_v6_rst( void )
{
    struct sk_buff *skb;
    bool success = true;

    // Set packet type to V6 RST
    if ((skb = init_packet_type_for_test( PACKET_TYPE_V6_RST )) == NULL)
        return false;

    success &= assert_true( packet_is_v6_rst( skb ), "Test if we detect a V6 RST packet.");

    kfree_skb(skb);
    return success;
}

/**
 * BTW: This test contains no asserts.
 */
bool test_send_probe_packet( void )
{
    struct session_entry se;
    bool success = true;

    if (!init_session_entry( IPPROTO_TCP, &se ))
    	return false;

    log_debug("Sending a packet, catch it!");
    success &= assert_true( send_probe_packet( &se ), "Test if we can send a probe packet.");

    return success;
}


bool test_tcp_closed_state_handle_6( void )
{
    struct sk_buff *skb;
    struct session_entry *session;
    struct tuple tuple;
    bool success = true;

    if (!(skb = init_packet_type_for_test( PACKET_TYPE_V6_SYN )))
        return false;
    if (!init_tuple_for_test_ipv6( &tuple, IPPROTO_TCP ))
    	return false;

    success &= assert_true(tcp_closed_state_handle( skb, &tuple ), "V6 syn-result");

    session = session_get( &tuple );
    success &= assert_not_null(session, "V6 syn-session.");
    if (session)
    	success &= assert_equals_u8(V6_INIT, session->state, "V6 syn-state");
    kfree_skb(skb);

    return success;
}

bool test_tcp_closed_state_handle_4( void )
{
    struct sk_buff *skb;
    struct session_entry *session;
    struct tuple tuple;
    bool success = true;

    config.drop_external_tcp = false;

    if (!(skb = init_packet_type_for_test( PACKET_TYPE_V4_SYN )))
        return false;
    if (!init_tuple_for_test_ipv4( &tuple, IPPROTO_TCP ))
        return false;

    success &= assert_true(tcp_closed_state_handle( skb, &tuple ), "V4 syn-result");

    session = session_get( &tuple );
    success &= assert_not_null(session, "V4 syn-session");
    if (session)
        success &= assert_equals_u8(V4_INIT, session->state, "V4 syn-state");
    kfree_skb(skb);

    return success;
}

static bool init_skb_and_session(struct sk_buff **skb, struct session_entry *session,
        unsigned char type, u_int8_t state, unsigned int lifetime)
{
    struct tuple tuple4, tuple6;

    // Init the packet.
    *skb = init_packet_type_for_test(type);
    if (!(*skb))
        return false;

    // Init the session.
    if (!init_tuple_for_test_ipv4(&tuple4, IPPROTO_TCP))
        goto failure;
    if (!init_tuple_for_test_ipv6(&tuple6, IPPROTO_TCP))
        goto failure;

    session->ipv6.remote.address = tuple6.src.addr.ipv6;
    session->ipv6.remote.l4_id = tuple6.src.l4_id;
    session->ipv6.local.address = tuple6.dst.addr.ipv6;
    session->ipv6.local.l4_id = tuple6.dst.l4_id;
    session->ipv4.remote.address = tuple4.src.addr.ipv4;
    session->ipv4.remote.l4_id = tuple4.src.l4_id;
    session->ipv4.local.address = tuple4.dst.addr.ipv4;
    session->ipv4.local.l4_id = tuple4.dst.l4_id;
    session->dying_time = 10;
    session->state = state;

    return true;

failure:
    kfree(skb);
    return false;
}


bool test_tcp_v4_init_state_handle( void )
{
    struct sk_buff *skb;
    struct session_entry session;
    bool success = true;

    // A V6 SYN packet arrives.
    if (!init_skb_and_session(&skb, &session, PACKET_TYPE_V6_SYN, V4_INIT, 10))
        return false;

    success &= assert_true(tcp_v4_init_state_handle(skb, &session), "V6 syn-result");
    success &= assert_equals_u8(ESTABLISHED, session.state, "V6 syn-state");
    success &= assert_not_equals_int(10, session.dying_time, "V6 syn-lifetime");
    kfree_skb(skb);

    // Something else arrives.
    if (!init_skb_and_session(&skb, &session, PACKET_TYPE_V6_RST, V4_INIT, 10))
        return false;

	success &= assert_true(tcp_v4_init_state_handle(skb, &session), "else-result");
	success &= assert_equals_u8(V4_INIT, session.state, "else-state");
	success &= assert_equals_int(10, session.dying_time, "else-lifetime");
	kfree_skb(skb);

    return success;
}

bool test_tcp_v6_init_state_handle( void )
{
    struct sk_buff *skb;
    struct session_entry session;
    bool success = true;

    // A V4 SYN packet arrives.
    if (!init_skb_and_session(&skb, &session, PACKET_TYPE_V4_SYN, V6_INIT, 10))
        return false;

    success &= assert_true(tcp_v6_init_state_handle(skb, &session), "V4 syn-result");
    success &= assert_equals_u8(ESTABLISHED, session.state, "V4 syn-state");
    success &= assert_not_equals_int(10, session.dying_time, "V4 syn-lifetime");
    kfree_skb(skb);

    // A V6 SYN packet arrives.
    if (!init_skb_and_session(&skb, &session, PACKET_TYPE_V6_SYN, V6_INIT, 10))
        return false;

    success &= assert_true(tcp_v6_init_state_handle(skb, &session), "V6 syn-result");
    success &= assert_equals_u8(V6_INIT, session.state, "V6 syn-state");
    success &= assert_not_equals_int(10, session.dying_time, "V6 syn-lifetime");
    kfree_skb(skb);

    // Something else arrives.
    if (!init_skb_and_session(&skb, &session, PACKET_TYPE_V6_RST, V6_INIT, 10))
        return false;

    success &= assert_true(tcp_v6_init_state_handle(skb, &session), "else-result");
    success &= assert_equals_u8(V6_INIT, session.state, "else-state");
    success &= assert_equals_int(10, session.dying_time, "else-lifetime");
    kfree_skb(skb);

    return success;
}

bool test_tcp_established_state_handle( void )
{
    struct sk_buff *skb;
    struct session_entry session;
    bool success = true;

    // A V4 FIN packet arrives.
    if (!init_skb_and_session(&skb, &session, PACKET_TYPE_V4_FIN, ESTABLISHED, 10))
        return false;

    success &= assert_true(tcp_established_state_handle( skb, &session ), "V4 fin-result");
    success &= assert_equals_u8(V4_FIN_RCV, session.state, "V4 fin-state");
    success &= assert_equals_int(10, session.dying_time, "V4 fin-lifetime");
    kfree_skb(skb);

    // A V6 FIN packet arrives.
    if (!init_skb_and_session(&skb, &session, PACKET_TYPE_V6_FIN, ESTABLISHED, 10))
        return false;

    success &= assert_true(tcp_established_state_handle( skb, &session ), "V6 fin-result");
    success &= assert_equals_u8(V6_FIN_RCV, session.state, "V6 fin-state");
    success &= assert_equals_int(10, session.dying_time, "V6 fin-lifetime");
    kfree_skb(skb);

    // A V4 RST packet arrives.
    if (!init_skb_and_session(&skb, &session, PACKET_TYPE_V4_RST, ESTABLISHED, 10))
        return false;

    success &= assert_true(tcp_established_state_handle( skb, &session ), "V4 rst-result");
    success &= assert_equals_u8(TRANS, session.state, "V4 rst-state");
    success &= assert_not_equals_int(10, session.dying_time, "V4 rst-lifetime");
    kfree_skb(skb);

    // A V6 RST packet arrives.
    if (!init_skb_and_session(&skb, &session, PACKET_TYPE_V6_RST, ESTABLISHED, 10))
        return false;

    success &= assert_true(tcp_established_state_handle( skb, &session ), "V6 rst-result");
    success &= assert_equals_u8(TRANS, session.state, "V6 rst-state");
    success &= assert_not_equals_int(10, session.dying_time, "V6 rst-lifetime");
    kfree_skb(skb);

    // Something else arrives.
    if (!init_skb_and_session(&skb, &session, PACKET_TYPE_V4_SYN, ESTABLISHED, 10))
        return false;

    success &= assert_true(tcp_established_state_handle(skb, &session), "else-result");
    success &= assert_equals_u8(ESTABLISHED, session.state, "else-state");
    success &= assert_not_equals_int(10, session.dying_time, "else-lifetime");
    kfree_skb(skb);

    return success;
}

bool test_tcp_v4_fin_rcv_state_handle( void )
{
    struct sk_buff *skb;
    struct session_entry session;
    bool success = true;

    // A V6 FIN packet arrives.
    if (!init_skb_and_session(&skb, &session, PACKET_TYPE_V6_FIN, V4_FIN_RCV, 10))
        return false;

    success &= assert_true(tcp_v4_fin_rcv_state_handle( skb, &session ), "V6 fin-result");
    success &= assert_equals_u8(V4_FIN_V6_FIN_RCV, session.state, "V6 fin-state");
    success &= assert_not_equals_int(10, session.dying_time, "V6 fin-lifetime");
    kfree_skb(skb);

    // Something else arrives.
    if (!init_skb_and_session(&skb, &session, PACKET_TYPE_V4_SYN, V4_FIN_RCV, 10))
        return false;

    success &= assert_true(tcp_v4_fin_rcv_state_handle(skb, &session), "else-result");
    success &= assert_equals_u8(V4_FIN_RCV, session.state, "else-state");
    success &= assert_not_equals_int(10, session.dying_time, "else-lifetime");
    kfree_skb(skb);

    return success;
}

bool test_tcp_v6_fin_rcv_state_handle( void )
{
    struct sk_buff *skb;
    struct session_entry session;
    bool success = true;

    // A V4 FIN packet arrives.
    if (!init_skb_and_session(&skb, &session, PACKET_TYPE_V4_FIN, V6_FIN_RCV, 10))
        return false;

    success &= assert_true(tcp_v6_fin_rcv_state_handle( skb, &session ), "V4 fin-result");
    success &= assert_equals_u8(V4_FIN_V6_FIN_RCV, session.state, "V4 fin-state");
    success &= assert_not_equals_int(10, session.dying_time, "V4 fin-lifetime");
    kfree_skb(skb);

    // Something else arrives.
    if (!init_skb_and_session(&skb, &session, PACKET_TYPE_V4_SYN, V6_FIN_RCV, 10))
        return false;

    success &= assert_true(tcp_v6_fin_rcv_state_handle(skb, &session), "else-result");
    success &= assert_equals_u8(V6_FIN_RCV, session.state, "else-state");
    success &= assert_not_equals_int(10, session.dying_time, "else-lifetime");
    kfree_skb(skb);

    return success;
}

bool test_tcp_trans_state_handle( void )
{
    struct sk_buff *skb;
    struct session_entry session;
    bool success = true;

    // A V4 RST packet arrives.
    if (!init_skb_and_session(&skb, &session, PACKET_TYPE_V4_RST, TRANS, 10))
        return false;

    success &= assert_true(tcp_trans_state_handle( skb, &session ), "V4 rst-result");
    success &= assert_equals_u8(TRANS, session.state, "V4 rst-state");
    success &= assert_equals_int(10, session.dying_time, "V4 rst-lifetime");
    kfree_skb(skb);

    // A V6 RST packet arrives.
    if (!init_skb_and_session(&skb, &session, PACKET_TYPE_V6_RST, TRANS, 10))
        return false;

    success &= assert_true(tcp_trans_state_handle( skb, &session ), "V6 rst-result");
    success &= assert_equals_u8(TRANS, session.state, "V6 rst-state");
    success &= assert_equals_int(10, session.dying_time, "V6 rst-lifetime");
    kfree_skb(skb);

    // Something else arrives.
    if (!init_skb_and_session(&skb, &session, PACKET_TYPE_V4_SYN, TRANS, 10))
        return false;

    success &= assert_true(tcp_trans_state_handle(skb, &session), "else-result");
    success &= assert_equals_u8(ESTABLISHED, session.state, "else-state");
    success &= assert_not_equals_int(10, session.dying_time, "else-lifetime");
    kfree_skb(skb);

    return success;
}

/**
 * We'll just chain a handful of packets, since testing every combination would take forever and
 * the inner functions were tested above anyway.
 * The chain is V6 SYN --> V4 SYN --> V6 RST --> V6 SYN.
 */
bool test_tcp( void )
{
    struct sk_buff *skb;
    struct session_entry *session;
    struct tuple tuple;
    bool success = true;

    // V6 SYN
    skb = init_packet_type_for_test( PACKET_TYPE_V6_SYN );
    if (!skb)
        goto failure;
    if (!init_tuple_for_test_ipv6( &tuple, IPPROTO_TCP ))
        goto failure;
    success &= assert_equals_int(NF_ACCEPT, tcp( skb, &tuple ), "Closed-result");
    session = session_get(&tuple);
    success &= assert_not_null(session, "Closed-session");
    if (session)
        success &= assert_equals_u8(V6_INIT, session->state, "Closed-state");
    kfree_skb(skb);

    // V4 SYN
    skb = init_packet_type_for_test( PACKET_TYPE_V4_SYN );
    if (!skb)
        goto failure;
    if (!init_tuple_for_test_ipv4( &tuple, IPPROTO_TCP ))
        goto failure;
    success &= assert_equals_int(NF_ACCEPT, tcp( skb, &tuple ), "V6 init-result");
    session = session_get(&tuple);
    success &= assert_not_null(session, "V6 init-session");
    if (session)
        success &= assert_equals_u8(ESTABLISHED, session->state, "V6 init-state");
    kfree_skb(skb);

    // V6 RST
    skb = init_packet_type_for_test( PACKET_TYPE_V6_RST );
    if (!skb)
        goto failure;
    if (!init_tuple_for_test_ipv6( &tuple, IPPROTO_TCP ))
        goto failure;
    success &= assert_equals_int(NF_ACCEPT, tcp( skb, &tuple ), "Established-result");
    session = session_get(&tuple);
    success &= assert_not_null(session, "Established-session");
    if (session)
        success &= assert_equals_u8(TRANS, session->state, "Established-state");
    kfree_skb(skb);

    // V6 SYN
    skb = init_packet_type_for_test( PACKET_TYPE_V6_SYN );
    if (!skb)
        goto failure;
    if (!init_tuple_for_test_ipv6( &tuple, IPPROTO_TCP ))
        goto failure;
    success &= assert_equals_int(NF_ACCEPT, tcp( skb, &tuple ), "Trans-result");
    session = session_get(&tuple);
    success &= assert_not_null(session, "Trans-session");
    if (session)
        success &= assert_equals_u8(ESTABLISHED, session->state, "Trans-state");
    kfree_skb(skb);

    return success;

failure:
    kfree_skb(skb);
    return false;
}

bool init_full(void)
{
	bool success = true;

	success &= pool6_init();
	success &= pool4_init(true);
	success &= bib_init();
	success &= session_init();
	success &= filtering_init();

	return success;
}

void end_full(void)
{
	filtering_destroy();
	session_destroy();
	bib_destroy();
	pool4_destroy();
	pool6_destroy();
}

int __init filtering_test_init(void)
{
    START_TESTS("Filtering and Updating");
    
    log_debug("\n\n\n");
    log_debug("\n\nNAT64 %s TEST module inserted!", "filtering_test");

    // Initialize the NAT configuration for the tests.
    if ( !config_init() )
		return -EINVAL;

    /*      UDP & ICMP      */
    CALL_TEST(test_transport_address_ipv4(), "test_transport_address_ipv4");
    CALL_TEST(test_transport_address_ipv6(), "test_transport_address_ipv6");
    CALL_TEST(test_extract_ipv4_from_ipv6(), "test_extract_ipv4_from_ipv6");
    CALL_TEST(test_embed_ipv4_in_ipv6(), "test_embed_ipv4_in_ipv6");
    CALL_TEST(test_allocate_ipv4_transport_address(), "test_allocate_ipv4_transport_address");
    CALL_TEST(test_allocate_ipv4_transport_address_digger(), "test_allocate_ipv4_transport_address_digger");
    INIT_CALL_END(init_full(), test_ipv6_udp(), end_full(), "test_ipv6_udp");
    INIT_CALL_END(init_full(), test_ipv4_udp(), end_full(), "test_ipv4_udp");
    INIT_CALL_END(init_full(), test_ipv6_icmp6(), end_full(), "test_ipv6_icmp6");
    INIT_CALL_END(init_full(), test_ipv4_icmp4(), end_full(), "test_ipv4_icmp4");
    //~ CALL_TEST(test_send_icmp_error_message(), "test_send_icmp_error_message"); // Not implemented yet!
    INIT_CALL_END(init_full(), test_filtering_and_updating(), end_full(), "test_filtering_and_updating");

    /*      TCP      */
    CALL_TEST(test_packet_is_ipv4(), "test_packet_is_ipv4");
    CALL_TEST(test_packet_is_ipv6(), "test_packet_is_ipv6");
    CALL_TEST(test_packet_is_v4_syn(), "test_packet_is_v4_syn");
    CALL_TEST(test_packet_is_v6_syn(), "test_packet_is_v6_syn");
    CALL_TEST(test_packet_is_v4_fin(), "test_packet_is_v4_fin");
    CALL_TEST(test_packet_is_v6_fin(), "test_packet_is_v6_fin");
    CALL_TEST(test_packet_is_v4_rst(), "test_packet_is_v4_rst");
    CALL_TEST(test_packet_is_v6_rst(), "test_packet_is_v6_rst");
    CALL_TEST(test_send_probe_packet(), "test_send_probe_packet");
    INIT_CALL_END(init_full(), test_tcp_closed_state_handle_6(), end_full(), "test_tcp_closed_state_handle_6");
    INIT_CALL_END(init_full(), test_tcp_closed_state_handle_4(), end_full(), "test_tcp_closed_state_handle_4");
    CALL_TEST(test_tcp_v4_init_state_handle(), "test_tcp_v4_init_state_handle");
    CALL_TEST(test_tcp_v6_init_state_handle(), "test_tcp_v6_init_state_handle");
    CALL_TEST(test_tcp_established_state_handle(), "test_tcp_established_state_handle");
    CALL_TEST(test_tcp_v4_fin_rcv_state_handle(), "test_tcp_v4_fin_rcv_state_handle");
    CALL_TEST(test_tcp_v6_fin_rcv_state_handle(), "test_tcp_v6_fin_rcv_state_handle");
    CALL_TEST(test_tcp_trans_state_handle(), "test_tcp_trans_state_handle");
    INIT_CALL_END(init_full(), test_tcp(), end_full(), "test_tcp");

	config_destroy();
    /* A non 0 return means a test failed; module can't be loaded. */
    END_TESTS;
}

void __exit filtering_test_exit(void)
{
    log_debug("NAT64 %s TEST module removed!\n\n\n", "filtering_test");
}

module_init(filtering_test_init);
module_exit(filtering_test_exit);
