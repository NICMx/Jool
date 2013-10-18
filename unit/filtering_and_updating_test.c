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
MODULE_AUTHOR("Roberto Aceves <r.aceves@itesm.mx>");
MODULE_AUTHOR("Alberto Leiva <aleiva@nic.mx>");
MODULE_DESCRIPTION("Unitary tests for the Filtering\'s part of NAT64");
MODULE_ALIAS("nat64_test_filtering");

#include "nat64/comm/str_utils.h"
#include "nat64/mod/packet_db.h"
#include "nat64/unit/types.h"
#include "nat64/unit/unit_test.h"
#include "nat64/unit/skb_generator.h"
#include "filtering_and_updating.c"



static noinline bool str_to_addr6_verbose(const char *str, struct in6_addr *addr)
{
	if (str_to_addr6(str, addr) != 0)
	{
		log_warning("Cannot parse '%s' as a valid IPv6 address", str);
		return false;
	}
	return true;
}
static noinline bool str_to_addr4_verbose(const char *str, struct in_addr *addr)
{
	if (str_to_addr4(str, addr) != 0)
	{
		log_warning("Cannot parse '%s' as a valid IPv4 address", str);
		return false;
	}
	return true;
}

#define IPV6_INJECT_BIB_ENTRY_SRC_ADDR  "2001:db8:c0ca:1::1"
#define IPV6_INJECT_BIB_ENTRY_SRC_PORT  1080
#define IPV4_INJECT_BIB_ENTRY_DST_ADDR  "192.168.2.1"
#define IPV4_INJECT_BIB_ENTRY_DST_PORT  1082
#define INIT_TUPLE_ICMP_ID              10
static noinline bool inject_bib_entry( u_int8_t l4protocol )
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

    if ( l4protocol == L4PROTO_ICMP )
    {
        transport_address_ipv4( addr4, INIT_TUPLE_ICMP_ID, &ta_ipv4 );
        transport_address_ipv6( addr6, INIT_TUPLE_ICMP_ID, &ta_ipv6 );
    }
    else
    {
        transport_address_ipv4( addr4, IPV4_INJECT_BIB_ENTRY_DST_PORT, &ta_ipv4 );
        transport_address_ipv6( addr6, IPV6_INJECT_BIB_ENTRY_SRC_PORT, &ta_ipv6 );
    }

    bib_e = bib_create( &ta_ipv4, &ta_ipv6, false);
    if (!bib_e)
    {
    	log_warning("Could not allocate the BIB entry.");
    	return false;
    }
    
    if (bib_add( bib_e, l4protocol ) != 0)
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
static noinline bool init_session_entry( l4_protocol l4_proto, struct session_entry *se )
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

    se->ipv6.remote.address = src6; /* X' */
    se->ipv6.remote.l4_id = IPV6_INIT_SESSION_ENTRY_SRC_PORT; /* x */
    se->ipv6.local.address = dst6; /* Y' */
    se->ipv6.local.l4_id = IPV6_INIT_SESSION_ENTRY_DST_PORT; /* y */
    se->ipv4.local.address = src4; /* (T, t) */
    se->ipv4.local.l4_id = IPV4_INIT_SESSION_ENTRY_SRC_PORT; /* (T, t) */
    se->ipv4.remote.address = dst4; /* (Z, z) or (Z(Y’),y) */
    se->ipv4.remote.l4_id = IPV4_INIT_SESSION_ENTRY_DST_PORT; /* (Z, z) or (Z(Y’),y) */

    se->dying_time = 0;
    se->bib = NULL;
    INIT_LIST_HEAD(&se->entries_from_bib);
    INIT_LIST_HEAD(&se->expiration_node);
    se->l4_proto = l4_proto;
    se->state = CLOSED;

    return true;
}



#define IPV4_TRANSPORT_ADDR     "192.168.1.4"
#define IPV4_TRANSPORT_PORT     1081
static noinline bool test_transport_address_ipv4( void )
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
static noinline bool test_transport_address_ipv6( void )
{
    struct in6_addr addr6;
    struct ipv6_tuple_address ta;
    bool success = true;

    /* Build an IPv6 transport address from address & port */
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
static noinline bool test_extract_ipv4_from_ipv6( void )
{
    struct in6_addr addr6;
    struct in_addr extracted4;
    struct in_addr correct4;
    bool success = true;

    if (pool6_init(NULL, 0) != 0)
    	return false;
    success &= str_to_addr6_verbose(IPV6_EXTRACT_ADDR, &addr6);
    success &= str_to_addr4_verbose(IPV4_EXTRACTED_ADDR, &correct4);

    success &= assert_true(extract_ipv4(&addr6, &extracted4),
        "Check that an IPv4 address can be extracted from an IPv6 address.");
    success &= assert_equals_ipv4(&extracted4, &correct4, 
        "Assert that the extraction of the IPv4 address was correct.");

	pool6_destroy();
	return success;
}


#define IPV6_EMBEDDED_ADDR      "64:ff9b::192.168.2.3"
#define IPV4_EMBEDDABLE_ADDR    "192.168.2.3"
static noinline bool test_embed_ipv4_in_ipv6( void )
{
    struct in_addr embeddable4;
    struct in6_addr embed6;
    struct in6_addr embedded6;
    bool success = true;

    if (pool6_init(NULL, 9) != 0)
    	return false;
    success &= str_to_addr4_verbose(IPV4_EMBEDDABLE_ADDR, &embeddable4);
    success &= str_to_addr6_verbose(IPV6_EMBEDDED_ADDR, &embedded6);
    
    success &= assert_true(append_ipv4( &embeddable4, &embed6 ) , 
        "Check that we can embed an IPv4 address inside of an IPv6 address correctly.");
    success &= assert_equals_ipv6( &embed6 , &embedded6 , 
        "Verify that the IPv4 was embedded into a IPv6 address is correct.");
    
    return success;
}


#define IPV4_ALLOCATED_ADDR     "192.168.2.1"
static noinline bool test_allocate_ipv4_transport_address( void )
{
    struct tuple tuple;
    struct ipv4_tuple_address tuple_addr;
    struct in_addr expected_addr;
    bool success = true;
    int error;

    success &= str_to_addr4_verbose(IPV4_ALLOCATED_ADDR, &expected_addr);
    success &= inject_bib_entry( L4PROTO_ICMP );
    success &= inject_bib_entry( L4PROTO_TCP );
    success &= inject_bib_entry( L4PROTO_UDP );
    if (!success)
    	return false;

    error = init_ipv6_tuple(&tuple, "1::2", 1212, "3::4", 3434, L4PROTO_ICMP);
	if (error)
		return false;
	success &= assert_true(allocate_ipv4_transport_address(&tuple, &tuple_addr),
		"Function result for ICMP");
	success &= assert_equals_ipv4(&expected_addr , &tuple_addr.address, "IPv4 address for ICMP");

	error = init_ipv6_tuple(&tuple, "1::2", 1212, "3::4", 3434, L4PROTO_TCP);
	if (error)
		return false;
	success &= assert_true(allocate_ipv4_transport_address(&tuple, &tuple_addr),
		"Function result for TCP");
	success &= assert_equals_ipv4(&expected_addr , &tuple_addr.address, "IPv4 address for TCP");
	success &= assert_true(tuple_addr.l4_id > 1023, "Port range for TCP");

	error = init_ipv6_tuple(&tuple, "1::2", 1212, "3::4", 3434, L4PROTO_UDP);
	if (error)
		return false;
	success &= assert_true(allocate_ipv4_transport_address(&tuple, &tuple_addr),
		"Function result for UDP");
	success &= assert_equals_ipv4(&expected_addr , &tuple_addr.address, "IPv4 address for UDP");
	success &= assert_true(tuple_addr.l4_id % 2 == 0, "Port parity for UDP");
	success &= assert_true( tuple_addr.l4_id > 1023, "Port range for UDP");

    return success;
}


#define IPV4_ALLOCATED_PORT_DIGGER  1024
static noinline bool test_allocate_ipv4_transport_address_digger( void )
{
    struct in_addr expected_addr;
    struct tuple tuple;
    struct ipv4_tuple_address new_ipv4_transport_address;
    bool success = true;
    int error;

    success &= inject_bib_entry( L4PROTO_ICMP );
    success &= inject_bib_entry( L4PROTO_TCP );
    error = init_ipv6_tuple(&tuple, "1::2", 1212, "3::4", 3434, L4PROTO_UDP);
	if (error)
		return false;
    success &= str_to_addr4_verbose(IPV4_ALLOCATED_ADDR, &expected_addr);
    if (!success)
    	return false;
    
    success &= assert_true( allocate_ipv4_transport_address_digger(&tuple, L4PROTO_UDP, &new_ipv4_transport_address),
        "Check that we can allocate a brand new IPv4 transport address for UDP.");
    success &= assert_equals_ipv4( &new_ipv4_transport_address.address, &expected_addr,
    		"Check that the allocated IPv4 address is correct for UDP.");
    success &= assert_true( new_ipv4_transport_address.l4_id % 2 == 0,
        "Check that the allocated IPv4 port is even.");
    success &= assert_true( new_ipv4_transport_address.l4_id > 1023,
		"Check that the allocated IPv4 port is in the upper range.");

    return success;
}


static noinline bool test_ipv6_udp( void )
{
    struct packet *pkt;
    struct tuple tuple;
    struct ipv6_pair pair6;
    struct sk_buff *skb;
    bool success = true;
    int error;

    /* Prepare */
	error = init_pair6(&pair6, "1::2", 1212, "3::4", 3434);
	if (error)
		return false;
    error = init_ipv6_tuple_from_pair(&tuple, &pair6, L4PROTO_UDP);
	if (error)
			return false;
    error = create_skb_ipv6_udp(&pair6, &skb, 100);
	if (error)
		return false;
	success &= assert_equals_int(VER_CONTINUE, pkt_from_skb(skb, &pkt), "Get pkt_from_skb");

	/* Evaluate */
    success &= assert_equals_int(VER_CONTINUE, ipv6_udp( pkt->first_fragment, &tuple ),
		"See if we can process correctly an IPv6 UDP packet.");
    pkt_kfree(pkt, true);

    return success;
}

static noinline bool test_ipv4_udp( void )
{
    struct packet *pkt;
    struct tuple tuple;
    struct sk_buff* skb;
    struct ipv4_pair pair4;
    struct ipv6_pair pair6;
    bool success = true;
    int error;

    /* Prepare */
	error = init_pair4(&pair4, "8.7.6.5", 8765, "5.6.7.8", 5678);
	if (error)
		return false;
    error = init_ipv4_tuple_from_pair(&tuple, &pair4, L4PROTO_UDP);
	if (error)
		return false;
	error = create_skb_ipv4_udp(&pair4, &skb, 100);
	if (error)
		return false;
	success &= assert_equals_int(VER_CONTINUE, pkt_from_skb(skb, &pkt), "Get pkt_from_skb IPv4 UDP");

	/* Evaluate */
    success &= assert_equals_int(VER_DROP, ipv4_udp( pkt->first_fragment, &tuple ),
		"See if we discard an IPv4 UDP packet, which tries to start a communication.");
    pkt_kfree(pkt, true);

    /* Prepare */
	error = init_pair6(&pair6, "1::2", 1212, "3::4", 3434);
	if (error)
		return false;
	error = init_ipv6_tuple_from_pair(&tuple, &pair6, L4PROTO_UDP);
	if (error)
			return false;
	error = create_skb_ipv6_udp(&pair6, &skb, 100);
	if (error)
		return false;
	success &= assert_equals_int(VER_CONTINUE, pkt_from_skb(skb, &pkt), "Get pkt_from_skb");

	/* Evaluate */
    success &= assert_equals_int(VER_CONTINUE, ipv6_udp( pkt->first_fragment, &tuple ),
		"See if we can process correctly an IPv6 UDP packet, (in test_ipv4_udp)");
    pkt_kfree(pkt, true);

    /*
     * TODO (test) The following code no longer works, because the BIB stored in the previous step
     * now uses a random port. These tests are missing lots of asserts anyway, so I'll fix both
     * issues at the same time later.
     */
    /*
    if (!init_tuple_for_test_ipv4( &tuple , protocol  ))
    	return false;
    skb = init_skb_for_test( &tuple, protocol );
    if (!skb)
		return false;
    success &= assert_equals_int(VER_CONTINUE, ipv4_udp( skb, &tuple ),
		"See if we can process correctly an expected IPv4 UDP packet.");
    kfree_skb(skb);
    */

    return success;
}

static noinline bool test_ipv6_icmp6( void )
{
    struct packet *pkt;
    struct tuple tuple;
    struct sk_buff *skb;
    struct ipv6_pair pair6;
    bool success = true;
    int error;

    /* Prepare */
	error = init_pair6(&pair6, "1::2", 1212, "3::4", 3434);
	if (error)
		return false;
	error = init_ipv6_tuple_from_pair(&tuple, &pair6, L4PROTO_ICMP);
	if (error)
			return false;
	error = create_skb_ipv6_icmp_info(&pair6, &skb, 100);
	if (error)
		return false;
	success &= assert_equals_int(VER_CONTINUE, pkt_from_skb(skb, &pkt), "Get pkt_from_skb IPv6 ICMP");

	/* Evaluate */
    success &= assert_equals_int(VER_CONTINUE, ipv6_icmp6(pkt->first_fragment, &tuple),
		"See if we can process correctly an IPv6 ICMP packet.");
    pkt_kfree(pkt, true);
      
    return success;
}

static noinline bool test_ipv4_icmp4( void )
{
	struct packet *pkt;
	struct ipv6_pair pair6;
	struct ipv4_pair pair4;
    struct tuple tuple;
    struct sk_buff* skb = NULL;
    bool success = true;
    int error;

    /*
     * Discard an ICMP coming from IPv4 machine.
     */

    /* Prepare */
	error = init_pair4(&pair4, "8.7.6.5", 8765, "5.6.7.8", 5678);
	if (error)
		return false;
	error = init_ipv4_tuple_from_pair(&tuple, &pair4, L4PROTO_ICMP);
	if (error)
		return false;
	error = create_skb_ipv4_udp(&pair4, &skb, 100);
	if (error)
		return false;
	success &= assert_equals_int(VER_CONTINUE, pkt_from_skb(skb, &pkt), "Get pkt_from_skb IPv4 UDP");

	/* Evaluate */
	success &= assert_equals_int(VER_DROP, ipv4_icmp4(pkt->first_fragment, &tuple ),
			"See if we discard an IPv4 ICMP packet, which tries to start a communication.");
	pkt_kfree(pkt, true);

	/*
	 * Accept & process an ICMP coming from IPv6 machine.
	 */

	/* Prepare */
	error = init_pair6(&pair6, "1::2", 1212, "3::4", 3434);
	if (error)
		return false;
	error = init_ipv6_tuple_from_pair(&tuple, &pair6, L4PROTO_ICMP);
	if (error)
			return false;
	error = create_skb_ipv6_udp(&pair6, &skb, 100);
	if (error)
		return false;
	success &= assert_equals_int(VER_CONTINUE, pkt_from_skb(skb, &pkt), "Get pkt_from_skb");

	/* Evaluate */
	success &= assert_equals_int(VER_CONTINUE, ipv6_icmp6(pkt->first_fragment, &tuple ),
			"See if we can process correctly an IPv6 ICMP packet.");
	pkt_kfree(pkt, true);

    /* TODO (test) see test_ipv4_udp(). */
    /*
    protocol = L4PROTO_ICMP;
    if (!init_tuple_for_test_ipv4( &tuple , protocol ))
    	return false;
    skb = init_skb_for_test( &tuple, protocol );
    if (!skb)
		return false;
    success &= assert_not_null(skb, "init_skb_for_test");
    success &= assert_equals_int(VER_CONTINUE, ipv4_icmp4( skb, &tuple ),
		"See if we can process correctly an expected IPv4 ICMP packet.");
    kfree_skb(skb);
    */

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

    protocol = L4PROTO_ICMP;

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
static noinline bool test_filtering_and_updating( void )
{
    struct packet *pkt;
    struct tuple tuple;
    struct sk_buff *skb;
    struct ipv6_pair pair6;
    struct ipv4_pair pair4;
    bool success = true;
    int error;

    log_debug(" >>> Errores de ICMP no deben afectar las tablas ");

    /* Prepare */
	error = init_pair4(&pair4, "8.7.6.5", 8765, "5.6.7.8", 5678);
	if (error)
		return false;
	error = init_ipv4_tuple_from_pair(&tuple, &pair4, L4PROTO_ICMP);
	if (error)
		return false;
	error = create_skb_ipv4_icmp_error(&pair4, &skb, 100);
	if (error)
		return false;
	success &= assert_equals_int(VER_CONTINUE, pkt_from_skb(skb, &pkt), "Get pkt_from_skb");

	/* Evaluate */
    icmp_hdr(skb)->type = ICMP_DEST_UNREACH; /* Error packet */
	success &= assert_equals_int(VER_CONTINUE,  filtering_and_updating(pkt, &tuple),
		"See if we can forward an IPv4 ICMP packet.");
	pkt_kfree(pkt, true);


    log_debug(" >>> Get rid of hairpinning loop ");

    /* Prepare */
	error = init_pair6(&pair6, "64:ff9b::1:2", 1212, "64:ff9b::3:4", 3434);
	if (error)
		return false;
	error = init_ipv6_tuple_from_pair(&tuple, &pair6, L4PROTO_UDP);
	if (error)
			return false;
	error = create_skb_ipv6_udp(&pair6, &skb, 100);
	if (error)
		return false;
	success &= assert_equals_int(VER_CONTINUE, pkt_from_skb(skb, &pkt), "Get pkt_from_skb");

	/* Evaluate */
    success &= assert_equals_int(VER_DROP,  filtering_and_updating(pkt, &tuple),
		"See if we can get rid of hairpinning loop in IPv6.");
	pkt_kfree(pkt, true);


    log_debug(" >>> Get rid of unwanted packets ");

    /* Prepare */
	error = init_pair6(&pair6, "1::2", 1212, INIT_TUPLE_IPV6_HAIR_LOOP_DST_ADDR, 3434);
	if (error)
		return false;
	error = init_ipv6_tuple_from_pair(&tuple, &pair6, L4PROTO_UDP);
	if (error)
			return false;
	error = create_skb_ipv6_udp(&pair6, &skb, 100);
	if (error)
		return false;
	success &= assert_equals_int(VER_CONTINUE, pkt_from_skb(skb, &pkt), "Get pkt_from_skb");

	/* Evaluate */
	success &= assert_equals_int(VER_DROP,  filtering_and_updating(pkt, &tuple),
		"See if we can get rid of unwanted packets in IPv6.");
	pkt_kfree(pkt, true);


    log_debug(" >>> Get rid of un-expected packets, destined to an address not in pool");

    /* Prepare */
	error = init_pair4(&pair4, INIT_TUPLE_IPV4_NOT_POOL_DST_ADDR, 8765, "5.6.7.8", 5678);
	if (error)
		return false;
	error = init_ipv4_tuple_from_pair(&tuple, &pair4, L4PROTO_UDP);
	if (error)
		return false;
	error = create_skb_ipv4_udp(&pair4, &skb, 100);
	if (error)
		return false;
	success &= assert_equals_int(VER_CONTINUE, pkt_from_skb(skb, &pkt), "Get pkt_from_skb");

	/* Evaluate */
    success &= assert_equals_int(VER_DROP,  filtering_and_updating(pkt, &tuple),
		"See if we can get rid of packet destined to an address not in pool.");
	pkt_kfree(pkt, true);


    log_debug(" >>> IPv4 incoming packet --> reject");

    /* Prepare */
	error = init_pair4(&pair4, "8.7.6.5", 8765, "5.6.7.8", 5678);
	if (error)
		return false;
	error = init_ipv4_tuple_from_pair(&tuple, &pair4, L4PROTO_UDP);
	if (error)
		return false;
	error = create_skb_ipv4_udp(&pair4, &skb, 100);
	if (error)
		return false;
	success &= assert_equals_int(VER_CONTINUE, pkt_from_skb(skb, &pkt), "Get pkt_from_skb");

	/* Evaluate */
    success &= assert_equals_int(VER_DROP,  filtering_and_updating(pkt, &tuple),
		"See if we can do reject an incoming IPv4 UDP packet.");
	pkt_kfree(pkt, true);


    log_debug(" >>> IPv6 incoming packet --> accept");

    /* Prepare */
	error = init_pair6(&pair6, "1::2", 1212, "64:ff9b::3:4", 3434);
	if (error)
		return false;
	error = init_ipv6_tuple_from_pair(&tuple, &pair6, L4PROTO_UDP);
	if (error)
			return false;
	error = create_skb_ipv6_udp(&pair6, &skb, 100);
	if (error)
		return false;
	success &= assert_equals_int(VER_CONTINUE, pkt_from_skb(skb, &pkt), "Get pkt_from_skb");

	/* Evaluate */
    success &= assert_equals_int(VER_CONTINUE, filtering_and_updating(pkt, &tuple),
    		"See if we can do filtering and updating on an incoming IPv6 UDP packet.");
	pkt_kfree(pkt, true);


    /* TODO (test) see test_ipv4_udp(). */
    /*
    log_debug(" >>> IPv4 incoming packet --> accept");
    success &= init_tuple_for_test_ipv4( &tuple , protocol );
    skb = init_skb_for_test( &tuple, protocol );
    success &= assert_not_null(skb, "init_skb_for_test");
    success &= assert_equals_int(VER_CONTINUE,  filtering_and_updating( skb, &tuple),
			"See if we can do filtering and updating on an incoming IPv4 UDP packet.");
    kfree_skb(skb);
    */

    return success;
}


enum test_packet_type {
	PACKET_TYPE_DEFAULT=0,
	PACKET_TYPE_V6_SYN=1, PACKET_TYPE_V4_SYN,
	PACKET_TYPE_V6_RST,   PACKET_TYPE_V4_RST,
	PACKET_TYPE_V6_FIN,   PACKET_TYPE_V4_FIN
};

static noinline bool set_skb_tcp_type(struct sk_buff *skb, enum test_packet_type type)
{
    struct tcphdr *tcp_header;

    if (!skb) {
    	log_err(ERR_NULL, "Skb is NULL");
    	return false;
    }
    tcp_header = tcp_hdr(skb);

    switch (type) {
	case PACKET_TYPE_V6_SYN:
	case PACKET_TYPE_V4_SYN:
		tcp_header->syn = 1;
		break;
	case PACKET_TYPE_V6_RST:
	case PACKET_TYPE_V4_RST:
		tcp_header->rst = 1;
		break;
	case PACKET_TYPE_V6_FIN:
	case PACKET_TYPE_V4_FIN:
		tcp_header->fin = 1;
		break;
	case PACKET_TYPE_DEFAULT:
		break;
	default:
		log_debug("  set_skb_tcp_type.c: Invalid packet type: %u", type);
		return false;
    }

    return true;
}

static noinline bool test_create_packet_tcp(struct packet **pkt, enum test_packet_type type)
{
	struct sk_buff *skb;
	struct ipv6_pair pair6;
	struct ipv4_pair pair4;
	bool success = true;
	int error;

	switch (type) {
	case PACKET_TYPE_V6_SYN:
	case PACKET_TYPE_V6_RST:
	case PACKET_TYPE_V6_FIN:
		error = init_pair6(&pair6, "1::2", 1212, "3::4", 3434);
		if (error)
			return false;
		error = create_skb_ipv6_tcp(&pair6, &skb, 100);
		if (error)
			return false;
		success &= assert_equals_int(VER_CONTINUE, pkt_from_skb(skb, pkt), "Get pkt_from_skb");
		break;

	case PACKET_TYPE_V4_SYN:
	case PACKET_TYPE_V4_RST:
	case PACKET_TYPE_V4_FIN:
		error = init_pair4(&pair4, "8.7.6.5", 8765, "5.6.7.8", 5678);
		if (error)
			return false;
		error = create_skb_ipv4_tcp(&pair4, &skb, 100);
		if (error)
			return false;
		success &= assert_equals_int(VER_CONTINUE, pkt_from_skb(skb, pkt), "Get pkt_from_skb");
		break;

	case PACKET_TYPE_DEFAULT:
	default:
		log_debug("  Invalid packet type: %u", type);
		return false;
	}

	success &= set_skb_tcp_type((*pkt)->first_fragment->skb, type);

	return success;
}

static noinline bool test_packet_is_syn( void )
{
    struct packet *pkt;
    bool success = true;

	/*
	 * V4 SYN
	 */

    /* Prepare */
    success &= test_create_packet_tcp(&pkt, PACKET_TYPE_V4_SYN);

	/* Evaluate */
    success &= assert_true(packet_is_syn( pkt->first_fragment ), "Test if we detect a V4 SYN packet.");
	pkt_kfree(pkt, true);

    /*
     * V6 SYN
     */

	/* Prepare */
    success &= test_create_packet_tcp(&pkt, PACKET_TYPE_V6_SYN);

	/* Evaluate */
    success &= assert_true( packet_is_syn( pkt->first_fragment ), "Test if we detect a V6 SYN packet.");
	pkt_kfree(pkt, true);

    return success;
}

static noinline bool test_packet_is_fin( void )
{
    struct packet *pkt;
    bool success = true;

	/*
	 * V4 FIN
	 */

    /* Prepare */
    success &= test_create_packet_tcp(&pkt, PACKET_TYPE_V4_FIN);

	/* Evaluate */
    success &= assert_true(packet_is_fin( pkt->first_fragment ), "Test if we detect a V4 FIN packet.");
	pkt_kfree(pkt, true);

    /*
     * V6 FIN
     */

	/* Prepare */
	success &= test_create_packet_tcp(&pkt, PACKET_TYPE_V6_FIN);

	/* Evaluate */
    success &= assert_true( packet_is_fin( pkt->first_fragment ), "Test if we detect a V6 FIN packet.");
	pkt_kfree(pkt, true);

    return success;
}

static noinline bool test_packet_is_rst( void )
{
    struct packet *pkt;
    bool success = true;

	/*
	 * V4 RST
	 */

    /* Prepare */
    success &= test_create_packet_tcp(&pkt, PACKET_TYPE_V4_RST);

	/* Evaluate */
    success &= assert_true(packet_is_rst( pkt->first_fragment ), "Test if we detect a V4 RST packet.");
	pkt_kfree(pkt, true);

    /*
     * V6 RST
     */

	/* Prepare */
	success &= test_create_packet_tcp(&pkt, PACKET_TYPE_V6_RST);

	/* Evaluate */
    success &= assert_true( packet_is_rst( pkt->first_fragment ), "Test if we detect a V6 RST packet.");
	pkt_kfree(pkt, true);


/* TODO missing unset flags tests. */

    return success;
}


/**
 * BTW: This test doesn't assert the packet is actually sent.
 */
static noinline bool test_send_probe_packet( void )
{
    struct session_entry se;
    bool success = true;

    if (!init_session_entry( L4PROTO_TCP, &se ))
    	return false;

    log_debug("Sending a packet, catch it!");
    success &= assert_true( send_probe_packet( &se ), "Test if we can send a probe packet.");

    return success;
}

static noinline bool test_tcp_closed_state_handle_6( void )
{
    struct session_entry *session;
    struct tuple tuple;
    struct packet *pkt;
    struct ipv6_pair pair6;
    bool success = true;
    int error;

    /* Prepare */
	error = init_pair6(&pair6, "1::2", 1212, "3::4", 3434);
	if (error)
		return false;
	error = init_ipv6_tuple_from_pair(&tuple, &pair6, L4PROTO_TCP);
	if (error)
		return false;
    success &= test_create_packet_tcp(&pkt, PACKET_TYPE_V6_SYN);

	/* Evaluate */
    success &= assert_true(tcp_closed_state_handle( pkt->first_fragment, &tuple ), "V6 syn-result");

	/* Validate */
    session = session_get( &tuple );
    success &= assert_not_null(session, "V6 syn-session.");
    if (session)
    	success &= assert_equals_u8(V6_INIT, session->state, "V6 syn-state");
	pkt_kfree(pkt, true);

    return success;
}

/*
static noinline bool test_tcp_closed_state_handle_4( void )
{
    struct session_entry *session;
    struct tuple tuple;
    struct packet *pkt;
    struct ipv4_pair pair4;
    int error;
    bool success = true;

    config.drop_external_tcp = false;

    Prepare
	error = init_pair4(&pair4, "8.7.6.5", 8765, "5.6.7.8", 5678);
	if (error)
		return false;
	error = init_ipv4_tuple_from_pair(&tuple, &pair4, L4PROTO_TCP);
	if (error)
		return false;
    success &= test_create_packet_tcp(&pkt, PACKET_TYPE_V4_SYN);

	Evaluate
    success &= assert_true(tcp_closed_state_handle( pkt->first_fragment, &tuple ), "V4 syn-result");

	Validate
    session = session_get( &tuple );
    success &= assert_not_null(session, "V4 syn-session");
    if (session)
        success &= assert_equals_u8(V4_INIT, session->state, "V4 syn-state");
	pkt_kfree(pkt, true);

    return success;
}
*/

static noinline bool init_tcp_session(
		unsigned char *remote6_addr, u16 remote6_id,
		unsigned char *local6_addr, u16 local6_id,
		unsigned char *local4_addr, u16 local4_id,
		unsigned char *remote4_addr, u16 remote4_id,
		enum tcp_states state,
		struct session_entry *session)
{
	if (!str_to_addr6_verbose(remote6_addr, &session->ipv6.remote.address))
		return false;
	session->ipv6.remote.l4_id = remote6_id;
	if (!str_to_addr6_verbose(local6_addr, &session->ipv6.local.address))
		return false;
	session->ipv6.local.l4_id = local6_id;

	if (!str_to_addr4_verbose(local4_addr, &session->ipv4.local.address))
		return false;
	session->ipv4.local.l4_id = local4_id;
	if (!str_to_addr4_verbose(remote4_addr, &session->ipv4.remote.address))
		return false;
	session->ipv4.remote.l4_id = remote4_id;

	session->dying_time = jiffies - msecs_to_jiffies(100);
	session->bib = NULL;
	INIT_LIST_HEAD(&session->entries_from_bib);
	INIT_LIST_HEAD(&session->expiration_node);
	session->l4_proto = L4PROTO_TCP;
	session->state = state;

	return true;
}

/*
 * A V6 SYN packet arrives.
 */
static noinline bool test_tcp_v4_init_state_handle_v6syn( void )
{
	struct session_entry session;
	struct packet *pkt;
	bool success = true;

	/* Prepare */
	success &= init_tcp_session("1::2", 1212, "3::4", 3434, "5.6.7.8", 5678, "8.7.6.5", 8765,
			V4_INIT, &session);
	success &= test_create_packet_tcp(&pkt, PACKET_TYPE_V6_SYN);
	if (!success)
		return false;

	/* Evaluate */
	success &= assert_true(tcp_v4_init_state_handle(pkt->first_fragment, &session), "V6 syn-result");
	success &= assert_equals_u8(ESTABLISHED, session.state, "V6 syn-state");
	success &= assert_true(session.dying_time > jiffies, "V6 syn-lifetime");

	pkt_kfree(pkt, true);
	return success;
}

/*
 * Something else arrives.
 */
static noinline bool test_tcp_v4_init_state_handle_else( void )
{
	struct session_entry session;
	struct packet *pkt;
	bool success = true;

	/* Prepare */
	success &= init_tcp_session("1::2", 1212, "3::4", 3434, "5.6.7.8", 5678, "8.7.6.5", 8765,
			V4_INIT, &session);
	success &= test_create_packet_tcp(&pkt, PACKET_TYPE_V6_RST);
	if (!success)
		return false;

	/* Evaluate */
	success &= assert_true(tcp_v4_init_state_handle(pkt->first_fragment, &session), "else-result");
	success &= assert_equals_u8(V4_INIT, session.state, "else-state");
	success &= assert_true(session.dying_time < jiffies, "else-lifetime");

	pkt_kfree(pkt, true);
	return success;
}

/*
 * A V4 SYN packet arrives.
 */
static noinline bool test_tcp_v6_init_state_handle_v4syn( void )
{
	struct session_entry session;
	struct packet *pkt;
	bool success = true;

	/* Prepare */
	success &= init_tcp_session("1::2", 1212, "3::4", 3434, "5.6.7.8", 5678, "8.7.6.5", 8765,
			V6_INIT, &session);
	success &= test_create_packet_tcp(&pkt, PACKET_TYPE_V4_SYN);
	if (!success)
		return false;

	/* Evaluate */
	success &= assert_true(tcp_v6_init_state_handle(pkt->first_fragment, &session),
			"V4 syn-result");
	success &= assert_equals_u8(ESTABLISHED, session.state, "V4 syn-state");
	success &= assert_true(session.dying_time > jiffies, "V4 syn-lifetime");

	pkt_kfree(pkt, true);
	return success;
}

/*
 * A V6 SYN packet arrives.
 */
static noinline bool test_tcp_v6_init_state_handle_v6syn( void )
{
	struct session_entry session;
	struct packet *pkt;
	bool success = true;

	/* Prepare */
	success &= init_tcp_session("1::2", 1212, "3::4", 3434, "5.6.7.8", 5678, "8.7.6.5", 8765,
			V6_INIT, &session);
	success &= test_create_packet_tcp(&pkt, PACKET_TYPE_V6_SYN);
	if (!success)
		return false;

	/* Evaluate */
	success &= assert_true(tcp_v6_init_state_handle(pkt->first_fragment, &session),
			"V6 syn-result");
	success &= assert_equals_u8(V6_INIT, session.state, "V6 syn-state");
	success &= assert_true(session.dying_time > jiffies, "V6 syn-lifetime");

	pkt_kfree(pkt, true);
	return success;
}

/*
 * Something else arrives.
 */
static noinline bool test_tcp_v6_init_state_handle_else( void )
{
	struct session_entry session;
	struct packet *pkt;
	bool success = true;

	/* Prepare */
	success &= init_tcp_session("1::2", 1212, "3::4", 3434, "5.6.7.8", 5678, "8.7.6.5", 8765,
			V6_INIT, &session);
	success &= test_create_packet_tcp(&pkt, PACKET_TYPE_V6_RST);
	if (!success)
		return false;

	/* Evaluate */
	success &= assert_true(tcp_v6_init_state_handle(pkt->first_fragment, &session), "else-result");
	success &= assert_equals_u8(V6_INIT, session.state, "else-state");
	success &= assert_true(session.dying_time < jiffies, "else-lifetime");

	pkt_kfree(pkt, true);
	return success;
}
/*
 * A V4 FIN packet arrives.
 */
static noinline bool test_tcp_established_state_handle_v4fin( void )
{
	struct session_entry session;
	struct packet *pkt;
	bool success = true;

	/* Prepare */
	success &= init_tcp_session("1::2", 1212, "3::4", 3434, "5.6.7.8", 5678, "8.7.6.5", 8765,
			ESTABLISHED, &session);
	success &= test_create_packet_tcp(&pkt, PACKET_TYPE_V4_FIN);
	if (!success)
		return false;

	/* Evaluate */
	success &= assert_true(tcp_established_state_handle( pkt->first_fragment, &session ), "result");
	success &= assert_equals_u8(V4_FIN_RCV, session.state, "V4 fin-state");
	success &= assert_true(session.dying_time < jiffies, "V4 fin-lifetime");

	pkt_kfree(pkt, true);
	return success;
}

/*
 * A V6 FIN packet arrives.
 */
static noinline bool test_tcp_established_state_handle_v6fin( void )
{
	struct session_entry session;
	struct packet *pkt;
	bool success = true;

	/* Prepare */
	success &= init_tcp_session("1::2", 1212, "3::4", 3434, "5.6.7.8", 5678, "8.7.6.5", 8765,
			ESTABLISHED, &session);
	success &= test_create_packet_tcp(&pkt, PACKET_TYPE_V6_FIN);
	if (!success)
		return false;

	/* Evaluate */
	success &= assert_true(tcp_established_state_handle( pkt->first_fragment, &session ), "result");
	success &= assert_equals_u8(V6_FIN_RCV, session.state, "V6 fin-state");
	success &= assert_true(session.dying_time < jiffies, "V6 fin-lifetime");

	pkt_kfree(pkt, true);
	return success;
}

/*
 * A V4 RST packet arrives.
 */
static noinline bool test_tcp_established_state_handle_v4rst( void )
{
	struct session_entry session;
	struct packet *pkt;
	bool success = true;

	/* Prepare */
	success &= init_tcp_session("1::2", 1212, "3::4", 3434, "5.6.7.8", 5678, "8.7.6.5", 8765,
				ESTABLISHED, &session);
	success &= test_create_packet_tcp(&pkt, PACKET_TYPE_V4_RST);
	if (!success)
		return false;

	/* Evaluate */
	success &= assert_true(tcp_established_state_handle( pkt->first_fragment, &session ), "result");
	success &= assert_equals_u8(TRANS, session.state, "V4 rst-state");
	success &= assert_true(session.dying_time > jiffies, "V4 rst-lifetime");

	pkt_kfree(pkt, true);
	return success;
}

/*
 * A V6 RST packet arrives.
 */
static noinline bool test_tcp_established_state_handle_v6rst( void )
{
	struct session_entry session;
	struct packet *pkt;
	bool success = true;

	/* Prepare */
	success &= init_tcp_session("1::2", 1212, "3::4", 3434, "5.6.7.8", 5678, "8.7.6.5", 8765,
			ESTABLISHED, &session);
	success &= test_create_packet_tcp(&pkt, PACKET_TYPE_V6_RST);
	if (!success)
		return false;

	/* Evaluate */
	success &= assert_true(tcp_established_state_handle( pkt->first_fragment, &session ), "result");
	success &= assert_equals_u8(TRANS, session.state, "V6 rst-state");
	success &= assert_true(session.dying_time > jiffies, "V6 rst-lifetime");

	pkt_kfree(pkt, true);
	return success;
}

/*
 * Something else arrives.
 */
static noinline bool test_tcp_established_state_handle_else( void )
{
	struct session_entry session;
	struct packet *pkt;
	bool success = true;

	/* Prepare */
	success &= init_tcp_session("1::2", 1212, "3::4", 3434, "5.6.7.8", 5678, "8.7.6.5", 8765,
			ESTABLISHED, &session);
	success &= test_create_packet_tcp(&pkt, PACKET_TYPE_V4_SYN);
	if (!success)
		return false;

	/* Evaluate */
	success &= assert_true(tcp_established_state_handle(pkt->first_fragment, &session), "result");
	success &= assert_equals_u8(ESTABLISHED, session.state, "else-state");
	success &= assert_true(session.dying_time > jiffies, "else-lifetime");

	pkt_kfree(pkt, true);
	return success;
}

/*
 * A V6 FIN packet arrives.
 */
static noinline bool test_tcp_v4_fin_rcv_state_handle_v6fin( void )
{
	struct session_entry session;
	struct packet *pkt;
	bool success = true;

	/* Prepare */
	success &= init_tcp_session("1::2", 1212, "3::4", 3434, "5.6.7.8", 5678, "8.7.6.5", 8765,
			V4_FIN_RCV, &session);
	success &= test_create_packet_tcp(&pkt, PACKET_TYPE_V6_FIN);
	if (!success)
		return false;

	/* Evaluate */
	success &= assert_true(tcp_v4_fin_rcv_state_handle( pkt->first_fragment, &session ), "V6 fin-result");
	success &= assert_equals_u8(V4_FIN_V6_FIN_RCV, session.state, "V6 fin-state");
	success &= assert_true(session.dying_time > jiffies, "V6 fin-lifetime");

	pkt_kfree(pkt, true);
	return success;
}

/*
 * Something else arrives.
 */
static noinline bool test_tcp_v4_fin_rcv_state_handle_else( void )
{
	struct session_entry session;
	struct packet *pkt;
	bool success = true;

	/* Prepare */
	success &= init_tcp_session("1::2", 1212, "3::4", 3434, "5.6.7.8", 5678, "8.7.6.5", 8765,
			V4_FIN_RCV, &session);
	success &= test_create_packet_tcp(&pkt, PACKET_TYPE_V4_SYN);
	if (!success)
		return false;

	/* Evaluate */
	success &= assert_true(tcp_v4_fin_rcv_state_handle(pkt->first_fragment, &session), "else-result");
	success &= assert_equals_u8(V4_FIN_RCV, session.state, "else-state");
	success &= assert_true(session.dying_time > jiffies, "else-lifetime");

	pkt_kfree(pkt, true);
	return success;
}

/*
 * A V4 FIN packet arrives.
 */
static noinline bool test_tcp_v6_fin_rcv_state_handle_v4fin( void )
{
	struct session_entry session;
	struct packet *pkt;
	bool success = true;

	/* Prepare */
	success &= init_tcp_session("1::2", 1212, "3::4", 3434, "5.6.7.8", 5678, "8.7.6.5", 8765,
			V6_FIN_RCV, &session);
	success &= test_create_packet_tcp(&pkt, PACKET_TYPE_V4_FIN);
	if (!success)
		return false;

	/* Evaluate */
	success &= assert_true(tcp_v6_fin_rcv_state_handle( pkt->first_fragment, &session ), "V4 fin-result");
	success &= assert_equals_u8(V4_FIN_V6_FIN_RCV, session.state, "V4 fin-state");
	success &= assert_true(session.dying_time > jiffies, "V4 fin-lifetime");

	pkt_kfree(pkt, true);
	return success;
}

/*
 * Something else arrives.
 */
static noinline bool test_tcp_v6_fin_rcv_state_handle_else( void )
{
	struct session_entry session;
	struct packet *pkt;
	bool success = true;

	/* Prepare */
	success &= init_tcp_session("1::2", 1212, "3::4", 3434, "5.6.7.8", 5678, "8.7.6.5", 8765,
			V6_FIN_RCV, &session);
	success &= test_create_packet_tcp(&pkt, PACKET_TYPE_V4_SYN);
	if (!success)
		return false;

	/* Evaluate */
	success &= assert_true(tcp_v6_fin_rcv_state_handle(pkt->first_fragment, &session), "else-result");
	success &= assert_equals_u8(V6_FIN_RCV, session.state, "else-state");
	success &= assert_true(session.dying_time > jiffies, "else-lifetime");

	pkt_kfree(pkt, true);
	return success;
}

/*
 * A V4 RST packet arrives.
 */
static noinline bool test_tcp_trans_state_handle_v4rst( void )
{
	struct session_entry session;
	struct packet *pkt;
	bool success = true;

	/* Prepare */
	success &= init_tcp_session("1::2", 1212, "3::4", 3434, "5.6.7.8", 5678, "8.7.6.5", 8765,
			TRANS, &session);
	success &= test_create_packet_tcp(&pkt, PACKET_TYPE_V4_RST);
	if (!success)
		return false;

	/* Evaluate */
	success &= assert_true(tcp_trans_state_handle( pkt->first_fragment, &session ), "V4 rst-result");
	success &= assert_equals_u8(TRANS, session.state, "V4 rst-state");
	success &= assert_true(session.dying_time < jiffies, "V4 rst-lifetime");

	pkt_kfree(pkt, true);
	return success;
}

/*
* A V6 RST packet arrives.
*/
static noinline bool test_tcp_trans_state_handle_v6rst( void )
{
	struct session_entry session;
	struct packet *pkt;
	bool success = true;

	/* Prepare */
	success &= init_tcp_session("1::2", 1212, "3::4", 3434, "5.6.7.8", 5678, "8.7.6.5", 8765,
			TRANS, &session);
	success &= test_create_packet_tcp(&pkt, PACKET_TYPE_V6_RST);
	if (!success)
		return false;

	/* Evaluate */
	success &= assert_true(tcp_trans_state_handle( pkt->first_fragment, &session ), "V6 rst-result");
	success &= assert_equals_u8(TRANS, session.state, "V6 rst-state");
	success &= assert_true(session.dying_time < jiffies, "V6 rst-lifetime");

	pkt_kfree(pkt, true);
	return success;
}

/*
 * Something else arrives.
 */
static noinline bool test_tcp_trans_state_handle_else( void )
{
	struct session_entry session;
	struct packet *pkt;
	bool success = true;

	/* Prepare */
	success &= init_tcp_session("1::2", 1212, "3::4", 3434, "5.6.7.8", 5678, "8.7.6.5", 8765,
			TRANS, &session);
	success &= test_create_packet_tcp(&pkt, PACKET_TYPE_V4_SYN);
	if (!success)
		return false;

	/* Evaluate */
	success &= assert_true(tcp_trans_state_handle(pkt->first_fragment, &session), "else-result");
	success &= assert_equals_u8(ESTABLISHED, session.state, "else-state");
	success &= assert_true(session.dying_time > jiffies, "else-lifetime");

	pkt_kfree(pkt, true);
	return success;
}

/**
 * We'll just chain a handful of packets, since testing every combination would take forever and
 * the inner functions were tested above anyway.
 * The chain is V6 SYN --> V4 SYN --> V6 RST --> V6 SYN.
 *
 * TODO (test) see test_ipv4_udp().
 */
static noinline bool test_tcp( void )
{
    struct session_entry *session;
    bool success = true;
    struct ipv6_pair pair6;
	struct ipv4_pair pair4;
	struct tuple tuple6;
	struct tuple tuple4;
	struct packet *pkt;
	int error;

	error = init_pair6(&pair6, "1::2", 1212, "64:ff9b::3:4", 3434);
	if (error)
		return false;
	error = init_ipv6_tuple_from_pair(&tuple6, &pair6, L4PROTO_TCP);
	if (error)
		return false;

	error = init_pair4(&pair4, "0.3.0.4", 3434, "192.168.2.1", 18789);
	if (error)
		return false;
	error = init_ipv4_tuple_from_pair(&tuple4, &pair4, L4PROTO_TCP);
	if (error)
		return false;

    /*
     * V6 SYN
     */

	/* Prepare */
	success &= test_create_packet_tcp(&pkt, PACKET_TYPE_V6_SYN);

	/* Evaluate */
    success &= assert_equals_int(VER_CONTINUE, tcp( pkt->first_fragment, &tuple6 ), "Closed-result");
    session = session_get(&tuple6);
    success &= assert_not_null(session, "Closed-session");
    if (session)
        success &= assert_equals_u8(V6_INIT, session->state, "Closed-state");
	pkt_kfree(pkt, true);

    /*
     * V4 SYN
     */

    /* Prepare */
	success &= test_create_packet_tcp(&pkt, PACKET_TYPE_V4_SYN);

	/* Evaluate */
	tuple4.dst.l4_id = session->ipv4.local.l4_id; /* Local port is given by pool4 and random */
    success &= assert_equals_int(VER_CONTINUE, tcp( pkt->first_fragment, &tuple4 ), "V6 init-result");
    session = session_get(&tuple4);
    success &= assert_not_null(session, "V6 init-session");
    if (session)
        success &= assert_equals_u8(ESTABLISHED, session->state, "V6 init-state");
	pkt_kfree(pkt, true);

    /*
     * V6 RST
     */

	/* Prepare */
	success &= test_create_packet_tcp(&pkt, PACKET_TYPE_V6_RST);

	/* Evaluate */
    success &= assert_equals_int(VER_CONTINUE, tcp( pkt->first_fragment, &tuple6 ), "Established-result");
    session = session_get(&tuple6);
    success &= assert_not_null(session, "Established-session");
    if (session)
        success &= assert_equals_u8(TRANS, session->state, "Established-state");
	pkt_kfree(pkt, true);

    /*
     * V6 SYN
     */

	/* Prepare */
	success &= test_create_packet_tcp(&pkt, PACKET_TYPE_V6_SYN);

	/* Evaluate */
    success &= assert_equals_int(VER_CONTINUE, tcp( pkt->first_fragment, &tuple6 ), "Trans-result");
    session = session_get(&tuple6);
    success &= assert_not_null(session, "Trans-session");
    if (session)
        success &= assert_equals_u8(ESTABLISHED, session->state, "Trans-state");
	pkt_kfree(pkt, true);

    return success;
}

//static bool session_expired_callback(struct session_entry *entry)
//{
//	return false;
//}

static noinline bool init_full(void)
{
	int error;

	error = pool6_init(NULL, 0);
	if (error)
		goto fail;
	error = pool4_init(NULL, 0);
	if (error)
		goto fail;
	error = bib_init();
	if (error)
		goto fail;
	error = session_init();
	if (error)
		goto fail;
	error = filtering_init();
	if (error)
		goto fail;

	return true;

fail:
	return false;
}

static noinline bool init_filtering_only(void)
{
	int error = filtering_init();
	return error ? false : true;
}

static void end_full(void)
{
	filtering_destroy();
	session_destroy();
	bib_destroy();
	pool4_destroy();
	pool6_destroy();
}

static void end_filtering_only(void)
{
	filtering_destroy();
}

#define TEST_FILTERING_ONLY(fn, name) \
		INIT_CALL_END(init_filtering_only(), fn, end_filtering_only(), name)
static int __init filtering_test_init(void)
{
	START_TESTS("Filtering and Updating");

	log_debug("\n\n\n");
	log_debug("\n\nNAT64 %s TEST module inserted!", "filtering_test");

	/*      UDP & ICMP      */
	CALL_TEST(test_transport_address_ipv4(), "test_transport_address_ipv4");
	CALL_TEST(test_transport_address_ipv6(), "test_transport_address_ipv6");
	CALL_TEST(test_extract_ipv4_from_ipv6(), "test_extract_ipv4_from_ipv6");
	CALL_TEST(test_embed_ipv4_in_ipv6(), "test_embed_ipv4_in_ipv6");
	INIT_CALL_END(init_full(), test_allocate_ipv4_transport_address(), end_full(), "test_allocate_ipv4_transport_address");
	INIT_CALL_END(init_full(), test_allocate_ipv4_transport_address_digger(), end_full(), "test_allocate_ipv4_transport_address_digger");
	INIT_CALL_END(init_full(), test_ipv6_udp(), end_full(), "test_ipv6_udp");
	INIT_CALL_END(init_full(), test_ipv4_udp(), end_full(), "test_ipv4_udp");
	INIT_CALL_END(init_full(), test_ipv6_icmp6(), end_full(), "test_ipv6_icmp6");
	INIT_CALL_END(init_full(), test_ipv4_icmp4(), end_full(), "test_ipv4_icmp4");
	/* CALL_TEST(test_send_icmp_error_message(), "test_send_icmp_error_message"); Not implemented yet! */
	INIT_CALL_END(init_full(), test_filtering_and_updating(), end_full(), "test_filtering_and_updating");

	/*      TCP      */
	CALL_TEST(test_packet_is_syn(), "test_packet_is_syn");
	CALL_TEST(test_packet_is_fin(), "test_packet_is_fin");
	CALL_TEST(test_packet_is_rst(), "test_packet_is_rst");
	CALL_TEST(test_send_probe_packet(), "test_send_probe_packet");

	INIT_CALL_END(init_full(), test_tcp_closed_state_handle_6(), end_full(), "TCP-CLOSED-6");
	/* Not implemented yet! */
	/* INIT_CALL_END(init_full(), test_tcp_closed_state_handle_4(), end_full(), "TCP-CLOSED-4"); */
	TEST_FILTERING_ONLY(test_tcp_v4_init_state_handle_v6syn(), "TCP-V4 INIT-V6 syn");
	TEST_FILTERING_ONLY(test_tcp_v4_init_state_handle_else(), "TCP-V4 INIT-else");
	TEST_FILTERING_ONLY(test_tcp_v6_init_state_handle_v6syn(), "TCP-V6 INIT-V6 SYN");
	TEST_FILTERING_ONLY(test_tcp_v6_init_state_handle_v4syn(), "TCP-V6 INIT-V4 SYN");
	TEST_FILTERING_ONLY(test_tcp_v6_init_state_handle_else(), "TCP-V6 INIT-else");
	TEST_FILTERING_ONLY(test_tcp_established_state_handle_v4fin(), "TCP-established-V4 fin");
	TEST_FILTERING_ONLY(test_tcp_established_state_handle_v6fin(), "TCP-established-V6 fin");
	TEST_FILTERING_ONLY(test_tcp_established_state_handle_v4rst(), "TCP-established-V4 rst");
	TEST_FILTERING_ONLY(test_tcp_established_state_handle_v6rst(), "TCP-established-V6 rst");
	TEST_FILTERING_ONLY(test_tcp_established_state_handle_else(), "TCP-established-else");
	TEST_FILTERING_ONLY(test_tcp_v4_fin_rcv_state_handle_v6fin(), "TCP-V4 FIN RCV-V6 fin");
	TEST_FILTERING_ONLY(test_tcp_v4_fin_rcv_state_handle_else(), "TCP-V4 FIN RCV-else");
	TEST_FILTERING_ONLY(test_tcp_v6_fin_rcv_state_handle_v4fin(), "TCP-V6 FIN RCV-v4fin");
	TEST_FILTERING_ONLY(test_tcp_v6_fin_rcv_state_handle_else(), "TCP-V6 FIN RCV-else");
	TEST_FILTERING_ONLY(test_tcp_trans_state_handle_v6rst(), "TCP-TRANS-V6 rst");
	TEST_FILTERING_ONLY(test_tcp_trans_state_handle_v4rst(), "TCP-TRANS-V4 rst");
	TEST_FILTERING_ONLY(test_tcp_trans_state_handle_else(), "TCP-TRANS-else");

	INIT_CALL_END(init_full(), test_tcp(), end_full(), "test_tcp");

	/* A non 0 return means a test failed; module can't be loaded. */
	END_TESTS;
}

static void __exit filtering_test_exit(void)
{
    log_debug("NAT64 %s TEST module removed!\n\n\n", "filtering_test");
}

module_init(filtering_test_init);
module_exit(filtering_test_exit);
