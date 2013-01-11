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
//~ #include <linux/types.h>    /* bool */
#include <linux/printk.h>   /* pr_* */

//~ #define DRIVER_AUTHOR   "Roberto <r.aceves@itesm.mx>"
//~ #define DRIVER_DESC     "Unitary tests for the Filtering's part of NAT64"
//~ MODULE_LICENSE("GPL");  /* Get rid of taint message by declaring code as GPL. */
//~ MODULE_AUTHOR(DRIVER_AUTHOR);       /* Who wrote this module? */
//~ MODULE_DESCRIPTION(DRIVER_DESC);    /* What does this module do */

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Roberto <r.aceves@itesm.mx>"); 
MODULE_DESCRIPTION("Unitary tests for the Filtering\'s part of NAT64");
MODULE_ALIAS("nat64_test_filtering");


#include "unit_test_rob.h"

//~ #include <net/netfilter/nf_conntrack_tuple.h>
//~ #include <linux/types.h>
#include <linux/ipv6.h>
//~ #include "nf_nat64_types.h"

// What are we testing?
#include "nf_nat64_ipv4_pool.h"
#include "nf_nat64_config.h"
#include "xt_nat64_module_conf_validation.h"
#include "nf_nat64_filtering_and_updating.c"

extern struct config_struct cs;


/* ASSERT_EQUALS(expected, actual, test_name) */
/*
bool test_( void )
{
    struct in_addr addr;
    struct in6_addr addr6;
    START_TEST;

    // 
    in4_pton(IPV4_IN_POOL, -1, (u8 *)&addr, '\x0', NULL);
    ASSERT_EQUALS(true,  ( & ), " .");

    // 
    in6_pton( , -1, (u8 *)&addr6, '\x0', NULL);
    ASSERT_EQUALS(true,  ( & ), " .");

    
    END_TEST;
}
*/




/* We are testing: filtering.c 
 * BEGIN: filtering.c */

#define INIT_TUPLE_IPV4_SRC_ADDR    "192.168.2.1"
#define INIT_TUPLE_IPV6_SRC_ADDR    "2001:db8:c0ca::1"
#define INIT_TUPLE_IPV4_DST_ADDR    "192.168.2.44"
#define INIT_TUPLE_IPV6_DST_ADDR    "64:ff9b::192.168.2.44"
#define INIT_TUPLE_IPV6_ICMP_ID     1080
#define INIT_TUPLE_IPV4_ICMP_ID     ( INIT_TUPLE_IPV6_ICMP_ID  )
#define INIT_TUPLE_IPV6_SRC_PORT    1080
#define INIT_TUPLE_IPV6_DST_PORT    1081
#define INIT_TUPLE_IPV4_SRC_PORT    1082
#define INIT_TUPLE_IPV4_DST_PORT    1081
void init_tuple_for_test_ipv6(struct nf_conntrack_tuple *tuple, u_int8_t l4protocol)
{
    struct in6_addr addr6;

    in6_pton(INIT_TUPLE_IPV6_SRC_ADDR, -1, (u8 *)&addr6, '\x0', NULL);
    tuple->ipv6_src_addr =  addr6;

    in6_pton(INIT_TUPLE_IPV6_DST_ADDR, -1, (u8 *)&addr6, '\x0', NULL);
    tuple->ipv6_dst_addr =  addr6;

    tuple->L3_PROTOCOL = NFPROTO_IPV6;
    tuple->L4_PROTOCOL = l4protocol;
    
    if ( l4protocol == IPPROTO_ICMPV6 )
    {
        tuple->icmp_id = htons( INIT_TUPLE_IPV6_ICMP_ID );
        tuple->dst_port = htons( INIT_TUPLE_IPV6_ICMP_ID );
    }
    else
    {
        tuple->src_port = htons( INIT_TUPLE_IPV6_SRC_PORT );
        tuple->dst_port = htons( INIT_TUPLE_IPV6_DST_PORT );
    }
}
void init_tuple_for_test_ipv4(struct nf_conntrack_tuple *tuple, u_int8_t l4protocol)
{
    struct in_addr addr;

    in4_pton(INIT_TUPLE_IPV4_DST_ADDR, -1, (u8 *)&addr, '\x0', NULL);
    tuple->ipv4_src_addr =  addr;

    in4_pton(INIT_TUPLE_IPV4_SRC_ADDR, -1, (u8 *)&addr, '\x0', NULL);
    tuple->ipv4_dst_addr =  addr;

    tuple->L3_PROTOCOL = NFPROTO_IPV4;
    tuple->L4_PROTOCOL = l4protocol;

    if ( l4protocol == IPPROTO_ICMP )
    {
        tuple->icmp_id = htons( INIT_TUPLE_IPV4_ICMP_ID );
        tuple->dst_port = htons( INIT_TUPLE_IPV4_ICMP_ID );
    }
    else
    {
        tuple->src_port = htons( INIT_TUPLE_IPV4_DST_PORT );
        tuple->dst_port = htons( INIT_TUPLE_IPV4_SRC_PORT );
    }
}


#define IPV6_INJECT_BIB_ENTRY_SRC_ADDR  "2001:db8:c0ca::1"
#define IPV6_INJECT_BIB_ENTRY_SRC_PORT  1080
#define IPV4_INJECT_BIB_ENTRY_DST_ADDR  "192.168.2.1"
#define IPV4_INJECT_BIB_ENTRY_DST_PORT  1082
#define INIT_TUPLE_ICMP_ID              10
// Inject a BIB entry for a protocol
//~ void inject_bib_entry( struct ipv4_tuple_address ipv6, struct ipv4_tuple_address ipv4 )
bool inject_bib_entry( struct bib_entry *bib_e, u_int8_t l4protocol )
{
    struct ipv4_tuple_address ta_ipv4;
    struct ipv6_tuple_address ta_ipv6;

    struct in_addr addr4;
    struct in6_addr addr6;

    in4_pton(IPV4_INJECT_BIB_ENTRY_DST_ADDR, -1, (u8 *)&addr4, '\x0', NULL);
    in6_pton(IPV6_INJECT_BIB_ENTRY_SRC_ADDR, -1, (u8 *)&addr6, '\x0', NULL);


    if ( l4protocol == IPPROTO_ICMPV6 )
    {
        transport_address_ipv4( addr4, htons( INIT_TUPLE_ICMP_ID ), &ta_ipv4 );
        transport_address_ipv6( addr6, htons( INIT_TUPLE_ICMP_ID ), &ta_ipv6 );        
    }
    else
    {
        transport_address_ipv4( addr4, htons( IPV4_INJECT_BIB_ENTRY_DST_PORT ), &ta_ipv4 );
        transport_address_ipv6( addr6, htons( IPV6_INJECT_BIB_ENTRY_SRC_PORT ), &ta_ipv6 );
    }
    //~ bib_e->ipv4 = ta_ipv4;
    //~ bib_e->ipv6 = ta_ipv6;
    bib_e = nat64_create_bib_entry( &ta_ipv4, &ta_ipv6);
    
    return nat64_add_bib_entry( bib_e, l4protocol );
    //~ nat64_add_bib_entry( bib_e, IPPROTO_TCP);
    //~ nat64_add_bib_entry( bib_e, IPPROTO_ICMP);

}

// Inject a Session Table Entry for the 3 protocols
void inject_session_entry( struct ipv6_pair ipv6, struct ipv6_pair ipv4 )
{
    // TODO: Implement me!
}

#define IPV4_TRANSPORT_ADDR     "192.168.1.4"
#define IPV4_TRANSPORT_PORT     1081
//~ void transport_address_ipv4(struct ipv4_tuple_address *ta, struct in_addr addr, __be16 pi)
bool test_transport_address_ipv4( void )
{
    struct in_addr addr;
    struct ipv4_tuple_address ta;

    START_TEST;

    // 
    in4_pton(IPV4_TRANSPORT_ADDR, -1, (u8 *)&addr, '\x0', NULL);
    transport_address_ipv4( addr, htons( (__be16)IPV4_TRANSPORT_PORT ), &ta );
    
    ASSERT_EQUALS(true, ipv4_addr_equals(&ta.address, &addr) ,
        "Check that the address part of an IPv4 transport address is correct.");

    ASSERT_EQUALS(htons(ta.pi.port), (__be16)IPV4_TRANSPORT_PORT,
        "Check that the port part of an IPv4 transport address is correct.");

    END_TEST;
}



#define IPV6_TRANSPORT_ADDR     "2001:db8:c0ca::1"
#define IPV6_TRANSPORT_PORT     1081
//~ void transport_address_ipv6(struct ipv6_tuple_address *ta, struct in6_addr addr, __be16 pi)
bool test_transport_address_ipv6( void )
{
    struct in6_addr addr6;
    struct ipv6_tuple_address ta;
    
    START_TEST;

    // Build an IPv6 transport address from address & port
    in6_pton(IPV6_TRANSPORT_ADDR, -1, (u8 *)&addr6, '\x0', NULL);
    transport_address_ipv6( addr6, htons( (__be16)IPV6_TRANSPORT_PORT ), &ta );
    
    ASSERT_EQUALS(true, ipv6_addr_equals (&ta.address, &addr6) ,
        "Check that the address part of an IPv6 transport address is correct.");

    ASSERT_EQUALS( htons( ta.pi.port ), (__be16)IPV6_TRANSPORT_PORT , 
        "Check that the port part of an IPv6 transport address is correct.");
    
    END_TEST;
}


#define IPV6_EXTRACT_ADDR     "2001:db8:c0ca::192.168.2.3"
#define IPV4_EXTRACTED_ADDR     "192.168.2.3"
//~ int extract_ipv4_from_ipv6 (struct in6_addr ipv6, struct in_addr *ipv4)
bool test_extract_ipv4_from_ipv6( void )
{
    struct in6_addr addr6;
    struct in_addr extracted4;
    struct in_addr correct4;
    
    START_TEST;

    // Convert the IPv6 address to binary
    in6_pton(IPV6_EXTRACT_ADDR, -1, (u8 *)&addr6, '\x0', NULL);
    
    ASSERT_EQUALS(true, extract_ipv4_from_ipv6 (addr6, &extracted4) , 
        "Check that an IPv4 address can be extracted from an IPv6 address.");

    in4_pton(IPV4_EXTRACTED_ADDR, -1, (u8 *)&correct4, '\x0', NULL);
    ASSERT_EQUALS(true, ipv4_addr_equals(&extracted4, &correct4) , 
        "Assert that the extraction of the IPv4 address was correct.");

    
    END_TEST;
}


#define IPV6_EMBED_ADDR         "2001:db8:c0ca::1"
#define IPV6_EMBEDDED_ADDR      "2001:db8:c0ca::192.168.2.3"
#define IPV4_EMBEDDABLE_ADDR    "192.168.2.3"
//~ int embed_ipv4_in_ipv6 (struct in_addr ipv4, struct in6_addr *ipv6)
bool test_embed_ipv4_in_ipv6( void )
{
    struct in_addr embeddable4;
    struct in6_addr embed6;
    struct in6_addr embedded6;
    
    START_TEST;

    // Convert to binary the IPv4 address to embed
    in4_pton(IPV4_EMBEDDABLE_ADDR, -1, (u8 *)&embeddable4, '\x0', NULL);
    
    ASSERT_EQUALS(true, embed_ipv4_in_ipv6 ( embeddable4, &embed6 ) , 
        "Check that we can embed an IPv4 address inside of an IPv6 address correctly.");

    // Verify the output
    in6_pton(IPV6_EMBED_ADDR, -1, (u8 *)&embedded6, '\x0', NULL);
    ASSERT_EQUALS(true, ipv6_addr_equals( &embed6 , &embedded6 ) , 
        "Check that the port part of an IPv6 transport address is correct.");
    
    END_TEST;
}

#define IPV4_GET_ICMP_ID_ADDR   "192.168.2.3"
#define IPV4_GET_ICMP_ID        0x004
//~ int get_icmpv4_identifier(struct in_addr *address, __be16 *pi)
bool test_get_icmpv4_identifier( void )
{
    struct in_addr addr4;
    __be16 pi;
    
    START_TEST;

    // Convert to binary the IPv4 address to embed
    in4_pton(IPV4_GET_ICMP_ID_ADDR, -1, (u8 *)&addr4, '\x0', NULL);
    
    ASSERT_EQUALS(true, get_icmpv4_identifier ( &addr4, &pi ) , 
        "Check that we can embed an IPv4 address inside of an IPv6 address correctly.");

    // Verify the output
    ASSERT_EQUALS(pi, IPV4_GET_ICMP_ID , 
        "Check that the ICMPv4 identifier was the expected (hard-coded).");
    
    END_TEST;
}


#define IPV6_ALLOCATE_SRC_ADDR  "2001:db8:c0ca::1"
#define IPV6_ALLOCATE_SRC_PORT  1080
#define IPV4_ALLOCATED_ADDR     "192.168.2.1"
#define IPV4_ALLOCATED_PORT_ICMP     (IPV6_ALLOCATE_SRC_PORT + 2)  // <-- 1082
#define IPV4_ALLOCATED_PORT     (IPV6_ALLOCATE_SRC_PORT +1 + 2)  // <-- 1082
//~ bool  allocate_ipv4_transport_address(struct nf_conntrack_tuple *tuple, 
                                     //~ u_int8_t protocol, 
                                     //~ struct ipv4_tuple_address *new_ipv4_transport_address)
bool test_allocate_ipv4_transport_address( void )
{
    struct in_addr expected_addr;
    bool ret;
    u_int8_t protocol;
    
    struct nf_conntrack_tuple tuple;
    struct ipv4_tuple_address new_ipv4_transport_address;

    struct bib_entry bib_e;

//~ int ii = 0;
    START_TEST;
    
//~ pr_debug("-- %d --", ii++);

    nat64_bib_init();
//~ pr_debug("-- %d --", ii++);

    protocol = IPPROTO_ICMP;
    ret = inject_bib_entry( &bib_e, protocol );
    ASSERT_EQUALS(true,  ret, "Trying to insert a BIB entry for do some tests.");
//~ pr_debug("-- %d --", ii++);

    // 
    init_tuple_for_test_ipv4(&tuple, protocol);
//~ pr_debug("-- %d --", ii++);

    in4_pton(IPV4_ALLOCATED_ADDR, -1, (u8 *)&expected_addr, '\x0', NULL);
//~ pr_debug("-- %d --", ii++);

    ret = allocate_ipv4_transport_address(&tuple, protocol, &new_ipv4_transport_address);
    ASSERT_EQUALS(true,  ret, "Check that we can allocate a brand new IPv4 transport address for ICMP.");
   
    ASSERT_EQUALS(true,  ipv4_addr_equals (&new_ipv4_transport_address.address, &expected_addr) ,
        "Check that the allocated IPv4 address is correct for ICMP.");
//~ pr_debug(">> new_ipv4_transport_address = %pI4", &new_ipv4_transport_address.address );
//~ pr_debug(">> expected_addr = %pI4", &expected_addr );

    ASSERT_EQUALS( (__be16)(IPV4_ALLOCATED_PORT_ICMP), ntohs(new_ipv4_transport_address.pi.port),  
        "Check that the allocated IPv4 port is correct for ICMP.");
//~ pr_debug("-- %d --", ii++);

    // 
    protocol = IPPROTO_TCP;
    ret = inject_bib_entry( &bib_e, protocol );
    ASSERT_EQUALS(true,  ret, "Trying to insert a BIB entry for do some tests.");
    init_tuple_for_test_ipv4(&tuple, protocol);
//~ pr_debug("-- %d --", ii++);

    in4_pton(IPV4_ALLOCATED_ADDR, -1, (u8 *)&expected_addr, '\x0', NULL);

    ret = allocate_ipv4_transport_address(&tuple, protocol, &new_ipv4_transport_address);
    ASSERT_EQUALS(true,  ret, "Check that we can allocate a brand new IPv4 transport address for TCP.");
   
    ASSERT_EQUALS(true,  ipv4_addr_equals (&new_ipv4_transport_address.address, &expected_addr) ,
        "Check that the allocated IPv4 address is correct for TCP.");

    pr_debug("	IPV4_ALLOCATED_PORT=%d , new_ipv4_transport_address.pi.port=%d", (__be16)(IPV4_ALLOCATED_PORT), ntohs(new_ipv4_transport_address.pi.port) );  
    ASSERT_EQUALS( (__be16)(IPV4_ALLOCATED_PORT ), ntohs(new_ipv4_transport_address.pi.port),  
        "Check that the allocated IPv4 port is correct for TCP.");
//~ pr_debug("-- %d --", ii++);
    
    // 
    protocol = IPPROTO_UDP;
    ret = inject_bib_entry( &bib_e, protocol );
    ASSERT_EQUALS(true,  ret, "Trying to insert a BIB entry for do some tests.");
    init_tuple_for_test_ipv4(&tuple, protocol);
//~ pr_debug("-- %d --", ii++);

    in4_pton(IPV4_ALLOCATED_ADDR, -1, (u8 *)&expected_addr, '\x0', NULL);

    ret = allocate_ipv4_transport_address(&tuple, protocol, &new_ipv4_transport_address);
    ASSERT_EQUALS(true,  ret, "Check that we can allocate a brand new IPv4 transport address for UDP.");
   
    ASSERT_EQUALS(true,  ipv4_addr_equals (&new_ipv4_transport_address.address, &expected_addr) ,
        "Check that the allocated IPv4 address is correct for UDP.");

    ASSERT_EQUALS( (__be16)(IPV4_ALLOCATED_PORT ), ntohs(new_ipv4_transport_address.pi.port),  
        "Check that the allocated IPv4 port is correct for UDP.");

//~ pr_debug("-- %d --", ii++);

    nat64_bib_destroy();
//~ pr_debug("-- %d --", ii++);
    
    END_TEST;
}

//~ bool allocate_ipv4_transport_address_digger(struct nf_conntrack_tuple *tuple, 
                                     //~ u_int8_t protocol, 
                                     //~ struct ipv4_tuple_address *new_ipv4_transport_address)
bool test_allocate_ipv4_transport_address_digger( void )
{
    struct in_addr expected_addr;
    bool ret;
    u_int8_t protocol;
    
    struct nf_conntrack_tuple tuple;
    struct ipv4_tuple_address new_ipv4_transport_address;

    struct bib_entry bib_e1;
    struct bib_entry bib_e2;

int ii = 0;
    START_TEST;
//~ pr_debug("-- %d --", ii++); 

    nat64_bib_init();
//~ pr_debug("-- %d --", ii++); 


    protocol = IPPROTO_ICMP;
    ret = inject_bib_entry( &bib_e1, protocol );
    ASSERT_EQUALS(true,  ret, "Trying to insert a BIB entry for do some tests.");
//~ pr_debug("-- %d --", ii++); 

    // 
    protocol = IPPROTO_TCP;
    ret = inject_bib_entry( &bib_e2, protocol );
    ASSERT_EQUALS(true,  ret, "Trying to insert a BIB entry for do some tests.");
//~ pr_debug("-- %d --", ii++); 
    
    // 
    protocol = IPPROTO_UDP;
    //~ inject_bib_entry( &bib_e, protocol );     
    init_tuple_for_test_ipv6(&tuple, protocol);
//~ pr_debug("-- %d --", ii++); 

    in4_pton(IPV4_ALLOCATED_ADDR, -1, (u8 *)&expected_addr, '\x0', NULL);
//~ pr_debug("-- %d --", ii++);

    ret = allocate_ipv4_transport_address_digger(&tuple, protocol, &new_ipv4_transport_address);
    ASSERT_EQUALS(true,  ret, "Check that we can allocate a brand new IPv4 transport address for UDP.");
pr_debug("-- %d --", ii++); 

    ASSERT_EQUALS(true,  ipv4_addr_equals (&new_ipv4_transport_address.address, &expected_addr) ,
        "Check that the allocated IPv4 address is correct for UDP.");
pr_debug(">> new_ipv4_transport_address = %pI4", &new_ipv4_transport_address.address );
pr_debug(">> expected_addr = %pI4", &expected_addr );

    ASSERT_EQUALS( (__be16)(IPV4_ALLOCATED_PORT ), new_ipv4_transport_address.pi.port,  
        "Check that the allocated IPv4 port is correct for UDP.");

//~ pr_debug("-- %d --", ii++); 

    nat64_bib_destroy();
//~ pr_debug("-- %d --", ii++); 
    
    END_TEST;
}

//~ int ipv6_udp(struct nf_conntrack_tuple *tuple)
bool test_ipv6_udp( void )
{
    int ret;
    u_int8_t protocol;
    //~ u_int16_t L3_PROTOCOL;
    struct nf_conntrack_tuple tuple;
    
    START_TEST;

    nat64_bib_init();
    nat64_session_init();

    protocol = IPPROTO_UDP;

    // Init tuple
    init_tuple_for_test_ipv6( &tuple, protocol );

    // Create Bib & Session:
    ret = ipv6_udp( &tuple );
    ASSERT_EQUALS(NF_ACCEPT, ret, "See if we can process correctly an IPv6 UDP packet.");

    nat64_session_destroy();
    nat64_bib_destroy();
    
    END_TEST;
}

//~ int ipv4_udp(struct nf_conntrack_tuple *tuple)
bool test_ipv4_udp( void )
{
    int ret;
    u_int8_t protocol;
    struct nf_conntrack_tuple tuple;
    
    START_TEST;

    nat64_bib_init();
    nat64_session_init();

    protocol = IPPROTO_UDP;

    // Init tuple
    init_tuple_for_test_ipv4( &tuple , protocol  );

    // Discard un-expected IPv4 packets.
    ret = ipv4_udp(&tuple);
    ASSERT_EQUALS(NF_DROP, ret, "See if we discard an IPv4 UDP packet, which tries to start a communication.");

    // Process an expected packet

    // Create Bib & Session:
    init_tuple_for_test_ipv6( &tuple , protocol  );    
    ret = ipv6_udp( &tuple );
    ASSERT_EQUALS(NF_ACCEPT, ret, "See if we can process correctly an IPv6 UDP packet.");
    
    init_tuple_for_test_ipv4( &tuple , protocol  );

    ret = ipv4_udp( &tuple );
    ASSERT_EQUALS(NF_ACCEPT, ret, "See if we can process correctly an expected IPv4 UDP packet.");

    nat64_session_destroy();
    nat64_bib_destroy();
    
    END_TEST;
}

//~ int ipv6_icmp6(struct nf_conntrack_tuple *tuple)
bool test_ipv6_icmp6( void )
{
    int ret;
    u_int8_t protocol;
    struct nf_conntrack_tuple tuple;
    
    START_TEST;

    nat64_bib_init();
    nat64_session_init();

    protocol = IPPROTO_ICMPV6;

    // Init tuple
    init_tuple_for_test_ipv6( &tuple , protocol );

    // Create Bib & Session:
    ret = ipv6_icmp6(&tuple);
    ASSERT_EQUALS(NF_ACCEPT,  ret, "See if we can process correctly an IPv6 ICMP packet.");

    nat64_session_destroy();
    nat64_bib_destroy();
      
    END_TEST;
}

//~ int ipv4_icmp4(struct nf_conntrack_tuple *tuple)
bool test_ipv4_icmp4( void )
{
    int ret;
    u_int8_t protocol;
    struct nf_conntrack_tuple tuple;
    
    START_TEST;

    nat64_bib_init();
    nat64_session_init();

    protocol = IPPROTO_ICMP;

pr_debug(">>> Init ipv4 tuple");
    // Init tuple
    init_tuple_for_test_ipv4( &tuple , protocol );

pr_debug(">>> Inject ipv4 tuple for icmp");
    // Discard un-expected IPv4 packets.
    ret = ipv4_icmp4( &tuple );
    ASSERT_EQUALS(NF_DROP, ret, "See if we discard an IPv4 ICMP packet, which tries to start a communication.");

    // Process an expected packet
    
    // Create Bib & Session:
    protocol = IPPROTO_ICMPV6;
pr_debug(">>> Init ipv6 tuple");    
    init_tuple_for_test_ipv6( &tuple , protocol );
pr_debug(">>> Inject ipv6 tuple to create a bib & session");
    ret = ipv6_icmp6( &tuple );
    ASSERT_EQUALS(NF_ACCEPT, ret, "See if we can process correctly an IPv6 ICMP packet.");

pr_debug(">>> Init ipv4 tuple");
    protocol = IPPROTO_ICMP;
    init_tuple_for_test_ipv4( &tuple , protocol );

pr_debug(">>> Test an existing ipv4 tuple");
    // Process an expected IPv4 packets.
    ret = ipv4_icmp4( &tuple );
    ASSERT_EQUALS(NF_ACCEPT, ret, "See if we can process correctly an expected IPv4 ICMP packet.");
pr_debug(">>> Destroy bib and session");

    nat64_session_destroy();
    nat64_bib_destroy();
    
    END_TEST;
}

//~ void send_icmp_error_message(struct nf_conntrack_tuple *tuple, u_int8_t type, u_int8_t code);
bool test_send_icmp_error_message( void )
{
    struct nf_conntrack_tuple tuple;
    u_int8_t protocol;
    u_int8_t type;
    u_int8_t code;

    START_TEST;

    protocol = IPPROTO_ICMP;

pr_debug(">>> Init ipv4 tuple");
    // Init tuple
    init_tuple_for_test_ipv4( &tuple , protocol );

    pr_debug("Test if we can send an ICMP error packet: DESTINATION_UNREACHABLE, HOST_UNREACHABLE");
    type = DESTINATION_UNREACHABLE;
    code = HOST_UNREACHABLE;
    send_icmp_error_message( &tuple, type, code);

    pr_debug("Test if we can send an ICMP error packet: DESTINATION_UNREACHABLE, ADDRESS_UNREACHABLE");
    type = DESTINATION_UNREACHABLE;
    code = ADDRESS_UNREACHABLE;
    send_icmp_error_message( &tuple, type, code);

    pr_debug("Test if we can send an ICMP error packet: DESTINATION_UNREACHABLE, COMMUNICATION_ADMINISTRATIVELY_PROHIBITED");
    type = DESTINATION_UNREACHABLE;
    code = COMMUNICATION_ADMINISTRATIVELY_PROHIBITED;
    send_icmp_error_message( &tuple, type, code);

pr_debug(">>> Init ipv6 tuple");
    // Init tuple
    init_tuple_for_test_ipv6( &tuple , protocol );

    pr_debug("Test if we can send an ICMPv6 error packet: DESTINATION_UNREACHABLE, HOST_UNREACHABLE");
    type = DESTINATION_UNREACHABLE;
    code = HOST_UNREACHABLE;
    send_icmp_error_message( &tuple, type, code);

    pr_debug("Test if we can send an ICMPv6 error packet: DESTINATION_UNREACHABLE, ADDRESS_UNREACHABLE");
    type = DESTINATION_UNREACHABLE;
    code = ADDRESS_UNREACHABLE;
    send_icmp_error_message( &tuple, type, code);

    pr_debug("Test if we can send an ICMPv6 error packet: DESTINATION_UNREACHABLE, COMMUNICATION_ADMINISTRATIVELY_PROHIBITED");
    type = DESTINATION_UNREACHABLE;
    code = COMMUNICATION_ADMINISTRATIVELY_PROHIBITED;
    send_icmp_error_message( &tuple, type, code);
    
    END_TEST;
}


#define INIT_TUPLE_IPV6_HAIR_LOOP_DST_ADDR    "2001:db8:c0ca::1"
#define INIT_TUPLE_IPV6_HAIR_LOOP_SRC_ADDR    "64:ff9b::192.168.2.44"
#define INIT_TUPLE_IPV4_NOT_POOL_DST_ADDR     "192.168.100.44"
//~ int filtering_and_updating(struct packet packet, struct nf_conntrack_tuple *tuple)
bool test_filtering_and_updating( void )
{
    int ret;
    u_int8_t protocol;
    struct nf_conntrack_tuple tuple;
    struct sk_buff skb;
    struct in_addr addr4;
    struct in6_addr addr6;
    
    START_TEST;

    nat64_bib_init();
    nat64_session_init();

pr_debug(">>> Errores de ICMP no deben afectar las tablas");
    // IPv4 incoming packet
    protocol = IPPROTO_ICMP;
    // Init tuple
    init_tuple_for_test_ipv4( &tuple , protocol );
    // Process a tuple generated from a incoming IPv6 packet:
    ret = filtering_and_updating( &skb, &tuple);
    ASSERT_EQUALS(NF_ACCEPT,  ret, "See if we can forward an IPv4 ICMP packet.");

pr_debug(">>> Get rid of hairpinning loop ");
    // IPv6 incoming packet
    protocol = IPPROTO_UDP;
    // Init tuple
    init_tuple_for_test_ipv6( &tuple , protocol );
    // Add pref64
    in6_pton(INIT_TUPLE_IPV6_HAIR_LOOP_SRC_ADDR , -1, (u8 *)&addr6, '\x0', NULL);
    tuple.ipv6_src_addr = addr6; 
    // Process a tuple generated from a incoming IPv6 packet:
    ret = filtering_and_updating( &skb, &tuple);
    // 
    ASSERT_EQUALS(NF_DROP,  ret, "See if we can get rid of hairpinning loop in IPv6.");

pr_debug(">>> Get rid of unwanted packets");
    // IPv6 incoming packet
    protocol = IPPROTO_UDP;
    // Init tuple
    init_tuple_for_test_ipv6( &tuple , protocol );
    // Unwanted packet
    in6_pton(INIT_TUPLE_IPV6_HAIR_LOOP_DST_ADDR , -1, (u8 *)&addr6, '\x0', NULL);
    tuple.ipv6_dst_addr = addr6; 
    // Process a tuple generated from a incoming IPv6 packet:
    ret = filtering_and_updating( &skb, &tuple);
    ASSERT_EQUALS(NF_DROP,  ret, "See if we can get rid of unwanted packets in IPv6.");

pr_debug(">>> Get rid of un-expected packets, destined to an address not in pool");
    // IPv4 incoming packet
    protocol = IPPROTO_UDP;
    // Init tuple
    init_tuple_for_test_ipv4( &tuple , protocol );
    // Packet destined to an address not in pool
    in6_pton(INIT_TUPLE_IPV4_NOT_POOL_DST_ADDR , -1, (u8 *)&addr4, '\x0', NULL);
    tuple.ipv4_dst_addr = addr4; 
    // Process a tuple generated from a incoming IPv6 packet:
    ret = filtering_and_updating( &skb, &tuple);
    ASSERT_EQUALS(NF_DROP,  ret, "See if we can get rid of packet destined to an address not in pool.");


pr_debug(">>> packet");



pr_debug(">>> IPv4 incoming packet --> reject");
    // IPv4 incoming packet
    protocol = IPPROTO_UDP;
    // Init tuple
    init_tuple_for_test_ipv4( &tuple , protocol );
    // Process a tuple generated from a incoming IPv6 packet:
    ret = filtering_and_updating( &skb, &tuple);
    ASSERT_EQUALS(NF_DROP,  ret, "See if we can do reject an incoming IPv4 UDP packet.");

pr_debug(">>> IPv6 incoming packet --> accept");
    // IPv6 incoming packet
    protocol = IPPROTO_UDP;
    // Init tuple
    init_tuple_for_test_ipv6( &tuple , protocol );
    // Process a tuple generated from a incoming IPv6 packet:
    ret = filtering_and_updating( &skb, &tuple);
    ASSERT_EQUALS(NF_ACCEPT,  ret, "See if we can do filtering and updating on an incoming IPv6 UDP packet.");

pr_debug(">>> IPv4 incoming packet --> accept");
    // IPv4 incoming packet
    protocol = IPPROTO_UDP;
    // Init tuple
    init_tuple_for_test_ipv4( &tuple , protocol );
    // Process a tuple generated from a incoming IPv6 packet:
    ret = filtering_and_updating( &skb, &tuple);
    ASSERT_EQUALS(NF_ACCEPT,  ret, "See if we can do filtering and updating on an incoming IPv4 UDP packet.");


    nat64_session_destroy();
    nat64_bib_destroy();
    
    END_TEST;
}

/* END: filtering.c */


/* We are testing: filtering_tcp.c 
 * BEGIN: filtering_tcp.c */



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
			pr_warning("NAT64:  test_filtering.c: Invalid packet type in init_packet_type_for_test().");
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

pr_debug("  ...\n");

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
			pr_warning("NAT64:  test_filtering.c: Invalid packet type in init_packet_type_for_test().");
			kfree_skb(skb);
			return NULL;
    }

    return skb;
}


//~ bool packet_is_ipv4(struct packet *packet)
bool test_packet_is_ipv4( void )
{
    //~ struct packet packet;
    struct sk_buff *buffer;

    START_TEST;

pr_debug("init_packet_type_for_test");
    // Set packet type to V4 SYN
    if ((buffer = init_packet_type_for_test( PACKET_TYPE_V4_SYN )) == NULL)
    	return false;


pr_debug("call to packet_is_ipv4");
    // 
    ASSERT_EQUALS(true,  packet_is_ipv4( buffer ), "Test if we detect an IPv4 packet.");
pr_debug("back from packet_is_ipv4");
    
	kfree_skb(buffer);
    END_TEST;
}

//~ bool packet_is_ipv6(struct packet *packet)
bool test_packet_is_ipv6( void )
{
    struct sk_buff *skb;

    START_TEST;

    // Set packet type to V6 SYN
    if ((skb = init_packet_type_for_test( PACKET_TYPE_V6_SYN )) == NULL)
    	return false;

    // 
    ASSERT_EQUALS(true,  packet_is_ipv6( skb ), "Test if we detect an IPv6 packet.");
    
    kfree_skb(skb);
    END_TEST;
}


//~ bool packet_is_v4_syn(struct packet *packet);
bool test_packet_is_v4_syn( void )
{
    struct sk_buff *skb;

    START_TEST;

    // Set packet type to V4 SYN
	if ((skb = init_packet_type_for_test( PACKET_TYPE_V4_SYN )) == NULL)
    	return false;

    // 
    ASSERT_EQUALS(true, packet_is_v4_syn( skb ), "Test if we detect a V4 SYN packet.");
    
    kfree_skb(skb);
    END_TEST;
}


//~ bool packet_is_v6_syn(struct packet *packet);
bool test_packet_is_v6_syn( void )
{
    struct sk_buff *skb;

    START_TEST;

    // Set packet type to V6 SYN
	if ((skb = init_packet_type_for_test( PACKET_TYPE_V6_SYN )) == NULL)
    	return false;

    // 
    ASSERT_EQUALS(true,  packet_is_v6_syn( skb ), "Test if we detect a V6 SYN packet.");
    
    kfree_skb(skb);
    END_TEST;
}

//~ bool packet_is_v4_fin(struct packet *packet);
bool test_packet_is_v4_fin( void )
{
    struct sk_buff *skb;

    START_TEST;

    // Set packet type to V4 FIN
	if ((skb = init_packet_type_for_test( PACKET_TYPE_V4_FIN )) == NULL)
    	return false;

    // 
    ASSERT_EQUALS(true, packet_is_v4_fin( skb ), "Test if we detect a V4 FIN packet.");
    
    kfree_skb(skb);
    END_TEST;
}


//~ bool packet_is_v6_fin(struct packet *packet);
bool test_packet_is_v6_fin( void )
{
    struct sk_buff *skb;

    START_TEST;

    // Set packet type to V6 FIN
    if ((skb = init_packet_type_for_test( PACKET_TYPE_V6_FIN )) == NULL)
    	return false;

    // 
    ASSERT_EQUALS(true,  packet_is_v6_fin( skb ), "Test if we detect a V6 FIN packet.");
    
    kfree_skb(skb);
    END_TEST;
}


//~ bool packet_is_v4_rst(struct packet *packet);
bool test_packet_is_v4_rst( void )
{
    struct sk_buff *skb;

    START_TEST;

    // Set packet type to V4 RST
    if ((skb = init_packet_type_for_test( PACKET_TYPE_V4_RST )) == NULL)
    	return false;

    // 
    ASSERT_EQUALS(true, packet_is_v4_rst( skb ), "Test if we detect a V4 RST packet.");
    
    kfree_skb(skb);
    END_TEST;
}


//~ bool packet_is_v6_rst(struct packet *packet);
bool test_packet_is_v6_rst( void )
{
    struct sk_buff *skb;

    START_TEST;

    // Set packet type to V6 RST
    if ((skb = init_packet_type_for_test( PACKET_TYPE_V6_RST )) == NULL)
    	return false;

    // 
    ASSERT_EQUALS(true,  packet_is_v6_rst( skb ), "Test if we detect a V6 RST packet.");
    
    kfree_skb(skb);
    END_TEST;
}


//~ bool send_probe_packet(struct sk_buff* skb)
bool test_send_probe_packet( void )
{
	struct sk_buff skb;
	
    START_TEST;

	// TODO: Define here the destination of the packet, instead of doing it in send_probe_packet() function.

    // 
    ASSERT_EQUALS(true,  send_probe_packet( &skb ), "Test if we can send a probe packet.");
    
    END_TEST;
}


//~ int tcp_closed_state_handle(struct sk_buff* skb, struct nf_conntrack_tuple *tuple)
bool test_tcp_closed_state_handle( void )
{
	int ret = 0;
	struct session_entry *session_entry_p;
	struct sk_buff *skb;
	struct nf_conntrack_tuple tuple;
    
    START_TEST;

	/* Input: 
	 * 			V6 SYN 
	 * */
	pr_debug(">>> State: CLOSED\n	Packet seq: V6 SYN    \n");

    nat64_bib_init();
    nat64_session_init();

    // Construct a V6 SYN packet
    if ((skb = init_packet_type_for_test( PACKET_TYPE_V6_SYN )) == NULL)
    	return false;
	// Set packet's tuple.
	init_tuple_for_test_ipv6( &tuple, IPPROTO_TCP );
	// Process CLOSED state
	ret = tcp_closed_state_handle( skb, &tuple );
	ASSERT_EQUALS(NF_ACCEPT, ret, "Check that we processed correctly the CLOSED state.");
	
	// Check we changed to "V6 INIT" state
	session_entry_p = nat64_get_session_entry( &tuple ); // Searches for the Session Table Entry corresponding to the incoming tuple
	if ( session_entry_p == NULL ) // If NO session was found:
	{
		pr_warning("ERROR. Could NOT find an existing SESSION entry for an incoming V6 SYN packet.");
	}
    ASSERT_EQUALS(V6_INIT,  session_entry_p->current_state, "Test if we correctly processed V6 SYN packet.");
pr_debug("session_entry_p->current_state = %d\n", session_entry_p->current_state );
pr_debug("V6_INIT = %d\n", V6_INIT );

    
    nat64_session_destroy();
    nat64_bib_destroy();

    // TODO (alberto) revisar esto
	/* Input: 
	 * 			V4 SYN 
	 * */
	//~ pr_debug(">>> State: CLOSED\n	Packet seq: V4 SYN    \n");

	/* +------+      V4       +-------+
	 * |CLOSED|-----SYN------>|V4 INIT|
	 * +------+               +-------+
	 *                */
	 
	/* FIXME:	Can NOT test this as there's a conflict in the function: 
	 *			bool nat64_add_session_entry()    */  
/*
    nat64_bib_init();
    nat64_session_init();

    // Construct a V4 SYN packet
    init_packet_type_for_test( &skb , PACKET_TYPE_V4_SYN );
	// Set packet's tuple.
	init_tuple_for_test_ipv4( &tuple, IPPROTO_TCP );
	// Process CLOSE state
	ret = tcp_closed_state_handle( &skb, &tuple );
	ASSERT_EQUALS(NF_ACCEPT, ret, "Check that we processed correctly the CLOSED state.");


	// Check we changed to "V4 INIT" state
	session_entry_p = nat64_get_session_entry( &tuple ); // Searches for the Session Table Entry corresponding to the incoming tuple
	if ( session_entry_p == NULL ) // If NO session was found:
	{
		pr_warning("ERROR. Could NOT find an existing SESSION entry for an incoming V4 SYN packet.");
	}
    ASSERT_EQUALS(V4_INIT,  session_entry_p->current_state, "Test if we correctly processed V4 SYN packet.");
pr_debug("session_entry_p->current_state = %d\n", session_entry_p->current_state );
pr_debug("V4_INIT = %d\n", V4_INIT );

*/    
    
    kfree_skb(skb);
    END_TEST;
}


/* FIXME:	Can NOT test this as there's a conflict in the function: 
 *			bool nat64_add_session_entry()    */  
/*
//~ int tcp_v4_init_state_handle(struct packet *packet, struct nf_conntrack_tuple *tuple);
bool test_tcp_v4_init_state_handle( void )
{
    struct packet packet;
    struct nf_conntrack_tuple tuple;
	struct session_entry *session_entry_p;

    struct ipv6_pair ipv6; struct ipv6_pair ipv4;
    
    START_TEST;

    nat64_bib_init();
    nat64_session_init();

    // Init packet
    init_packet_type_for_test( &packet.buffer , PACKET_TYPE_V4_SYN );

    // Init tuple
    init_tuple_for_test_ipv4( &tuple, IPPROTO_TCP);

    // Test case: there's NOT a Session Entry
    ASSERT_EQUALS(NF_DROP, tcp_v4_init_state_handle( &packet, &tuple ),
        "Testing that 'tcp_v4_init_state_handle' correctly drops packets for non-existing STE.");

    // Inject a Session Table Entry
    inject_session_entry( ipv6, ipv4 );

    // Test case: there IS a Session Entry
    ASSERT_EQUALS(NF_ACCEPT, tcp_v4_init_state_handle( &packet, &tuple ),
        "Testing that 'tcp_v4_init_state_handle' correctly accepts packets for existing STE.");

	// Check we changed to "V4 INIT" state
	session_entry_p = nat64_get_session_entry( &tuple ); // Searches for the Session Table Entry corresponding to the incoming tuple
	if ( session_entry_p == NULL ) // If NO session was found:
	{
		pr_warning("ERROR. Could NOT find an existing SESSION entry for an incoming V4 SYN packet.");
	}
    ASSERT_EQUALS(V4_INIT,  session_entry_p->current_state, "Test if we correctly processed V4 SYN packet.");
pr_debug("session_entry_p->current_state = %d\n", session_entry_p->current_state );
pr_debug("V4_INIT = %d\n", V4_INIT );



    nat64_session_destroy();
    nat64_bib_destroy();
    
    END_TEST;
}
*/


//~ int tcp_v6_init_state_handle(struct sk_buff* skb, struct nf_conntrack_tuple *tuple)
bool test_tcp_v6_init_state_handle( void )
{
	int ret = 0;
	struct session_entry *session_entry_p;
	struct sk_buff *skb;
	struct nf_conntrack_tuple tuple;
    
    START_TEST;

	/* Input: 
	 * 			V6 SYN --> V4 SYN 
	 * */
	pr_debug(">>> State: V6 INIT\n	Packet seq: V6 SYN --> V4 SYN    \n");

    nat64_bib_init();
    nat64_session_init();
	
    // Construct a V6 SYN packet
    if ((skb = init_packet_type_for_test( PACKET_TYPE_V6_SYN )) == NULL)
    		return false;
	// Set packet's tuple.
	init_tuple_for_test_ipv6( &tuple, IPPROTO_TCP );
	// Process CLOSED state
	ret = tcp_closed_state_handle( skb, &tuple );
	ASSERT_EQUALS(NF_ACCEPT, ret, "Check that we processed correctly the CLOSED state.");
	kfree_skb(skb);
	
	// Construct a V4 SYN packet
    if ((skb = init_packet_type_for_test( PACKET_TYPE_V4_SYN )) == NULL)
    		return false;
	// Use previous tuple
	// Process V6 INIT state
	ret = tcp_v6_init_state_handle( skb, &tuple );
	ASSERT_EQUALS(NF_ACCEPT, ret, "Check that we processed correctly the V6 INIT state.");
	kfree_skb(skb);
	
	// Check we changed to "ESTABLISHED" state
	session_entry_p = nat64_get_session_entry( &tuple ); // Searches for the Session Table Entry corresponding to the incoming tuple
	if ( session_entry_p == NULL ) // If NO session was found:
	{
		pr_warning("ERROR. Could NOT find an existing SESSION entry for an incoming ESTABLISHED packet.");
	}
    ASSERT_EQUALS(ESTABLISHED,  session_entry_p->current_state, "Test if we correctly processed V4 SYN packet.");
pr_debug("session_entry_p->current_state = %d\n", session_entry_p->current_state );
pr_debug("ESTABLISHED = %d\n", ESTABLISHED );
    
    nat64_session_destroy();
    nat64_bib_destroy();
    
    
    END_TEST;
}


//~ int tcp_established_state_handle(struct packet *packet, struct nf_conntrack_tuple *tuple);
bool test_tcp_established_state_handle( void )
{
	int ret = 0;
	struct session_entry *session_entry_p;
	struct sk_buff *skb;
	struct nf_conntrack_tuple tuple;
    
    START_TEST;

	/* Input: 
	 * 			V6 SYN --> V4 SYN --> V4 FIN 
	 * */
	pr_debug(">>> State: ESTABLISHED\n	Packet seq: V6 SYN --> V4 SYN --> V4 FIN    \n");

    nat64_bib_init();
    nat64_session_init();
	
    // TODO poner if (!init_packet_type_for_test)s.

    // Construct a V6 SYN packet
    if ((skb = init_packet_type_for_test( PACKET_TYPE_V6_SYN )) == NULL)
    	return false;
	// Set packet's tuple.
	init_tuple_for_test_ipv6( &tuple, IPPROTO_TCP );
	// Process CLOSE state
	ret = tcp_closed_state_handle( skb, &tuple );
	ASSERT_EQUALS(NF_ACCEPT, ret, "Check that we processed correctly the CLOSED state.");
	kfree_skb(skb);

	// Construct a V4 SYN packet
	if ((skb = init_packet_type_for_test( PACKET_TYPE_V4_SYN )) == NULL)
		return false;
	// Set packet's tuple.
	init_tuple_for_test_ipv4( &tuple, IPPROTO_TCP );
	// Process V6 INIT state
	ret = tcp_v6_init_state_handle( skb, &tuple );
	ASSERT_EQUALS(NF_ACCEPT, ret, "Check that we processed correctly the V6 INIT state.");
	kfree_skb(skb);

	// Construct a V4 FIN packet
	if ((skb = init_packet_type_for_test( PACKET_TYPE_V4_FIN )) == NULL)
		return false;
	// Use previous tuple
	// Process ESTABLISHED state
	ret = tcp_established_state_handle( skb, &tuple );
	ASSERT_EQUALS(NF_ACCEPT, ret, "Check that we processed correctly the ESTABLISHED state.");
	kfree_skb(skb);
	
	// Check we changed to "V4 FIN RCV" state
	session_entry_p = nat64_get_session_entry( &tuple ); // Searches for the Session Table Entry corresponding to the incoming tuple
	if ( session_entry_p == NULL ) // If NO session was found:
	{
		pr_warning("ERROR. Could NOT find an existing SESSION entry for an incoming V4 FIN packet.");
	}
    ASSERT_EQUALS(V4_FIN_RCV,  session_entry_p->current_state, "Test if we correctly processed V4 FIN packet.");
pr_debug("session_entry_p->current_state = %d\n", session_entry_p->current_state );
pr_debug("V4_FIN_RCV = %d\n", V4_FIN_RCV );
    
    nat64_session_destroy();
    nat64_bib_destroy();
    
	/* Input: 
	 * 			V6 SYN --> V4 SYN --> V6 FIN 
	 * */
	pr_debug(">>> State: ESTABLISHED\n	Packet seq: V6 SYN --> V4 SYN --> V6 FIN    \n");
	 
    nat64_bib_init();
    nat64_session_init();
	
    // Construct a V6 SYN packet
    if ((skb = init_packet_type_for_test( PACKET_TYPE_V6_SYN )) == NULL)
		return false;
	// Set packet's tuple.
	init_tuple_for_test_ipv6( &tuple, IPPROTO_TCP );
	// Process CLOSE state
	ret = tcp_closed_state_handle( skb, &tuple );
	ASSERT_EQUALS(NF_ACCEPT, ret, "Check that we processed correctly the CLOSED state.");
	kfree_skb(skb);

	// Construct a V4 SYN packet
	if ((skb = init_packet_type_for_test( PACKET_TYPE_V4_SYN )) == NULL)
		return false;
	// Set packet's tuple.
	init_tuple_for_test_ipv4( &tuple, IPPROTO_TCP );
	// Process V6 INIT state
	ret = tcp_v6_init_state_handle( skb, &tuple );
	ASSERT_EQUALS(NF_ACCEPT, ret, "Check that we processed correctly the V6 INIT state.");
	kfree_skb(skb);

	// Construct a V6 FIN packet
	if ((skb = init_packet_type_for_test( PACKET_TYPE_V6_FIN )) == NULL)
		return false;
	// Set packet's tuple.
	init_tuple_for_test_ipv6( &tuple, IPPROTO_TCP );
	// Process ESTABLISHED state
	ret = tcp_established_state_handle( skb, &tuple );
	ASSERT_EQUALS(NF_ACCEPT, ret, "Check that we processed correctly the ESTABLISHED state.");
	kfree_skb(skb);
	
	// Check we changed to "V6 FIN RCV" state
	session_entry_p = nat64_get_session_entry( &tuple ); // Searches for the Session Table Entry corresponding to the incoming tuple
	if ( session_entry_p == NULL ) // If NO session was found:
	{
		pr_warning("ERROR. Could NOT find an existing SESSION entry for an incoming V6 FIN packet.");
	}
    ASSERT_EQUALS(V6_FIN_RCV,  session_entry_p->current_state, "Test if we correctly processed V6 FIN packet.");
pr_debug("session_entry_p->current_state = %d\n", session_entry_p->current_state );
pr_debug("V6_FIN_RCV = %d\n", V6_FIN_RCV );
    
    nat64_session_destroy();
    nat64_bib_destroy();
    
	/* Input: 
	 * 			V6 SYN --> V4 SYN --> V6 RST 
	 * */
	pr_debug(">>> State: ESTABLISHED\n	Packet seq: V6 SYN --> V4 SYN --> V6 RST    \n");
	 
    nat64_bib_init();
    nat64_session_init();
	
    // Construct a V6 SYN packet
    if ((skb = init_packet_type_for_test( PACKET_TYPE_V6_SYN )) == NULL)
		return false;
	// Set packet's tuple.
	init_tuple_for_test_ipv6( &tuple, IPPROTO_TCP );
	// Process CLOSE state
	ret = tcp_closed_state_handle( skb, &tuple );
	ASSERT_EQUALS(NF_ACCEPT, ret, "Check that we processed correctly the CLOSED state.");
	kfree_skb(skb);

	// Construct a V4 SYN packet
	 if ((skb = init_packet_type_for_test( PACKET_TYPE_V4_SYN )) == NULL)
		return false;
	// Set packet's tuple.
	init_tuple_for_test_ipv4( &tuple, IPPROTO_TCP );
	// Process V6 INIT state
	ret = tcp_v6_init_state_handle( skb, &tuple );
	ASSERT_EQUALS(NF_ACCEPT, ret, "Check that we processed correctly the V6 INIT state.");
	kfree_skb(skb);

	// Construct a V6 RST packet
	if ((skb = init_packet_type_for_test( PACKET_TYPE_V6_RST )) == NULL)
		return false;
	// Set packet's tuple.
	init_tuple_for_test_ipv6( &tuple, IPPROTO_TCP );
	// Process ESTABLISHED state
	ret = tcp_established_state_handle( skb, &tuple );
	ASSERT_EQUALS(NF_ACCEPT, ret, "Check that we processed correctly the ESTABLISHED state.");
	kfree_skb(skb);
	
	// Check we changed to "TRANS" state
	session_entry_p = nat64_get_session_entry( &tuple ); // Searches for the Session Table Entry corresponding to the incoming tuple
	if ( session_entry_p == NULL ) // If NO session was found:
	{
		pr_warning("ERROR. Could NOT find an existing SESSION entry for an incoming V6 RST packet.");
	}
    ASSERT_EQUALS(TRANS,  session_entry_p->current_state, "Test if we correctly processed V6 RST packet.");
pr_debug("session_entry_p->current_state = %d\n", session_entry_p->current_state );
pr_debug("TRANS = %d\n", TRANS );
    
    nat64_session_destroy();
    nat64_bib_destroy();    
    
    END_TEST;
}


//~ int tcp_v4_fin_rcv_state_handle(struct packet *packet, struct nf_conntrack_tuple *tuple);
bool test_tcp_v4_fin_rcv_state_handle( void )
{
	int ret = 0;
	struct session_entry *session_entry_p;
	struct sk_buff *skb;
	struct nf_conntrack_tuple tuple;
    
    START_TEST;

	/* Input: 
	 * 			V6 SYN --> V4 SYN --> V4 FIN --> V6 FIN 
	 * */
	pr_debug(">>> State: V4 FIN RCV\n	Packet seq: V6 SYN --> V4 SYN --> V4 FIN --> V6 FIN    \n");

    nat64_bib_init();
    nat64_session_init();
	
    // Construct a V6 SYN packet
    if ((skb = init_packet_type_for_test( PACKET_TYPE_V6_SYN )) == NULL)
    		return false;
	// Set packet's tuple.
	init_tuple_for_test_ipv6( &tuple, IPPROTO_TCP );
	// Process CLOSE state
	ret = tcp_closed_state_handle( skb, &tuple );
	ASSERT_EQUALS(NF_ACCEPT, ret, "Check that we processed correctly the CLOSED state.");
	kfree_skb(skb);

	// Construct a V4 SYN packet
    if ((skb = init_packet_type_for_test( PACKET_TYPE_V4_SYN )) == NULL)
    		return false;
    // Set packet's tuple.
	init_tuple_for_test_ipv4( &tuple, IPPROTO_TCP );
	// Process V6 INIT state
	ret = tcp_v6_init_state_handle( skb, &tuple );
	ASSERT_EQUALS(NF_ACCEPT, ret, "Check that we processed correctly the V6 INIT state.");
	kfree_skb(skb);

	// Construct a V4 FIN packet
    if ((skb = init_packet_type_for_test( PACKET_TYPE_V4_FIN )) == NULL)
    		return false;
    // Use previous tuple
	// Process ESTABLISHED state
	ret = tcp_established_state_handle( skb, &tuple );
	ASSERT_EQUALS(NF_ACCEPT, ret, "Check that we processed correctly the ESTABLISHED state.");
	kfree_skb(skb);
	
	// Construct a V6 FIN packet
    if ((skb = init_packet_type_for_test( PACKET_TYPE_V6_FIN )) == NULL)
    		return false;
    // Set packet's tuple.
	init_tuple_for_test_ipv6( &tuple, IPPROTO_TCP );
	// Process V4 FIN RCV state
	ret = tcp_v4_fin_rcv_state_handle( skb, &tuple );
	ASSERT_EQUALS(NF_ACCEPT, ret, "Check that we processed correctly the V4 FIN RCV state.");
	kfree_skb(skb);
	
	// Check we changed to "V4 FIN + V6 FIN RCV" state
	session_entry_p = nat64_get_session_entry( &tuple ); // Searches for the Session Table Entry corresponding to the incoming tuple
	if ( session_entry_p == NULL ) // If NO session was found:
	{
		pr_warning("ERROR. Could NOT find an existing SESSION entry for an incoming V6 FIN packet.");
	}
    ASSERT_EQUALS(V4_FIN_V6_FIN_RCV,  session_entry_p->current_state, "Test if we correctly processed V6 FIN packet.");
pr_debug("session_entry_p->current_state = %d\n", session_entry_p->current_state );
pr_debug("V4_FIN_V6_FIN_RCV = %d\n", V4_FIN_V6_FIN_RCV );
    
    nat64_session_destroy();
    nat64_bib_destroy();


    END_TEST;
}


//~ int tcp_v6_fin_rcv_state_handle(struct packet *packet, struct nf_conntrack_tuple *tuple);
bool test_tcp_v6_fin_rcv_state_handle( void )
{
	int ret = 0;
	struct session_entry *session_entry_p;
	struct sk_buff *skb;
	struct nf_conntrack_tuple tuple;
    
    START_TEST;

	/* Input: 
	 * 			V6 SYN --> V4 SYN --> V6 FIN --> V4 FIN 
	 * */
	pr_debug(">>> State: V6 FIN RCV\n	Packet seq: V6 SYN --> V4 SYN --> V6 FIN --> V4 FIN    \n");

    nat64_bib_init();
    nat64_session_init();
	
    // Construct a V6 SYN packet
    if ((skb = init_packet_type_for_test( PACKET_TYPE_V6_SYN )) == NULL)
    		return false;
	// Set packet's tuple.
	init_tuple_for_test_ipv6( &tuple, IPPROTO_TCP );
	// Process CLOSE state
	ret = tcp_closed_state_handle( skb, &tuple );
	ASSERT_EQUALS(NF_ACCEPT, ret, "Check that we processed correctly the CLOSED state.");
	kfree_skb(skb);

	// Construct a V4 SYN packet
    if ((skb = init_packet_type_for_test( PACKET_TYPE_V4_SYN )) == NULL)
    		return false;
    // Set packet's tuple.
	init_tuple_for_test_ipv4( &tuple, IPPROTO_TCP );
	// Process V6 INIT state
	ret = tcp_v6_init_state_handle( skb, &tuple );
	ASSERT_EQUALS(NF_ACCEPT, ret, "Check that we processed correctly the V6 INIT state.");
	kfree_skb(skb);

	// Construct a V6 FIN packet
    if ((skb = init_packet_type_for_test( PACKET_TYPE_V6_FIN )) == NULL)
    		return false;
    // Set packet's tuple.
	init_tuple_for_test_ipv6( &tuple, IPPROTO_TCP );
	// Process ESTABLISHED state
	ret = tcp_established_state_handle( skb, &tuple );
	ASSERT_EQUALS(NF_ACCEPT, ret, "Check that we processed correctly the ESTABLISHED state.");
	kfree_skb(skb);
	
	// Construct a V4 FIN packet
    if ((skb = init_packet_type_for_test( PACKET_TYPE_V4_FIN )) == NULL)
    		return false;
    // Set packet's tuple.
	init_tuple_for_test_ipv4( &tuple, IPPROTO_TCP );
	// Process V6 FIN RCV state
	ret = tcp_v6_fin_rcv_state_handle( skb, &tuple );
	ASSERT_EQUALS(NF_ACCEPT, ret, "Check that we processed correctly the V6 FIN RCV state.");
	kfree_skb(skb);
	
	// Check we changed to "V4 FIN + V6 FIN RCV" state
	session_entry_p = nat64_get_session_entry( &tuple ); // Searches for the Session Table Entry corresponding to the incoming tuple
	if ( session_entry_p == NULL ) // If NO session was found:
	{
		pr_warning("ERROR. Could NOT find an existing SESSION entry for an incoming V4 FIN packet.");
	}
    ASSERT_EQUALS(V4_FIN_V6_FIN_RCV,  session_entry_p->current_state, "Test if we correctly processed V4 FIN packet.");
pr_debug("session_entry_p->current_state = %d\n", session_entry_p->current_state );
pr_debug("V4_FIN_V6_FIN_RCV = %d\n", V4_FIN_V6_FIN_RCV );
    
    nat64_session_destroy();
    nat64_bib_destroy();

    
    END_TEST;
}

//~ capacitacion itesm.mx

/*
//~ int tcp_V4_FIN_V6_FIN_RCV_state_handle(struct packet *packet, struct nf_conntrack_tuple *tuple);
bool test_tcp_V4_FIN_V6_FIN_RCV_state_handle( void )
{
    
    // TODO: Deal with TIMEOUTs
    
    END_TEST;
}
*/

//~ int tcp_trans_state_handle(struct packet *packet, struct nf_conntrack_tuple *tuple);
bool test_tcp_trans_state_handle( void )
{
	int ret = 0;
	struct session_entry *session_entry_p;
	struct sk_buff *skb;
	struct nf_conntrack_tuple tuple;
    
    START_TEST;
	
	/* Input: 
	 * 			V6 SYN --> V4 SYN --> V6 RST --> V6 SYN 
	 * */
	pr_debug(">>> State: TRANS\n	Packet seq: V6 SYN --> V4 SYN --> V6 RST --> V6 SYN   \n");
	 
    nat64_bib_init();
    nat64_session_init();
	
    // Construct a V6 SYN packet
    if ((skb = init_packet_type_for_test( PACKET_TYPE_V6_SYN )) == NULL)
    		return false;
	// Set packet's tuple.
	init_tuple_for_test_ipv6( &tuple, IPPROTO_TCP );
	// Process CLOSE state
	ret = tcp_closed_state_handle( skb, &tuple );
	ASSERT_EQUALS(NF_ACCEPT, ret, "Check that we processed correctly the CLOSED state.");
	kfree_skb(skb);

	// Construct a V4 SYN packet
    if ((skb = init_packet_type_for_test( PACKET_TYPE_V4_SYN )) == NULL)
    		return false;
	// Set packet's tuple.
	init_tuple_for_test_ipv4( &tuple, IPPROTO_TCP );
	// Process V6 INIT state
	ret = tcp_v6_init_state_handle( skb, &tuple );
	ASSERT_EQUALS(NF_ACCEPT, ret, "Check that we processed correctly the V6 INIT state.");
	kfree_skb(skb);

	// Construct a V6 RST packet
    if ((skb = init_packet_type_for_test( PACKET_TYPE_V6_RST )) == NULL)
    		return false;
	// Set packet's tuple.
	init_tuple_for_test_ipv6( &tuple, IPPROTO_TCP );
	// Process ESTABLISHED state
	ret = tcp_established_state_handle( skb, &tuple );
	ASSERT_EQUALS(NF_ACCEPT, ret, "Check that we processed correctly the ESTABLISHED state.");
	kfree_skb(skb);
		
	// Construct a V6 SYN packet
    if ((skb = init_packet_type_for_test( PACKET_TYPE_V6_SYN )) == NULL)
    		return false;
    // Set packet's tuple.
	init_tuple_for_test_ipv6( &tuple, IPPROTO_TCP );
	// Process TRANS state
	ret = tcp_trans_state_handle( skb, &tuple );
	ASSERT_EQUALS(NF_ACCEPT, ret, "Check that we processed correctly the TRANS state.");
	kfree_skb(skb);
	
	// Check we changed back to "ESTABLISHED" state
	session_entry_p = nat64_get_session_entry( &tuple ); // Searches for the Session Table Entry corresponding to the incoming tuple
	if ( session_entry_p == NULL ) // If NO session was found:
	{
		pr_warning("ERROR. Could NOT find an existing SESSION entry for an incoming V6 SYN packet.");
	}
    ASSERT_EQUALS(ESTABLISHED,  session_entry_p->current_state, "Test if we correctly processed V6 SYN packet.");
pr_debug("session_entry_p->current_state = %d\n", session_entry_p->current_state );
pr_debug("ESTABLISHED = %d\n", ESTABLISHED );
    
    nat64_session_destroy();
    nat64_bib_destroy();    
        
    END_TEST;
}


//~ int tcp(struct packet *packet, struct nf_conntrack_tuple *tuple);
bool test_tcp( void )
{
	int ret = 0;
	struct session_entry *session_entry_p;
	struct sk_buff *skb;
	struct nf_conntrack_tuple tuple;
    
    START_TEST;
	
	/* Input: 
	 * 			V6 SYN --> V4 SYN --> V6 RST --> V6 SYN 
	 * */
	pr_debug(">>> State: TRANS\n	Packet seq: V6 SYN --> V4 SYN --> V6 RST --> V6 SYN   \n");
	 
    nat64_bib_init();
    nat64_session_init();
	
    // Construct a V6 SYN packet
    if ((skb = init_packet_type_for_test( PACKET_TYPE_V6_SYN )) == NULL)
    		return false;
	// Set packet's tuple.
	init_tuple_for_test_ipv6( &tuple, IPPROTO_TCP );
	// Process CLOSED state
	ret = tcp( skb, &tuple );
	ASSERT_EQUALS(NF_ACCEPT, ret, "Check that we processed correctly the CLOSED state.");
	kfree_skb(skb);

	// Construct a V4 SYN packet
    if ((skb = init_packet_type_for_test( PACKET_TYPE_V4_SYN )) == NULL)
    		return false;
	// Set packet's tuple.
	init_tuple_for_test_ipv4( &tuple, IPPROTO_TCP );
	// Process V6 INIT state
	ret = tcp( skb, &tuple );
	ASSERT_EQUALS(NF_ACCEPT, ret, "Check that we processed correctly the V6 INIT state.");
	kfree_skb(skb);

	// Construct a V6 RST packet
    if ((skb = init_packet_type_for_test( PACKET_TYPE_V6_RST )) == NULL)
    		return false;
	// Set packet's tuple.
	init_tuple_for_test_ipv6( &tuple, IPPROTO_TCP );
	// Process ESTABLISHED state
	ret = tcp( skb, &tuple );
	ASSERT_EQUALS(NF_ACCEPT, ret, "Check that we processed correctly the ESTABLISHED state.");
	kfree_skb(skb);
		
	// Construct a V6 SYN packet
    if ((skb = init_packet_type_for_test( PACKET_TYPE_V6_SYN )) == NULL)
    		return false;
	// Set packet's tuple.
	init_tuple_for_test_ipv6( &tuple, IPPROTO_TCP );
	// Process TRANS state
	ret = tcp( skb, &tuple );
	ASSERT_EQUALS(NF_ACCEPT, ret, "Check that we processed correctly the TRANS state.");
	kfree_skb(skb);
	
	// Check we changed back to "ESTABLISHED" state
	session_entry_p = nat64_get_session_entry( &tuple ); // Searches for the Session Table Entry corresponding to the incoming tuple
	if ( session_entry_p == NULL ) // If NO session was found:
	{
		pr_warning("ERROR. Could NOT find an existing SESSION entry for an incoming V6 SYN packet.");
	}
    ASSERT_EQUALS(ESTABLISHED,  session_entry_p->current_state, "Test if we correctly processed V6 SYN packet.");
pr_debug("session_entry_p->current_state = %d\n", session_entry_p->current_state );
pr_debug("ESTABLISHED = %d\n", ESTABLISHED );
    
    nat64_session_destroy();
    nat64_bib_destroy();    
    
    END_TEST;
}



/* END: filtering_tcp.c */





int __init filtering_test_init(void)
{
    START_TESTS("test_filtering.c");
    
    pr_debug("\n\n\n");
    pr_debug("\n\nNAT64 %s TEST module inserted!", "filtering_test");


    // Initialize the NAT configuration for the tests.
    nat64_config_init();

    /*      UDP & ICMP      */
    CALL_TEST(test_transport_address_ipv4(), "test_transport_address_ipv4");
    CALL_TEST(test_transport_address_ipv6(), "test_transport_address_ipv6");
    CALL_TEST(test_extract_ipv4_from_ipv6(), "test_extract_ipv4_from_ipv6");
    CALL_TEST(test_embed_ipv4_in_ipv6(), "test_embed_ipv4_in_ipv6");
    //~ CALL_TEST(test_get_icmpv4_identifier(), "test_get_icmpv4_identifier");
    CALL_TEST(test_allocate_ipv4_transport_address(), "test_allocate_ipv4_transport_address");
    //~ CALL_TEST(test_allocate_ipv4_transport_address_digger(), "test_allocate_ipv4_transport_address_digger");
    CALL_TEST(test_ipv6_udp(), "test_ipv6_udp");
    CALL_TEST(test_ipv4_udp(), "test_ipv4_udp");
    CALL_TEST(test_ipv6_icmp6(), "test_ipv6_icmp6");
    CALL_TEST(test_ipv4_icmp4(), "test_ipv4_icmp4");
    //~ CALL_TEST(test_send_icmp_error_message(), "test_send_icmp_error_message"); // Not implemented yet!
    CALL_TEST(test_filtering_and_updating(), "test_filtering_and_updating");
    
    
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
    //~ CALL_TEST(test_clean_function_simple(), "test_clean_function_simple");  // Not implemented yet!
    CALL_TEST(test_tcp_closed_state_handle(), "test_tcp_closed_state_handle");
    //~ CALL_TEST(test_tcp_v4_init_state_handle(), "test_tcp_v4_init_state_handle"); // Not implemented yet!
    CALL_TEST(test_tcp_v6_init_state_handle(), "test_tcp_v6_init_state_handle");
    CALL_TEST(test_tcp_established_state_handle(), "test_tcp_established_state_handle");
    CALL_TEST(test_tcp_v4_fin_rcv_state_handle(), "test_tcp_v4_fin_rcv_state_handle");
    CALL_TEST(test_tcp_v6_fin_rcv_state_handle(), "test_tcp_v6_fin_rcv_state_handle");
    //~ CALL_TEST(test_tcp_v4_fin_v6_fin_rcv_state_handle(), "test_tcp_v4_fin_v6_fin_rcv_state_handle"); // Not implemented yet!
    CALL_TEST(test_tcp_trans_state_handle(), "test_tcp_trans_state_handle");
    CALL_TEST(test_tcp(), "test_tcp");
  
    /* A non 0 return means a test failed; module can't be loaded. */
    END_TESTS;
}

void __exit filtering_test_exit(void)
{

    pr_debug("NAT64 %s TEST module removed!\n\n\n", "filtering_test");
}

module_init(filtering_test_init);
module_exit(filtering_test_exit);


