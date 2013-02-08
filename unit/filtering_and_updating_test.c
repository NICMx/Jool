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

#include "nat64/unit_test.h"

// What are we testing?
#include "nat64/pool4.h"
#include "nat64/config.h"
#include "nat64/config_validation.h"
#include "filtering_and_updating.c"

extern struct config_struct cs;

/* We are testing: filtering.c 
 * BEGIN: filtering.c */

#define INIT_TUPLE_IPV4_SRC_ADDR    "192.168.2.1"
#define INIT_TUPLE_IPV6_SRC_ADDR    "2001:db8:c0ca:1::1"
#define INIT_TUPLE_IPV4_DST_ADDR    "192.168.2.44"
#define INIT_TUPLE_IPV6_DST_ADDR    "64:ff9b::192.168.2.44"
#define INIT_TUPLE_IPV6_ICMP_ID     1024
#define INIT_TUPLE_IPV4_ICMP_ID     ( INIT_TUPLE_IPV6_ICMP_ID  )
#define INIT_TUPLE_IPV6_SRC_PORT    1080
#define INIT_TUPLE_IPV6_DST_PORT    1081
#define INIT_TUPLE_IPV4_SRC_PORT    1024
#define INIT_TUPLE_IPV4_DST_PORT    1081
void init_tuple_for_test_ipv6(struct nf_conntrack_tuple *tuple, u_int8_t l4protocol)
{
    struct in6_addr addr6;

    str_to_addr6(INIT_TUPLE_IPV6_SRC_ADDR, &addr6);
    tuple->ipv6_src_addr =  addr6;

    str_to_addr6(INIT_TUPLE_IPV6_DST_ADDR, &addr6);
    tuple->ipv6_dst_addr =  addr6;

    tuple->L3_PROTOCOL = NFPROTO_IPV6;
    tuple->L4_PROTOCOL = l4protocol;
    
    if ( l4protocol == IPPROTO_ICMPV6 || l4protocol == IPPROTO_ICMP)
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

    str_to_addr4(INIT_TUPLE_IPV4_DST_ADDR, &addr);
    tuple->ipv4_src_addr =  addr;

    str_to_addr4(INIT_TUPLE_IPV4_SRC_ADDR, &addr);
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

#define SKB_PAYLOAD 22
struct sk_buff* init_skb_for_test(  struct nf_conntrack_tuple *tuple, 
                                    struct sk_buff *skb_old, u_int8_t protocol )
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
            log_warning("Invalid protocol 1: %d", protocol);
            skb = NULL;
            return NULL;
    }

    l3_len = sizeof(struct iphdr);
    skb = alloc_skb(LL_MAX_HEADER + l3_len + l4_len + SKB_PAYLOAD, GFP_ATOMIC);
    if (!skb) {
        log_warning("  New packet allocation failed.");
        skb = NULL;
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
            break;
        case IPPROTO_UDP:
            udp_header = udp_hdr(skb);
            memset(udp_header, 0, l4_len);
            
            udp_header->source = tuple->src_port;
            udp_header->dest = tuple->dst_port;
            udp_header->len = sizeof(struct udphdr); // Not sure if it's correct
            udp_header->check = 0; // Not sure if it's correct
            break;
        case IPPROTO_ICMP:
            icmp_header = icmp_hdr(skb);
            memset(icmp_header, 0, l4_len);
			icmp_header->type = ICMP_ECHO;
			//~ icmp_header->type = ICMP_ECHOREPLY
			//~ icmp6_header->icmp6_type = ICMPV6_ECHO_REQUEST;
			//~ icmp6_header->icmp6_type = ICMPV6_ECHO_REPLY;
            break;
        default:
            log_warning("Invalid protocol 2."); // This will never be reached, remove it?
            skb = NULL;
            return NULL;
    }
    // TODO: Choose one of the above and below aproaches: ^ or v 
    //~ memset(skb_transport_header(skb), 0, l4_len);

    ip_header->version = 4;
    ip_header->ihl = (sizeof(struct iphdr))/4 ;
    ip_header->tos = 0;
    //~ ip_header->tot_len = htons(sizeof(struct iphdr));
    ip_header->tot_len = htons(l3_len + l4_len + SKB_PAYLOAD);
    ip_header->id = htons(111);
    ip_header->frag_off = 0;
    ip_header->ttl = 111;   // <--- What value should be used?
    ip_header->protocol = protocol;
    ip_header->check = 0;
    //~ skb_forward_csum(skb);

    ip_header->saddr = tuple->ipv4_src_addr.s_addr;
    ip_header->daddr = tuple->ipv4_dst_addr.s_addr;

    // TODO: Should we set the port in the transport header?
    skb->protocol = htons(ETH_P_IP);

    return skb;
}

#define IPV4_FIRST_POOL_ADDRESS     "192.168.2.1"
#define init_pool() { struct in_addr addr4; \
                      assert_true(pool4_init(true), "See if we can initialize the IPv4 pool." ); \
                      str_to_addr4(IPV4_FIRST_POOL_ADDRESS, &addr4); \
                      assert_equals_int(RESPONSE_SUCCESS, pool4_register(&addr4), "Try to create a new entry in the pool address"); }


#define IPV6_INJECT_BIB_ENTRY_SRC_ADDR  "2001:db8:c0ca:1::1"
#define IPV6_INJECT_BIB_ENTRY_SRC_PORT  1080
#define IPV4_INJECT_BIB_ENTRY_DST_ADDR  "192.168.2.1"
#define IPV4_INJECT_BIB_ENTRY_DST_PORT  1082
#define INIT_TUPLE_ICMP_ID              10
bool inject_bib_entry( struct bib_entry *bib_e, u_int8_t l4protocol )
{
    struct ipv4_tuple_address ta_ipv4;
    struct ipv6_tuple_address ta_ipv6;

    struct in_addr addr4;
    struct in6_addr addr6;

    str_to_addr4(IPV4_INJECT_BIB_ENTRY_DST_ADDR, &addr4);
    str_to_addr6(IPV6_INJECT_BIB_ENTRY_SRC_ADDR, &addr6);


    if ( l4protocol == IPPROTO_ICMP || l4protocol == IPPROTO_ICMPV6 )
    {
        transport_address_ipv4( addr4, htons( INIT_TUPLE_ICMP_ID ), &ta_ipv4 );
        transport_address_ipv6( addr6, htons( INIT_TUPLE_ICMP_ID ), &ta_ipv6 );        
    }
    else
    {
        transport_address_ipv4( addr4, htons( IPV4_INJECT_BIB_ENTRY_DST_PORT ), &ta_ipv4 );
        transport_address_ipv6( addr6, htons( IPV6_INJECT_BIB_ENTRY_SRC_PORT ), &ta_ipv6 );
    }
    bib_e = nat64_create_bib_entry( &ta_ipv4, &ta_ipv6);
    
    return nat64_add_bib_entry( bib_e, l4protocol );
}

#define IPV6_INIT_SESSION_ENTRY_SRC_ADDR  "2001:db8:c0ca:1::1"
#define IPV6_INIT_SESSION_ENTRY_SRC_PORT  1080
#define IPV6_INIT_SESSION_ENTRY_DST_ADDR  "64:ff9b::192.168.2.44"
#define IPV6_INIT_SESSION_ENTRY_DST_PORT  1080
#define IPV4_INIT_SESSION_ENTRY_SRC_ADDR  "192.168.2.1"
#define IPV4_INIT_SESSION_ENTRY_SRC_PORT  1082
#define IPV4_INIT_SESSION_ENTRY_DST_ADDR  "192.168.2.44"
#define IPV4_INIT_SESSION_ENTRY_DST_PORT  1082
void init_session_entry( u_int8_t l4protocol, struct session_entry *se )
{
    struct in_addr src4;
    struct in_addr dst4;
    struct in6_addr src6;
    struct in6_addr dst6;
    
    str_to_addr6(IPV6_INIT_SESSION_ENTRY_SRC_ADDR, &src6);
    str_to_addr6(IPV6_INIT_SESSION_ENTRY_DST_ADDR, &dst6);
    str_to_addr4(IPV4_INIT_SESSION_ENTRY_SRC_ADDR, &src4);
    str_to_addr4(IPV4_INIT_SESSION_ENTRY_DST_ADDR, &dst4);

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
    se->l4protocol = l4protocol;
    se->current_state = CLOSED;
}



#define IPV4_TRANSPORT_ADDR     "192.168.1.4"
#define IPV4_TRANSPORT_PORT     1081
bool test_transport_address_ipv4( void )
{
    struct in_addr addr;
    struct ipv4_tuple_address ta;
    bool success = true;

    str_to_addr4(IPV4_TRANSPORT_ADDR, &addr);
    transport_address_ipv4( addr, htons( (__be16)IPV4_TRANSPORT_PORT ), &ta );
    
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
    str_to_addr6(IPV6_TRANSPORT_ADDR, &addr6);
    transport_address_ipv6( addr6, htons( (__be16)IPV6_TRANSPORT_PORT ), &ta );
    
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

    // Convert the IPv6 address to binary
    str_to_addr6(IPV6_EXTRACT_ADDR, &addr6);
    
    success &= assert_true(pool6_init() , "Init IPv6 pool.");
    
    success &= assert_true(extract_ipv4(&addr6, &extracted4) , 
        "Check that an IPv4 address can be extracted from an IPv6 address.");

    str_to_addr4(IPV4_EXTRACTED_ADDR, &correct4);
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

    // Convert to binary the IPv4 address to embed
    str_to_addr4(IPV4_EMBEDDABLE_ADDR, &embeddable4);
    
    success &= assert_true(pool6_init() , "Init IPv6 pool.");

    success &= assert_true(append_ipv4( &embeddable4, &embed6 ) , 
        "Check that we can embed an IPv4 address inside of an IPv6 address correctly.");

    // Verify the output
    str_to_addr6(IPV6_EMBEDDED_ADDR, &embedded6);
    success &= assert_equals_ipv6( &embed6 , &embedded6 , 
        "Verify that the IPv4 was embedded into a IPv6 address is correct.");
//~ pr_debug(" - expected: %pI6c , actual: %pI6c", &embedded6 , &embed6 );
    
    pool6_destroy();

    return success;
}


#define IPV6_ALLOCATE_SRC_ADDR  "2001:db8:c0ca:1::1"
#define IPV6_ALLOCATE_SRC_PORT  1024
#define IPV4_ALLOCATED_ADDR     "192.168.2.1"
//~ #define IPV4_ALLOCATED_ADDR		POOL4_DEF[0]
#define IPV4_ALLOCATED_PORT_ICMP     (IPV6_ALLOCATE_SRC_PORT )  // <-- 1024
#define IPV4_ALLOCATED_PORT     (IPV6_ALLOCATE_SRC_PORT +1 )  // <-- 1025
bool test_allocate_ipv4_transport_address( void )
{
    struct in_addr expected_addr;
    u_int8_t protocol;
    
    struct nf_conntrack_tuple tuple;
    struct ipv4_tuple_address new_ipv4_transport_address;

    struct bib_entry bib_e;

    bool success = true;

	//~ unsigned char *pool4_addresses_str[] = POOL4_DEF;

    
    nat64_bib_init();

    // 
    protocol = IPPROTO_ICMP;
    init_pool();
    success &= assert_true(pool6_init() , "Init IPv6 pool.");

    success &= assert_true(inject_bib_entry( &bib_e, protocol ), "Trying to insert a BIB entry for do some tests.");

    init_tuple_for_test_ipv4(&tuple, protocol);

    str_to_addr4(IPV4_ALLOCATED_ADDR, &expected_addr);

    success &= assert_true(allocate_ipv4_transport_address(&tuple, protocol, &new_ipv4_transport_address), 
        "Check that we can allocate a brand new IPv4 transport address for ICMP.");
   
    success &= assert_equals_ipv4(&expected_addr , &new_ipv4_transport_address.address,
        "Check that the allocated IPv4 address is correct for ICMP.");

    success &= assert_equals_u16( IPV4_ALLOCATED_PORT_ICMP, new_ipv4_transport_address.l4_id,
        "Check that the allocated IPv4 port is correct for ICMP.");

    //
    protocol = IPPROTO_TCP;
    init_pool();

    success &= assert_true(inject_bib_entry( &bib_e, protocol ), "Trying to insert a BIB entry for do some tests.");
    init_tuple_for_test_ipv4(&tuple, protocol);

    str_to_addr4(IPV4_ALLOCATED_ADDR, &expected_addr);

    success &= assert_true(allocate_ipv4_transport_address(&tuple, protocol, &new_ipv4_transport_address), 
        "Check that we can allocate a brand new IPv4 transport address for TCP.");
   
    success &= assert_equals_ipv4(&expected_addr , &new_ipv4_transport_address.address,
        "Check that the allocated IPv4 address is correct for TCP.");

pr_debug("  IPV4_ALLOCATED_PORT=%d , new_ipv4_transport_address.l4_id=%d", IPV4_ALLOCATED_PORT, new_ipv4_transport_address.l4_id );
    success &= assert_equals_u16( IPV4_ALLOCATED_PORT, new_ipv4_transport_address.l4_id,
        "Check that the allocated IPv4 port is correct for TCP.");
    
    //
    protocol = IPPROTO_UDP;
    init_pool();

    success &= assert_true(inject_bib_entry( &bib_e, protocol ), "Trying to insert a BIB entry for do some tests.");
    init_tuple_for_test_ipv4(&tuple, protocol);

    str_to_addr4(IPV4_ALLOCATED_ADDR, &expected_addr);

    success &= assert_true(allocate_ipv4_transport_address(&tuple, protocol, &new_ipv4_transport_address), 
        "Check that we can allocate a brand new IPv4 transport address for UDP.");
   
    success &= assert_equals_ipv4(&expected_addr , &new_ipv4_transport_address.address,
        "Check that the allocated IPv4 address is correct for UDP.");

    success &= assert_equals_u16( IPV4_ALLOCATED_PORT, new_ipv4_transport_address.l4_id,
        "Check that the allocated IPv4 port is correct for UDP.");

    nat64_bib_destroy();
    pool4_destroy();
    
    return success;
}


#define IPV4_ALLOCATED_PORT_DIGGER  1024
bool test_allocate_ipv4_transport_address_digger( void )
{
    struct in_addr expected_addr;
    u_int8_t protocol;
    struct nf_conntrack_tuple tuple;
    struct ipv4_tuple_address new_ipv4_transport_address;
    struct bib_entry bib_e;
    bool success = true;

    nat64_bib_init();

pr_debug("IPPROTO_ICMP : %d", IPPROTO_ICMP);
    protocol = IPPROTO_ICMP;

    success &= assert_true(inject_bib_entry( &bib_e, protocol ), 
		"Trying to insert a BIB entry for do some tests.");

pr_debug("IPPROTO_TCP : %d", IPPROTO_TCP);
    protocol = IPPROTO_TCP;
    init_pool();
    
    success &= assert_true(inject_bib_entry( &bib_e, protocol ), 
		"Trying to insert a BIB entry for do some tests.");
    
pr_debug("IPPROTO_UDP : %d", IPPROTO_UDP);
    protocol = IPPROTO_UDP;

    init_tuple_for_test_ipv6(&tuple, protocol);

    str_to_addr4(IPV4_ALLOCATED_ADDR, &expected_addr);

pr_debug("  allocate_ipv4_transport_address_digger ");
    success &= assert_true(allocate_ipv4_transport_address_digger(&tuple, protocol, &new_ipv4_transport_address), 
        "Check that we can allocate a brand new IPv4 transport address for UDP.");

pr_debug("  ipv4_addr_equals ");
    success &= assert_true( ipv4_addr_equals (&new_ipv4_transport_address.address, &expected_addr) ,
        "Check that the allocated IPv4 address is correct for UDP.");

    success &= assert_equals_u16( (__be16)(IPV4_ALLOCATED_PORT_DIGGER ), new_ipv4_transport_address.l4_id,
        "Check that the allocated IPv4 port is correct for UDP.");

    nat64_bib_destroy();
    pool4_destroy();

    return success;
}


bool test_ipv6_udp( void )
{
    u_int8_t protocol;
    struct nf_conntrack_tuple tuple;
    struct sk_buff *skb = NULL;
    
    bool success = true;

    protocol = IPPROTO_UDP;

    init_pool();
    filtering_init();
    nat64_bib_init();
    nat64_session_init();

    // Init tuple
    init_tuple_for_test_ipv6( &tuple, protocol );
    // Init skb
    skb = init_skb_for_test( &tuple, skb, protocol );
    success &= assert_not_null(skb, "init_skb_for_test");        

    // Create Bib & Session:
    success &= assert_equals_int(NF_ACCEPT, ipv6_udp( skb, &tuple ), 
		"See if we can process correctly an IPv6 UDP packet.");

    nat64_session_destroy();
    nat64_bib_destroy();
    pool4_destroy();
    kfree_skb(skb);
    
    return success;
}

bool test_ipv4_udp( void )
{
    u_int8_t protocol;
    struct nf_conntrack_tuple tuple;
    struct sk_buff* skb = NULL;

    bool success = true;

    nat64_bib_init();
    nat64_session_init();
    filtering_init();

    protocol = IPPROTO_UDP;

    // Init tuple
    init_tuple_for_test_ipv4( &tuple , protocol  );
    // Init skb
    skb = init_skb_for_test( &tuple, skb, protocol );
    success &= assert_not_null(skb, "init_skb_for_test");        

    // Discard un-expected IPv4 packets.
pr_debug(" Discard un-expected IPv4 packets");
    success &= assert_equals_int(NF_DROP, ipv4_udp( skb, &tuple ), 
		"See if we discard an IPv4 UDP packet, which tries to start a communication.");

pr_debug(" Process an expected packet ");
    // Process an expected packet

    // Create Bib & Session:
pr_debug("  > create a new entry in the pool address");
    init_pool();

pr_debug("  > create a new entry in the BIB-Session Tables by processing an IPv6 UDP packet");
    init_tuple_for_test_ipv6( &tuple , protocol  );    
    success &= assert_equals_int(NF_ACCEPT, ipv6_udp( skb, &tuple ), 
		"See if we can process correctly an IPv6 UDP packet.");
    
    init_tuple_for_test_ipv4( &tuple , protocol  );

pr_debug("  > process correctly an expected IPv4 UDP packet");
    success &= assert_equals_int(NF_ACCEPT, ipv4_udp( skb, &tuple ), 
		"See if we can process correctly an expected IPv4 UDP packet.");

    pool4_destroy();
    nat64_session_destroy();
    nat64_bib_destroy();
    kfree_skb(skb);
    
    return success;
}

bool test_ipv6_icmp6( void )
{
    u_int8_t protocol;
    struct nf_conntrack_tuple tuple;
    struct sk_buff *skb = NULL;
    
    bool success = true;

    //~ protocol = IPPROTO_ICMPV6;
    protocol = IPPROTO_ICMP;

    nat64_bib_init();
    nat64_session_init();
    filtering_init();

    init_pool();

    // Init tuple
    init_tuple_for_test_ipv6( &tuple , protocol );
    // Init skb
    skb = init_skb_for_test( &tuple, skb, protocol );
    success &= assert_not_null(skb, "init_skb_for_test");        

    // Create Bib & Session:
    success &= assert_equals_int(NF_ACCEPT,  ipv6_icmp6(skb, &tuple), 
		"See if we can process correctly an IPv6 ICMP packet.");

    nat64_session_destroy();
    nat64_bib_destroy();
    pool4_destroy();
    kfree_skb(skb);
      
    return success;
}

bool test_ipv4_icmp4( void )
{
    u_int8_t protocol;
    struct nf_conntrack_tuple tuple;
    struct sk_buff* skb = NULL;
    
    bool success = true;

    protocol = IPPROTO_ICMP;

    nat64_bib_init();
    nat64_session_init();
    filtering_init();

    init_pool();

    // Init tuple
    init_tuple_for_test_ipv4( &tuple , protocol );
    // Init skb
    skb = init_skb_for_test( &tuple, skb, protocol );
    success &= assert_not_null(skb, "init_skb_for_test");        

pr_debug(" * Discard un-expected IPv4 packets");
    // Discard un-expected IPv4 packets.
    success &= assert_equals_int(NF_DROP, ipv4_icmp4( skb, &tuple ), 
		"See if we discard an IPv4 ICMP packet, which tries to start a communication.");
    kfree_skb(skb);

pr_debug(" * Process an expected packet");
    // Process an expected packet
    
pr_debug(" * Create Bib & Session");
    // Create Bib & Session:
    //~ protocol = IPPROTO_ICMPV6;
    protocol = IPPROTO_ICMP;
    init_tuple_for_test_ipv6( &tuple , protocol );
    // Init skb
    skb = init_skb_for_test( &tuple, skb, protocol );
    success &= assert_not_null(skb, "init_skb_for_test");        
    success &= assert_equals_int(NF_ACCEPT, ipv6_icmp6(skb, &tuple ), 
		"See if we can process correctly an IPv6 ICMP packet.");
    kfree_skb(skb);

pr_debug(" * Process an expected IPv4 packets.");
    // Process an expected IPv4 packets.
    protocol = IPPROTO_ICMP;
    init_tuple_for_test_ipv4( &tuple , protocol );
    // Init skb
    skb = init_skb_for_test( &tuple, skb, protocol );
    success &= assert_not_null(skb, "init_skb_for_test");        
    success &= assert_equals_int(NF_ACCEPT, ipv4_icmp4( skb, &tuple ), 
		"See if we can process correctly an expected IPv4 ICMP packet.");

pr_debug(" * Destroy everything X-| ");
    nat64_session_destroy();
    nat64_bib_destroy();
    pool4_destroy();

    kfree_skb(skb);
    
    return success;
}
/*
#define BUFFER_SIZE_ICMP 22
bool test_send_icmp_error_message( void )
{
    struct nf_conntrack_tuple tuple;
    u_int8_t protocol;
    u_int8_t type;
    u_int8_t code;

    struct sk_buff *skb = NULL;

    bool success = true;

    protocol = IPPROTO_ICMP;

    // Init tuple
    init_tuple_for_test_ipv4( &tuple , protocol );
    // Init skb
    //~ if ( (skb = init_skb_for_test( &tuple, skb, protocol ) ) == NULL )
    //~ skb = init_skb_for_test( &tuple, skb, protocol );
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


    pr_debug("Test if we can send an ICMP error packet: DESTINATION_UNREACHABLE, HOST_UNREACHABLE");
    type = DESTINATION_UNREACHABLE;
    code = HOST_UNREACHABLE;
    send_icmp_error_message( skb, type, code);

    pr_debug("Test if we can send an ICMP error packet: DESTINATION_UNREACHABLE, ADDRESS_UNREACHABLE");
    type = DESTINATION_UNREACHABLE;
    code = ADDRESS_UNREACHABLE;
    send_icmp_error_message( skb, type, code);

    pr_debug("Test if we can send an ICMP error packet: DESTINATION_UNREACHABLE, COMMUNICATION_ADMINISTRATIVELY_PROHIBITED");
    type = DESTINATION_UNREACHABLE;
    code = COMMUNICATION_ADMINISTRATIVELY_PROHIBITED;
    send_icmp_error_message( skb, type, code);

    kfree_skb(skb);


    // Init tuple
    init_tuple_for_test_ipv6( &tuple , protocol );
    // Init skb
    skb = init_skb_for_test( &tuple, skb, protocol );
    success &= assert_not_null(skb, "init_skb_for_test");        

    pr_debug("Test if we can send an ICMPv6 error packet: DESTINATION_UNREACHABLE, HOST_UNREACHABLE");
    type = DESTINATION_UNREACHABLE;
    code = HOST_UNREACHABLE;
    send_icmp_error_message( skb, type, code);

    pr_debug("Test if we can send an ICMPv6 error packet: DESTINATION_UNREACHABLE, ADDRESS_UNREACHABLE");
    type = DESTINATION_UNREACHABLE;
    code = ADDRESS_UNREACHABLE;
    send_icmp_error_message( skb, type, code);

    pr_debug("Test if we can send an ICMPv6 error packet: DESTINATION_UNREACHABLE, COMMUNICATION_ADMINISTRATIVELY_PROHIBITED");
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
    int ret;
    u_int8_t protocol = IPPROTO_UDP;
    struct nf_conntrack_tuple tuple;
    struct sk_buff *skb = NULL;
    struct in_addr addr4;
    struct in6_addr addr6;
    
    bool success = true;

    nat64_bib_init();
    nat64_session_init();
    
    init_pool();

    // >>> Errores de ICMP no deben afectar las tablas
    pr_debug(" >>> Errores de ICMP no deben afectar las tablas ");
    // IPv4 incoming packet
    protocol = IPPROTO_ICMP;
    // Init tuple
    init_tuple_for_test_ipv4( &tuple , protocol );
    // Init skb
    skb = init_skb_for_test( &tuple, skb, protocol );
    success &= assert_not_null(skb, "init_skb_for_test");        
    icmp_hdr(skb)->type = ICMP_DEST_UNREACH; // Set a error packet
    // Process a tuple generated from a incoming IPv6 packet:
    success &= assert_equals_int(NF_ACCEPT,  filtering_and_updating( skb, &tuple), 
		"See if we can forward an IPv4 ICMP packet.");
    kfree_skb(skb);

    // Tests UDP
    protocol = IPPROTO_UDP;

    // >>> Get rid of hairpinning loop 
    pr_debug(" >>> Get rid of hairpinning loop ");
    // IPv6 incoming packet
    // Init tuple
    init_tuple_for_test_ipv6( &tuple , protocol );
    // Init skb
    skb = init_skb_for_test( &tuple, skb, protocol );
    success &= assert_not_null(skb, "init_skb_for_test");        
    // Add pref64
    str_to_addr6(INIT_TUPLE_IPV6_HAIR_LOOP_SRC_ADDR , &addr6);
    tuple.ipv6_src_addr = addr6; 
    // Process a tuple generated from a incoming IPv6 packet:
    success &= assert_equals_int(NF_DROP,  filtering_and_updating( skb, &tuple), 
		"See if we can get rid of hairpinning loop in IPv6.");
    kfree_skb(skb);

    // >>> Get rid of unwanted packets
    pr_debug(" >>> Get rid of unwanted packets ");
    // IPv6 incoming packet
    // Init tuple
    init_tuple_for_test_ipv6( &tuple , protocol );
    // Init skb
    skb = init_skb_for_test( &tuple, skb, protocol );
    success &= assert_not_null(skb, "init_skb_for_test");        
    // Unwanted packet
    str_to_addr6(INIT_TUPLE_IPV6_HAIR_LOOP_DST_ADDR , &addr6);
    tuple.ipv6_dst_addr = addr6; 
    // Process a tuple generated from a incoming IPv6 packet:
    success &= assert_equals_int(NF_DROP,  filtering_and_updating( skb, &tuple), 
		"See if we can get rid of unwanted packets in IPv6.");
    kfree_skb(skb);

    // >>> Get rid of un-expected packets, destined to an address not in pool
    pr_debug(" >>> Get rid of un-expected packets, destined to an address not in pool");
    // IPv4 incoming packet
    // Init tuple
    init_tuple_for_test_ipv4( &tuple , protocol );
    // Init skb
    skb = init_skb_for_test( &tuple, skb, protocol );
    success &= assert_not_null(skb, "init_skb_for_test");        
    // Packet destined to an address not in pool
    str_to_addr4(INIT_TUPLE_IPV4_NOT_POOL_DST_ADDR , &addr4);
    tuple.ipv4_dst_addr = addr4; 
    // Process a tuple generated from a incoming IPv6 packet:
    success &= assert_equals_int(NF_DROP,  filtering_and_updating( skb, &tuple), 
		"See if we can get rid of packet destined to an address not in pool.");
    kfree_skb(skb);

    // >>> IPv4 incoming packet --> reject
    pr_debug(" >>> IPv4 incoming packet --> reject");
    // IPv4 incoming packet
    // Init tuple
    init_tuple_for_test_ipv4( &tuple , protocol );
    // Init skb
    skb = init_skb_for_test( &tuple, skb, protocol );
    success &= assert_not_null(skb, "init_skb_for_test");        
    // Process a tuple generated from a incoming IPv6 packet:
    success &= assert_equals_int(NF_DROP,  filtering_and_updating( skb, &tuple), 
		"See if we can do reject an incoming IPv4 UDP packet.");
    kfree_skb(skb);

    // >>> IPv6 incoming packet --> accept
    pr_debug(" >>> IPv6 incoming packet --> accept");
    // IPv6 incoming packet
    // Init tuple
    init_tuple_for_test_ipv6( &tuple , protocol );
    // Init skb
    skb = init_skb_for_test( &tuple, skb, protocol );
    success &= assert_not_null(skb, "init_skb_for_test");        
    // Process a tuple generated from a incoming IPv6 packet:
    ret = filtering_and_updating( skb, &tuple);
    success &= assert_equals_int(NF_ACCEPT,  ret, "See if we can do filtering and updating on an incoming IPv6 UDP packet.");
    kfree_skb(skb);

    // >>> IPv4 incoming packet --> accept
    pr_debug(" >>> IPv4 incoming packet --> accept");
    // IPv4 incoming packet
    // Init tuple
    init_tuple_for_test_ipv4( &tuple , protocol );
    // Init skb
    skb = init_skb_for_test( &tuple, skb, protocol );
    success &= assert_not_null(skb, "init_skb_for_test");        
    // Process a tuple generated from a incoming IPv6 packet:
    success &= assert_equals_int(NF_ACCEPT,  filtering_and_updating( skb, &tuple), 
		"See if we can do filtering and updating on an incoming IPv4 UDP packet.");

    nat64_session_destroy();
    nat64_bib_destroy();
    pool4_destroy();
    kfree_skb(skb);
    
    return success;
}

/* END: filtering.c */


/* We are testing: filtering:tcp 
 * BEGIN: filtering:tcp */


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

bool test_send_probe_packet( void )
{
    struct session_entry se;
    
    bool success = true;

    init_session_entry( IPPROTO_TCP, &se );

    pr_debug("NAT64: Sending a packet, catch it!");
    success &= assert_true( send_probe_packet( &se ), "Test if we can send a probe packet.");
    
    return success;
}


bool test_tcp_closed_state_handle( void )
{
    struct session_entry *session_entry_p;
    struct sk_buff *skb;
    struct nf_conntrack_tuple tuple;
    
    bool success = true;

    /* Input: 
     *          V6 SYN 
     * */
    pr_debug(">>> State: CLOSED\n   Packet seq: V6 SYN    \n");

    nat64_bib_init();
    nat64_session_init();
    filtering_init();
    init_pool();

    // Construct a V6 SYN packet
    if ((skb = init_packet_type_for_test( PACKET_TYPE_V6_SYN )) == NULL)
        return false;
    // Set packet's tuple.
    init_tuple_for_test_ipv6( &tuple, IPPROTO_TCP );
    // Process CLOSED state
    success &= assert_equals_int(NF_ACCEPT, tcp_closed_state_handle( skb, &tuple ), 
		"Check that we processed correctly the CLOSED state.");
    
    // Check we changed to "V6 INIT" state
    session_entry_p = nat64_get_session_entry( &tuple ); // Searches for the Session Table Entry corresponding to the incoming tuple
    if ( session_entry_p == NULL ) // If NO session was found:
    {
        pr_warning("ERROR. Could NOT find an existing SESSION entry for an incoming V6 SYN packet.");
    }
    success &= assert_equals_u8(V6_INIT,  session_entry_p->current_state, 
		"Test if we correctly processed V6 SYN packet.");
    
    nat64_session_destroy();
    nat64_bib_destroy();
    pool4_destroy();


    // TODO (alberto) revisar esto
    /* Input: 
     *          V4 SYN 
     * */
    //~ pr_debug(">>> State: CLOSED\n   Packet seq: V4 SYN    \n");

    /* +------+      V4       +-------+
     * |CLOSED|-----SYN------>|V4 INIT|
     * +------+               +-------+
     *                */
     
    /* FIXME:   Can NOT test this as there's a conflict in the function: 
     *          bool nat64_add_session_entry()    */  
/*
    nat64_bib_init();
    nat64_session_init();

    // Construct a V4 SYN packet
    init_packet_type_for_test( &skb , PACKET_TYPE_V4_SYN );
    // Set packet's tuple.
    init_tuple_for_test_ipv4( &tuple, IPPROTO_TCP );
    // Process CLOSE state
    success &= assert_equals_int(NF_ACCEPT, tcp_closed_state_handle( &skb, &tuple ), 
		"Check that we processed correctly the CLOSED state.");


    // Check we changed to "V4 INIT" state
    session_entry_p = nat64_get_session_entry( &tuple ); // Searches for the Session Table Entry corresponding to the incoming tuple
    if ( session_entry_p == NULL ) // If NO session was found:
    {
        pr_warning("ERROR. Could NOT find an existing SESSION entry for an incoming V4 SYN packet.");
    }
    success &= assert_equals_u8(V4_INIT,  session_entry_p->current_state, "Test if we correctly processed V4 SYN packet.");
pr_debug("session_entry_p->current_state = %d\n", session_entry_p->current_state );
pr_debug("V4_INIT = %d\n", V4_INIT );

*/    
    
    kfree_skb(skb);
    return success;
}


/* FIXME:   Can NOT test this as there's a conflict in the function: 
 *          bool nat64_add_session_entry()    */
/*
bool test_tcp_v4_init_state_handle( void )
{
    struct sk_buff *skb;
    struct nf_conntrack_tuple tuple;
    struct session_entry *session_entry_p;
    struct ipv6_pair ipv6; struct ipv6_pair ipv4;
    bool success = true;

    filtering_init();
    nat64_bib_init();
    nat64_session_init();
    init_pool();

	// Construct a V4 SYN packet
    if ((skb = init_packet_type_for_test( PACKET_TYPE_V4_SYN )) == NULL)
        return false;
    // Init tuple
    init_tuple_for_test_ipv4( &tuple, IPPROTO_TCP);

    // Test case: there's NOT a Session Entry
    success &= assert_equals_int(NF_DROP, tcp_v4_init_state_handle( skb, &tuple ),
        "Testing that 'tcp_v4_init_state_handle' correctly drops packets for non-existing STE.");

    // Inject a Session Table Entry
    inject_session_entry( ipv6, ipv4 );

    // Test case: there IS a Session Entry
    success &= assert_equals_int(NF_ACCEPT, tcp_v4_init_state_handle( skb, &tuple ),
        "Testing that 'tcp_v4_init_state_handle' correctly accepts packets for existing STE.");

    // Check we changed to "V4 INIT" state
    session_entry_p = nat64_get_session_entry( &tuple ); // Searches for the Session Table Entry corresponding to the incoming tuple
    if ( session_entry_p == NULL ) // If NO session was found:
    {
        pr_warning("ERROR. Could NOT find an existing SESSION entry for an incoming V4 SYN packet.");
    }
    success &= assert_equals_u8(V4_INIT,  session_entry_p->current_state, "Test if we correctly processed V4 SYN packet.");
pr_debug("session_entry_p->current_state = %d\n", session_entry_p->current_state );
pr_debug("V4_INIT = %d\n", V4_INIT );

    nat64_session_destroy();
    nat64_bib_destroy();
    pool4_destroy();
    kfree_skb(skb);
    
    return success;
}
*/

bool test_tcp_v6_init_state_handle( void )
{
    struct session_entry *session_entry_p;
    struct sk_buff *skb;
    struct nf_conntrack_tuple tuple;
    
    bool success = true;

    /* Input: 
     *          V6 SYN --> V4 SYN 
     * */
    pr_debug(">>> State: V6 INIT\n  Packet seq: V6 SYN --> V4 SYN    \n");

    filtering_init();
    nat64_bib_init();
    nat64_session_init();
    init_pool();
    
    // Construct a V6 SYN packet
    if ((skb = init_packet_type_for_test( PACKET_TYPE_V6_SYN )) == NULL)
            return false;
    // Set packet's tuple.
    init_tuple_for_test_ipv6( &tuple, IPPROTO_TCP );
    // Process CLOSED state
    success &= assert_equals_int(NF_ACCEPT, tcp_closed_state_handle( skb, &tuple ), 
		"Check that we processed correctly the CLOSED state.");
    kfree_skb(skb);
    
    // Construct a V4 SYN packet
    if ((skb = init_packet_type_for_test( PACKET_TYPE_V4_SYN )) == NULL)
            return false;
    // Use previous tuple
    // Process V6 INIT state
    success &= assert_equals_int(NF_ACCEPT, tcp_v6_init_state_handle( skb, &tuple ), 
		"Check that we processed correctly the V6 INIT state.");
    kfree_skb(skb);
    
    // Check we changed to "ESTABLISHED" state
    session_entry_p = nat64_get_session_entry( &tuple ); // Searches for the Session Table Entry corresponding to the incoming tuple
    if ( session_entry_p == NULL ) // If NO session was found:
    {
        pr_warning("ERROR. Could NOT find an existing SESSION entry for an incoming ESTABLISHED packet.");
    }
    success &= assert_equals_u8(ESTABLISHED,  session_entry_p->current_state, "Test if we correctly processed V4 SYN packet.");
    
    nat64_session_destroy();
    nat64_bib_destroy();
    pool4_destroy();

    
    return success;
}

bool test_tcp_established_state_handle( void )
{
    struct session_entry *session_entry_p;
    struct sk_buff *skb;
    struct nf_conntrack_tuple tuple;
    
    bool success = true;

    /* Input: 
     *          V6 SYN --> V4 SYN --> V4 FIN 
     * */
    pr_debug(">>> State: ESTABLISHED\n  Packet seq: V6 SYN --> V4 SYN --> V4 FIN    \n");

    filtering_init();
    nat64_bib_init();
    nat64_session_init();
    init_pool();
    
    // Construct a V6 SYN packet
    if ((skb = init_packet_type_for_test( PACKET_TYPE_V6_SYN )) == NULL)
        return false;
    // Set packet's tuple.
    init_tuple_for_test_ipv6( &tuple, IPPROTO_TCP );
    // Process CLOSE state
    success &= assert_equals_int(NF_ACCEPT, tcp_closed_state_handle( skb, &tuple ),
		"Check that we processed correctly the CLOSED state.");
    kfree_skb(skb);

    // Construct a V4 SYN packet
    if ((skb = init_packet_type_for_test( PACKET_TYPE_V4_SYN )) == NULL)
        return false;
    // Set packet's tuple.
    init_tuple_for_test_ipv4( &tuple, IPPROTO_TCP );
    // Process V6 INIT state
    success &= assert_equals_int(NF_ACCEPT, tcp_v6_init_state_handle( skb, &tuple ),
		"Check that we processed correctly the V6 INIT state.");
    kfree_skb(skb);

    // Construct a V4 FIN packet
    if ((skb = init_packet_type_for_test( PACKET_TYPE_V4_FIN )) == NULL)
        return false;
    // Use previous tuple
    // Process ESTABLISHED state
    success &= assert_equals_int(NF_ACCEPT, tcp_established_state_handle( skb, &tuple ),
		"Check that we processed correctly the ESTABLISHED state.");
    kfree_skb(skb);
    
    // Check we changed to "V4 FIN RCV" state
    session_entry_p = nat64_get_session_entry( &tuple ); // Searches for the Session Table Entry corresponding to the incoming tuple
    if ( session_entry_p == NULL ) // If NO session was found:
    {
        pr_warning("ERROR. Could NOT find an existing SESSION entry for an incoming V4 FIN packet.");
    }
    success &= assert_equals_u8(V4_FIN_RCV,  session_entry_p->current_state, "Test if we correctly processed V4 FIN packet.");
    
    nat64_session_destroy();
    nat64_bib_destroy();
    pool4_destroy();
    
    /* Input: 
     *          V6 SYN --> V4 SYN --> V6 FIN 
     * */
    pr_debug(">>> State: ESTABLISHED\n  Packet seq: V6 SYN --> V4 SYN --> V6 FIN    \n");
     
    nat64_bib_init();
    nat64_session_init();
    init_pool();
    
    // Construct a V6 SYN packet
    if ((skb = init_packet_type_for_test( PACKET_TYPE_V6_SYN )) == NULL)
        return false;
    // Set packet's tuple.
    init_tuple_for_test_ipv6( &tuple, IPPROTO_TCP );
    // Process CLOSE state
    success &= assert_equals_int(NF_ACCEPT, tcp_closed_state_handle( skb, &tuple ), 
		"Check that we processed correctly the CLOSED state.");
    kfree_skb(skb);

    // Construct a V4 SYN packet
    if ((skb = init_packet_type_for_test( PACKET_TYPE_V4_SYN )) == NULL)
        return false;
    // Set packet's tuple.
    init_tuple_for_test_ipv4( &tuple, IPPROTO_TCP );
    // Process V6 INIT state
    success &= assert_equals_int(NF_ACCEPT, tcp_v6_init_state_handle( skb, &tuple ),
		"Check that we processed correctly the V6 INIT state.");
    kfree_skb(skb);

    // Construct a V6 FIN packet
    if ((skb = init_packet_type_for_test( PACKET_TYPE_V6_FIN )) == NULL)
        return false;
    // Set packet's tuple.
    init_tuple_for_test_ipv6( &tuple, IPPROTO_TCP );
    // Process ESTABLISHED state
    success &= assert_equals_int(NF_ACCEPT, tcp_established_state_handle( skb, &tuple ), 
		"Check that we processed correctly the ESTABLISHED state.");
    kfree_skb(skb);
    
    // Check we changed to "V6 FIN RCV" state
    session_entry_p = nat64_get_session_entry( &tuple ); // Searches for the Session Table Entry corresponding to the incoming tuple
    if ( session_entry_p == NULL ) // If NO session was found:
    {
        pr_warning("ERROR. Could NOT find an existing SESSION entry for an incoming V6 FIN packet.");
    }
    success &= assert_equals_u8(V6_FIN_RCV,  session_entry_p->current_state, "Test if we correctly processed V6 FIN packet.");
    
    nat64_session_destroy();
    nat64_bib_destroy();
    pool4_destroy();
    
    /* Input: 
     *          V6 SYN --> V4 SYN --> V6 RST 
     * */
    pr_debug(">>> State: ESTABLISHED\n  Packet seq: V6 SYN --> V4 SYN --> V6 RST    \n");
     
    nat64_bib_init();
    nat64_session_init();
    init_pool();
    
    // Construct a V6 SYN packet
    if ((skb = init_packet_type_for_test( PACKET_TYPE_V6_SYN )) == NULL)
        return false;
    // Set packet's tuple.
    init_tuple_for_test_ipv6( &tuple, IPPROTO_TCP );
    // Process CLOSE state
    success &= assert_equals_int(NF_ACCEPT, tcp_closed_state_handle( skb, &tuple ), 
		"Check that we processed correctly the CLOSED state.");
    kfree_skb(skb);

    // Construct a V4 SYN packet
     if ((skb = init_packet_type_for_test( PACKET_TYPE_V4_SYN )) == NULL)
        return false;
    // Set packet's tuple.
    init_tuple_for_test_ipv4( &tuple, IPPROTO_TCP );
    // Process V6 INIT state
    success &= assert_equals_int(NF_ACCEPT, tcp_v6_init_state_handle( skb, &tuple ), 
		"Check that we processed correctly the V6 INIT state.");
    kfree_skb(skb);

    // Construct a V6 RST packet
    if ((skb = init_packet_type_for_test( PACKET_TYPE_V6_RST )) == NULL)
        return false;
    // Set packet's tuple.
    init_tuple_for_test_ipv6( &tuple, IPPROTO_TCP );
    // Process ESTABLISHED state
    success &= assert_equals_int(NF_ACCEPT, tcp_established_state_handle( skb, &tuple ), 
		"Check that we processed correctly the ESTABLISHED state.");
    kfree_skb(skb);
    
    // Check we changed to "TRANS" state
    session_entry_p = nat64_get_session_entry( &tuple ); // Searches for the Session Table Entry corresponding to the incoming tuple
    if ( session_entry_p == NULL ) // If NO session was found:
    {
        pr_warning("ERROR. Could NOT find an existing SESSION entry for an incoming V6 RST packet.");
    }
    success &= assert_equals_u8(TRANS,  session_entry_p->current_state, "Test if we correctly processed V6 RST packet.");
    
    nat64_session_destroy();
    nat64_bib_destroy();    
    pool4_destroy();
    
    return success;
}

bool test_tcp_v4_fin_rcv_state_handle( void )
{
    struct session_entry *session_entry_p;
    struct sk_buff *skb;
    struct nf_conntrack_tuple tuple;
    
    bool success = true;

    /* Input: 
     *          V6 SYN --> V4 SYN --> V4 FIN --> V6 FIN 
     * */
    pr_debug(">>> State: V4 FIN RCV\n   Packet seq: V6 SYN --> V4 SYN --> V4 FIN --> V6 FIN    \n");

    filtering_init();
    nat64_bib_init();
    nat64_session_init();
    init_pool();
    
    // Construct a V6 SYN packet
    if ((skb = init_packet_type_for_test( PACKET_TYPE_V6_SYN )) == NULL)
            return false;
    // Set packet's tuple.
    init_tuple_for_test_ipv6( &tuple, IPPROTO_TCP );
    // Process CLOSE state
    success &= assert_equals_int(NF_ACCEPT, tcp_closed_state_handle( skb, &tuple ), 
		"Check that we processed correctly the CLOSED state.");
    kfree_skb(skb);

    // Construct a V4 SYN packet
    if ((skb = init_packet_type_for_test( PACKET_TYPE_V4_SYN )) == NULL)
            return false;
    // Set packet's tuple.
    init_tuple_for_test_ipv4( &tuple, IPPROTO_TCP );
    // Process V6 INIT state
    success &= assert_equals_int(NF_ACCEPT, tcp_v6_init_state_handle( skb, &tuple ), 
		"Check that we processed correctly the V6 INIT state.");
    kfree_skb(skb);

    // Construct a V4 FIN packet
    if ((skb = init_packet_type_for_test( PACKET_TYPE_V4_FIN )) == NULL)
            return false;
    // Use previous tuple
    // Process ESTABLISHED state
    success &= assert_equals_int(NF_ACCEPT, tcp_established_state_handle( skb, &tuple ), 
		"Check that we processed correctly the ESTABLISHED state.");
    kfree_skb(skb);
    
    // Construct a V6 FIN packet
    if ((skb = init_packet_type_for_test( PACKET_TYPE_V6_FIN )) == NULL)
            return false;
    // Set packet's tuple.
    init_tuple_for_test_ipv6( &tuple, IPPROTO_TCP );
    // Process V4 FIN RCV state
    success &= assert_equals_int(NF_ACCEPT, tcp_v4_fin_rcv_state_handle( skb, &tuple ), 
		"Check that we processed correctly the V4 FIN RCV state.");
    kfree_skb(skb);
    
    // Check we changed to "V4 FIN + V6 FIN RCV" state
    session_entry_p = nat64_get_session_entry( &tuple ); // Searches for the Session Table Entry corresponding to the incoming tuple
    if ( session_entry_p == NULL ) // If NO session was found:
    {
        pr_warning("ERROR. Could NOT find an existing SESSION entry for an incoming V6 FIN packet.");
    }
    success &= assert_equals_u8(V4_FIN_V6_FIN_RCV,  session_entry_p->current_state, 
		"Test if we correctly processed V6 FIN packet.");
    
    nat64_session_destroy();
    nat64_bib_destroy();
    pool4_destroy();


    return success;
}

bool test_tcp_v6_fin_rcv_state_handle( void )
{
    struct session_entry *session_entry_p;
    struct sk_buff *skb;
    struct nf_conntrack_tuple tuple;
    
    bool success = true;

    /* Input: 
     *          V6 SYN --> V4 SYN --> V6 FIN --> V4 FIN 
     * */
    pr_debug(">>> State: V6 FIN RCV\n   Packet seq: V6 SYN --> V4 SYN --> V6 FIN --> V4 FIN    \n");

    filtering_init();
    nat64_bib_init();
    nat64_session_init();
    init_pool();
    
    // Construct a V6 SYN packet
    if ((skb = init_packet_type_for_test( PACKET_TYPE_V6_SYN )) == NULL)
            return false;
    // Set packet's tuple.
    init_tuple_for_test_ipv6( &tuple, IPPROTO_TCP );
    // Process CLOSE state
    success &= assert_equals_int(NF_ACCEPT, tcp_closed_state_handle( skb, &tuple ), 
		"Check that we processed correctly the CLOSED state.");
    kfree_skb(skb);

    // Construct a V4 SYN packet
    if ((skb = init_packet_type_for_test( PACKET_TYPE_V4_SYN )) == NULL)
            return false;
    // Set packet's tuple.
    init_tuple_for_test_ipv4( &tuple, IPPROTO_TCP );
    // Process V6 INIT state
    success &= assert_equals_int(NF_ACCEPT, tcp_v6_init_state_handle( skb, &tuple ), 
		"Check that we processed correctly the V6 INIT state.");
    kfree_skb(skb);

    // Construct a V6 FIN packet
    if ((skb = init_packet_type_for_test( PACKET_TYPE_V6_FIN )) == NULL)
            return false;
    // Set packet's tuple.
    init_tuple_for_test_ipv6( &tuple, IPPROTO_TCP );
    // Process ESTABLISHED state
    success &= assert_equals_int(NF_ACCEPT, tcp_established_state_handle( skb, &tuple ), 
		"Check that we processed correctly the ESTABLISHED state.");
    kfree_skb(skb);
    
    // Construct a V4 FIN packet
    if ((skb = init_packet_type_for_test( PACKET_TYPE_V4_FIN )) == NULL)
            return false;
    // Set packet's tuple.
    init_tuple_for_test_ipv4( &tuple, IPPROTO_TCP );
    // Process V6 FIN RCV state
    success &= assert_equals_int(NF_ACCEPT, tcp_v6_fin_rcv_state_handle( skb, &tuple ), 
		"Check that we processed correctly the V6 FIN RCV state.");
    kfree_skb(skb);
    
    // Check we changed to "V4 FIN + V6 FIN RCV" state
    session_entry_p = nat64_get_session_entry( &tuple ); // Searches for the Session Table Entry corresponding to the incoming tuple
    if ( session_entry_p == NULL ) // If NO session was found:
    {
        pr_warning("ERROR. Could NOT find an existing SESSION entry for an incoming V4 FIN packet.");
    }
    success &= assert_equals_u8(V4_FIN_V6_FIN_RCV,  session_entry_p->current_state, 
		"Test if we correctly processed V4 FIN packet.");
    
    nat64_session_destroy();
    nat64_bib_destroy();
    pool4_destroy();

    
    return success;
}


/*
//~ int tcp_v4_fin_v6_fin_rcv_state_handle(struct packet *packet, struct nf_conntrack_tuple *tuple);
bool test_tcp_v4_fin_v6_fin_rcv_state_handle( void )
{
    
    // TODO: Deal with TIMEOUTs
    
    return success;
}
*/

bool test_tcp_trans_state_handle( void )
{
    struct session_entry *session_entry_p;
    struct sk_buff *skb;
    struct nf_conntrack_tuple tuple;
    
    bool success = true;
    
    /* Input: 
     *          V6 SYN --> V4 SYN --> V6 RST --> V6 SYN 
     * */
    pr_debug(">>> State: TRANS\n    Packet seq: V6 SYN --> V4 SYN --> V6 RST --> V6 SYN   \n");
     
    filtering_init();
    nat64_bib_init();
    nat64_session_init();
    init_pool();
    
    // Construct a V6 SYN packet
    if ((skb = init_packet_type_for_test( PACKET_TYPE_V6_SYN )) == NULL)
            return false;
    // Set packet's tuple.
    init_tuple_for_test_ipv6( &tuple, IPPROTO_TCP );
    // Process CLOSE state
    success &= assert_equals_int(NF_ACCEPT, tcp_closed_state_handle( skb, &tuple ), 
		"Check that we processed correctly the CLOSED state.");
    kfree_skb(skb);

    // Construct a V4 SYN packet
    if ((skb = init_packet_type_for_test( PACKET_TYPE_V4_SYN )) == NULL)
            return false;
    // Set packet's tuple.
    init_tuple_for_test_ipv4( &tuple, IPPROTO_TCP );
    // Process V6 INIT state
    success &= assert_equals_int(NF_ACCEPT, tcp_v6_init_state_handle( skb, &tuple ), 
		"Check that we processed correctly the V6 INIT state.");
    kfree_skb(skb);

    // Construct a V6 RST packet
    if ((skb = init_packet_type_for_test( PACKET_TYPE_V6_RST )) == NULL)
            return false;
    // Set packet's tuple.
    init_tuple_for_test_ipv6( &tuple, IPPROTO_TCP );
    // Process ESTABLISHED state
    success &= assert_equals_int(NF_ACCEPT, tcp_established_state_handle( skb, &tuple ), 
		"Check that we processed correctly the ESTABLISHED state.");
    kfree_skb(skb);
        
    // Construct a V6 SYN packet
    if ((skb = init_packet_type_for_test( PACKET_TYPE_V6_SYN )) == NULL)
            return false;
    // Set packet's tuple.
    init_tuple_for_test_ipv6( &tuple, IPPROTO_TCP );
    // Process TRANS state
    success &= assert_equals_int(NF_ACCEPT, tcp_trans_state_handle( skb, &tuple ), 
		"Check that we processed correctly the TRANS state.");
    kfree_skb(skb);
    
    // Check we changed back to "ESTABLISHED" state
    session_entry_p = nat64_get_session_entry( &tuple ); // Searches for the Session Table Entry corresponding to the incoming tuple
    if ( session_entry_p == NULL ) // If NO session was found:
    {
        pr_warning("ERROR. Could NOT find an existing SESSION entry for an incoming V6 SYN packet.");
    }
    success &= assert_equals_u8(ESTABLISHED,  session_entry_p->current_state, 
		"Test if we correctly processed V6 SYN packet.");
    
    nat64_session_destroy();
    nat64_bib_destroy();    
    pool4_destroy();
        
    return success;
}

bool test_tcp( void )
{
    struct session_entry *session_entry_p;
    struct sk_buff *skb;
    struct nf_conntrack_tuple tuple;
    
    bool success = true;
    
    /* Input: 
     *          V6 SYN --> V4 SYN --> V6 RST --> V6 SYN 
     * */
    pr_debug(">>> State: TRANS\n    Packet seq: V6 SYN --> V4 SYN --> V6 RST --> V6 SYN   \n");
     
    nat64_bib_init();
    nat64_session_init();
    init_pool();
    
    // Construct a V6 SYN packet
    if ((skb = init_packet_type_for_test( PACKET_TYPE_V6_SYN )) == NULL)
            return false;
    // Set packet's tuple.
    init_tuple_for_test_ipv6( &tuple, IPPROTO_TCP );
    // Process CLOSED state
    success &= assert_equals_int(NF_ACCEPT, tcp( skb, &tuple ), 
		"Check that we processed correctly the CLOSED state.");
    kfree_skb(skb);

    // Construct a V4 SYN packet
    if ((skb = init_packet_type_for_test( PACKET_TYPE_V4_SYN )) == NULL)
            return false;
    // Set packet's tuple.
    init_tuple_for_test_ipv4( &tuple, IPPROTO_TCP );
    // Process V6 INIT state
    success &= assert_equals_int(NF_ACCEPT, tcp( skb, &tuple ), 
		"Check that we processed correctly the V6 INIT state.");
    kfree_skb(skb);

    // Construct a V6 RST packet
    if ((skb = init_packet_type_for_test( PACKET_TYPE_V6_RST )) == NULL)
            return false;
    // Set packet's tuple.
    init_tuple_for_test_ipv6( &tuple, IPPROTO_TCP );
    // Process ESTABLISHED state
    success &= assert_equals_int(NF_ACCEPT, tcp( skb, &tuple ), 
		"Check that we processed correctly the ESTABLISHED state.");
    kfree_skb(skb);
        
    // Construct a V6 SYN packet
    if ((skb = init_packet_type_for_test( PACKET_TYPE_V6_SYN )) == NULL)
            return false;
    // Set packet's tuple.
    init_tuple_for_test_ipv6( &tuple, IPPROTO_TCP );
    // Process TRANS state
    success &= assert_equals_int(NF_ACCEPT, tcp( skb, &tuple ), 
		"Check that we processed correctly the TRANS state.");
    kfree_skb(skb);
    
    // Check we changed back to "ESTABLISHED" state
    session_entry_p = nat64_get_session_entry( &tuple ); // Searches for the Session Table Entry corresponding to the incoming tuple
    if ( session_entry_p == NULL ) // If NO session was found:
    {
        pr_warning("ERROR. Could NOT find an existing SESSION entry for an incoming V6 SYN packet.");
    }
    success &= assert_equals_u8(ESTABLISHED,  session_entry_p->current_state, 
		"Test if we correctly processed V6 SYN packet.");
    
    nat64_session_destroy();
    nat64_bib_destroy();    
    pool4_destroy();
    
    return success;
}

/* END: filtering_tcp.c */


//~ bool test_icmp( void )
//~ {
    //~ u_int8_t protocol;
    //~ struct nf_conntrack_tuple tuple;
    //~ struct sk_buff* skb = NULL;
    //~ 
    //~ bool success = true;
//~ 
    //~ nat64_bib_init();
    //~ nat64_session_init();
//~ 
    //~ protocol = IPPROTO_UDP;
//~ 
    //~ // Init tuple
    //~ init_tuple_for_test_ipv4( &tuple , protocol  );
    //~ // Init skb
    //~ skb = init_skb_for_test( &tuple, skb, protocol );
    //~ success &= assert_not_null(skb, "init_skb_for_test");        
//~ 
        //~ send_icmp_error_message(skb, DESTINATION_UNREACHABLE, HOST_UNREACHABLE); 


    // Discard un-expected IPv4 packets.
//~ pr_debug(" Discard un-expected IPv4 packets");
    //~ ret = ipv4_udp( skb, &tuple ); 
    //~ ASSERT_EQUALS(NF_DROP, ret, "See if we discard an IPv4 UDP packet, which tries to start a communication.");


    //~ nat64_session_destroy();
    //~ nat64_bib_destroy();
    //~ kfree_skb(skb);
    //~ 
    //~ return success;
//~ }




int __init filtering_test_init(void)
{
    START_TESTS("Filtering and Updating");
    
    pr_debug("\n\n\n");
    pr_debug("\n\nNAT64 %s TEST module inserted!", "filtering_test");


    // Initialize the NAT configuration for the tests.
    if ( !nat64_config_init() )
		return -EINVAL;

    /*      UDP & ICMP      */
    //~ CALL_TEST(test_icmp(), "test_icmp");
    
    CALL_TEST(test_transport_address_ipv4(), "test_transport_address_ipv4");
    CALL_TEST(test_transport_address_ipv6(), "test_transport_address_ipv6");
    CALL_TEST(test_extract_ipv4_from_ipv6(), "test_extract_ipv4_from_ipv6");
    CALL_TEST(test_embed_ipv4_in_ipv6(), "test_embed_ipv4_in_ipv6");
    CALL_TEST(test_allocate_ipv4_transport_address(), "test_allocate_ipv4_transport_address");
    CALL_TEST(test_allocate_ipv4_transport_address_digger(), "test_allocate_ipv4_transport_address_digger");
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
    CALL_TEST(test_tcp_closed_state_handle(), "test_tcp_closed_state_handle");
    //~ CALL_TEST(test_tcp_v4_init_state_handle(), "test_tcp_v4_init_state_handle"); // Not implemented yet!
    CALL_TEST(test_tcp_v6_init_state_handle(), "test_tcp_v6_init_state_handle");
    CALL_TEST(test_tcp_established_state_handle(), "test_tcp_established_state_handle");
    CALL_TEST(test_tcp_v4_fin_rcv_state_handle(), "test_tcp_v4_fin_rcv_state_handle");
    CALL_TEST(test_tcp_v6_fin_rcv_state_handle(), "test_tcp_v6_fin_rcv_state_handle");
    //~ CALL_TEST(test_tcp_v4_fin_v6_fin_rcv_state_handle(), "test_tcp_v4_fin_v6_fin_rcv_state_handle"); // Not implemented yet!
    CALL_TEST(test_tcp_trans_state_handle(), "test_tcp_trans_state_handle");
    CALL_TEST(test_tcp(), "test_tcp");
  
	nat64_config_destroy();
    /* A non 0 return means a test failed; module can't be loaded. */
    END_TESTS;
}

void __exit filtering_test_exit(void)
{

    pr_debug("NAT64 %s TEST module removed!\n\n\n", "filtering_test");
}

module_init(filtering_test_init);
module_exit(filtering_test_exit);
