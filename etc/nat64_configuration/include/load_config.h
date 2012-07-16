#ifndef _LOAD_CONFIG_H_
#define _LOAD_CONFIG_H_
//#include <arpa/inet.h>

////////////////////////////////////////////////////////////////////////
// DEFAULT VALUES
////////////////////////////////////////////////////////////////////////

// IPv6:
#define IPV6_DEF_PREFIX     "64:ff9b::"
#define IPV6_DEF_MASKBITS   96
//
#define IPV6_DEF_TCP_POOL_FIRST 1024
#define IPV6_DEF_TCP_POOL_LAST  65535
//
#define IPV6_DEF_UDP_POOL_FIRST 1024
#define IPV6_DEF_UDP_POOL_LAST  65535
// IPv4:
#define IPV4_DEF_NET        "192.168.2.0"
#define IPV4_DEF_NET_MASK   24
//
#define IPV4_DEF_POOL_FIRST "192.168.2.1"
#define IPV4_DEF_POOL_LAST  "192.168.2.254"
//
#define IPV4_DEF_TCP_POOL_FIRST 1024
#define IPV4_DEF_TCP_POOL_LAST  65535
//
#define IPV4_DEF_UDP_POOL_FIRST 1024
#define IPV4_DEF_UDP_POOL_LAST  65535


////////////////////////////////////////////////////////////////////////
// STRUCTURES
////////////////////////////////////////////////////////////////////////

struct config_struct
{
    //// IPv4:
    struct in_addr ipv4_addr_net;
	unsigned char  ipv4_addr_net_mask_bits;
	struct in_addr ipv4_pool_range_first;
	struct in_addr ipv4_pool_range_last;
    //
    unsigned short ipv4_tcp_port_first;
    unsigned short ipv4_tcp_port_last;
    //
    unsigned short ipv4_udp_port_first;
    unsigned short ipv4_udp_port_last;
    
    //// IPv6:
    struct in6_addr ipv6_net_prefix;
	unsigned char   ipv6_net_mask_bits;
    //
	unsigned short  ipv6_tcp_port_range_first;
	unsigned short  ipv6_tcp_port_range_last;
	//
	unsigned short  ipv6_udp_port_range_first;
    unsigned short  ipv6_udp_port_range_last;   
};

#endif
