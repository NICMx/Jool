#ifndef _LINUX_NAT64_MODULE_COMMUNICATION_H
#define _LINUX_NAT64_MODULE_COMMUNICATION_H
/*
 * Communication with the NAT64 module (using netlink sockets).
 */

struct nat64_run_conf 
{
	/* IPv4 */
	char ipv4_addr_str[sizeof("255.255.255.255/32")];
	unsigned char ipv4_mask_bits;			//
	unsigned int ipv4_pool_range_first;		// Pool
	unsigned int ipv4_pool_range_last;		//
	unsigned int ipv4_tcp_port_range_first;	// TCP
	unsigned int ipv4_tcp_port_range_last;	//
	unsigned int ipv4_udp_port_range_first;	// UDP
	unsigned int ipv4_udp_port_range_last;	//
	
	/* IPv6 */
	char ipv6_net_prefix[sizeof("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128")];
	unsigned int  ipv6_net_addr[4];			// Address
	unsigned char ipv6_net_mask_bits;		//
	unsigned int ipv6_tcp_port_range_first;	// TCP
	unsigned int ipv6_tcp_port_range_last;	//
	unsigned int ipv6_udp_port_range_first;	// UDP
	unsigned int ipv6_udp_port_range_last;	//
};



#endif /* _LINUX_NAT64_MODULE_COMMUNICATION_H */
