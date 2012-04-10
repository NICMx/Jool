#ifndef _LINUX_NAT64_MODULE_COMMUNICATION_H
#define _LINUX_NAT64_MODULE_COMMUNICATION_H
/*
 * Communication with the NAT64 module (using netlink sockets).
 */

struct nat64_run_conf 
{
	char ipv4_addr_str[sizeof("255.255.255.255")];
	int  ipv4_mask_bits;
};



#endif /* _LINUX_NAT64_MODULE_COMMUNICATION_H */
