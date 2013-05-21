/**
 * @file
 * Utils to validate configuration data.
 *
 * @author Roberto Aceves
 */

#ifndef _NF_NAT64_MODULE_CONF_VALIDATION_H
#define _NF_NAT64_MODULE_CONF_VALIDATION_H


#ifdef __KERNEL__
	#include <linux/in.h>
#else
	#include <arpa/inet.h>
#endif


#define IPV4_NETMASK_BITS_MAX	32
#define IPV6_NETMASK_BITS_MAX	128
/* 255.255.255.255 */
#define BROADCAST_ADDR	0xffffFFFF
/* 0.0.0.0 */
#define DONT_CARE	0x00000000
/* IPv6 is compoused by 4 ints */
#define IPV6_SIZE_UINT32	4
/* Each int is 32-bits long */
#define IPV6_SIZE_UINT32_BITS	32


int get_net_addr_from_netmask_bits(int af, void *addr, unsigned char netmask_bits, void *net);

int convert_bits_to_netmask(int af, unsigned char bits, void *net);

int validate_ipv4_netmask_bits(unsigned char netmask_bits);

int validate_ipv4_pool_range(	const struct in_addr *network,
								const unsigned char maskbits,
								const struct in_addr *addr_first,
								const struct in_addr *addr_last);

int validate_ports_range(unsigned int first, unsigned int last);

/*int validate_ipv6_netmask_bits(unsigned char netmask_bits); */

int round_mask_up(int subnetmaskx);

int ip_masklen(int num);

#endif /* _NF_NAT64_MODULE_CONF_VALIDATION_H */
