/**
 * @file 	nat64_config_validation.h
 *
 * @brief 	Validates the information contained in configuration.
 *
 */

#ifndef _NAT64_CONFIG_VALIDATION_H_
#define _NAT64_CONFIG_VALIDATION_H_

#define _USER_SPACE_
#include "nf_nat64_config.h"
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>

#ifndef EXIT_FAILURE
	#define EXIT_SUCCESS    0       /* Successful exit status.  */
	#define EXIT_FAILURE    1       /* Failing exit status.  */
#endif

#define IPV4_NETMASK_BITS_MAX	32
#define IPV6_NETMASK_BITS_MAX	128
#define BROADCAST_ADDR	0xffffFFFF	// 255.255.255.255
#define DONT_CARE	0x00000000	// 0.0.0.0
#define IPV6_SIZE_UINT32	4	// IPv6 is compoused by 4 ints
#define IPV6_SIZE_UINT32_BITS	32 // Each int is 32-bits long


int get_net_addr_from_netmask_bits(int af, void *addr, unsigned char netmask_bits, void *net);

int ip_addrs_are_equal(int af, void *addr_1, void *addr_2);

int convert_ipv4_addr(const char *addr_str, struct in_addr *addr);

int convert_ipv6_addr(const char *addr_str, struct in6_addr *addr);

int validate_ipv4_netmask_bits(unsigned char netmask_bits);

int validate_ipv4_pool_range(	const struct in_addr *network,
								const unsigned char maskbits,
								const struct in_addr *addr_first,
								const struct in_addr *addr_last );

int validate_ports_range(unsigned int first, unsigned int last);

int validate_ipv6_netmask_bits(unsigned char netmask_bits);

int convert_bits_to_netmask(int af, unsigned char bits, void *net);

int roundup(int subnetmaskx);


int ip_masklen (int num);

int calc_netmask (int first, int last);
#endif
