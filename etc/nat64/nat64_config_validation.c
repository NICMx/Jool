#include "nat64_config_validation.h"
#include <stdbool.h>


/** Convertion and validation of IPv6 addresses in the configuration file.
 *
 * @param[in] 	af			Address family: AF_INET[6].
 * @param[in] 	addr_str	Address in string format.
 * @param[out]	addr		Output address in binary format.
 * @return		true if OK, otherwise false.
 */
int convert_IP_addr(int af, const char *addr_str, void *addr)
{
	switch(af)
	{
		case AF_INET:
			if (inet_pton(af, addr_str, (struct in_addr*)addr) == 0)
				return (false);
			break;
		case AF_INET6:
			if (inet_pton(af, addr_str, (struct in6_addr*)addr) == 0)
				return (false);
			break;
		default:
			return (false);
	}
	return (true);
}

/** Convertion and validation of IPv4 addresses in the configuration file.
 *
 * @param[in] 	addr_str	Address in string format.
 * @param[out]	addr		Output address in binary format.
 * @return		true if OK, otherwise false.
 */
int convert_ipv4_addr(const char *addr_str, struct in_addr *addr)
{
	return convert_IP_addr(AF_INET, addr_str, addr);
}

/** Convertion and validation of IPv6 addresses in the configuration file.
 *
 * @param[in] 	addr_str	Address in string format.
 * @param[out]	addr		Output address in binary format.
 * @return		true if OK, otherwise false.
 */
int convert_ipv6_addr(const char *addr_str, struct in6_addr *addr)
{
	return convert_IP_addr(AF_INET6, addr_str, addr);
}

/** Validate the network mask in the format '/n'.
 *
 * @param[in] 	netmask_bits	Network mask bits.
 * @return		true if OK, otherwise false.
 */
int validate_ipv4_netmask_bits(unsigned char netmask_bits)
{
	if (netmask_bits > 32 || netmask_bits < 0)
		return (false);
	
	return (true);
}

/** Convert from network mask bits (in CIDR format '/n') to network address.
 *  Works with IPv6 and IPv4.
 *
 * @param[in] 	af      Address family.
 * @param[in] 	bits	Network mask bits in CIDR format.
 * @param[out] 	net     Network address.
 * @return		true if OK, otherwise false.
 */
int convert_bits_to_netmask(int af, unsigned char bits, void *net)
{
	unsigned char ii = 0;

	switch(af)
	{
		case AF_INET:
			inet_pton(af, "0.0.0.0", (struct in_addr *)net);
			(*(struct in_addr *)net).s_addr = \
				BROADCAST_ADDR >>(IPV4_NETMASK_BITS_MAX - bits);
			break;
		case AF_INET6:
			inet_pton(af, "::0", (struct in6_addr *)net);

			for (ii = 0; ii < IPV6_SIZE_UINT32; ii++)
			{
				if (bits <= ii * IPV6_SIZE_UINT32_BITS )
				{
					if (bits == ii * IPV6_SIZE_UINT32_BITS )
						(*(struct in6_addr *)net).s6_addr32[ii] = \
							DONT_CARE;
					else
						(*(struct in6_addr *)net).s6_addr32[ii] = \
							htonl( BROADCAST_ADDR <<(IPV6_NETMASK_BITS_MAX - bits ) );
				}
				else
				{
					(*(struct in6_addr *)net).s6_addr32[ii] = BROADCAST_ADDR;
				}
			}
			break;
		default:
			//~ printf("%s. Error, bad address family.\n", "convert_bits_to_netmask");
			return false;
	}
	
	return true;	
}

/** Computes network address from IP address and network mask.
 *  Works with IPv6 and IPv4.
 * 
 * @param[in] 	af          Address family.
 * @param[in] 	ip_addr     IP address.
 * @param[in] 	ip_netmask	Network mask.
 * @param[out] 	net         Network address.
 * @return		true if OK, otherwise false.
 */
int get_net_addr(int af, void *ip_addr, void *ip_netmask, void *ip_net)
{
	unsigned char ii = 0;

	switch(af)
	{
		case AF_INET:
			(*(struct in_addr *)ip_net).s_addr = \
				(*(struct in_addr *)ip_addr).s_addr & \
				(*(struct in_addr *)ip_netmask).s_addr;
			break;
		
		case AF_INET6:
			for (ii = 0; ii < IPV6_SIZE_UINT32; ii++)
			{
				(*(struct in6_addr *)ip_net).s6_addr32[ii] = \
					(*(struct in6_addr *)ip_addr).s6_addr32[ii] & \
					(*(struct in6_addr *)ip_netmask).s6_addr32[ii];
			}

			break;

		default:
			//~ printf("%s. Error, bad address family.\n", "get_net_addr");
			return false;

	}

	return true;
}


/** Get network addresses using netmask bits (in CIDR).
 *
 * @param[in] 	af			Address Family: AF_INET[6].
 * @param[in] 	addr		IP address.
 * @param[in] 	netmask_bits Netmask bits in CIDR format.
 * @param[out] 	net	        Network address.
 * @return		TRUE if they are equal, FALSE otherwise.
 */
int get_net_addr_from_netmask_bits(int af, void *addr, unsigned char netmask_bits, void *net) 
{
    struct in_addr mask;
    struct in6_addr mask6;

    switch (af)
    {
        case AF_INET:
            if ( ! convert_bits_to_netmask(AF_INET, netmask_bits, &mask) )
                return false;
            if ( ! get_net_addr(AF_INET, addr, &mask, net) )
                return false;
            break;
        case AF_INET6:
            if ( ! convert_bits_to_netmask(AF_INET6, netmask_bits, &mask6) )
                return false;
            if ( ! get_net_addr(AF_INET6, addr, &mask6, net) )
                return false;
            break;
        default:
            return false;
    }
    return true;
}


/** Checks if 2 IP address are equal.
 *  Works with !IPv6 and IPv4.
 * 
 * @param[in] 	af      Address family.
 * @param[in] 	addr_1  IP address.
 * @param[in] 	addr_2  Network mask.
 * @return		true if both are equal, or false if they are different.
 */
int ip_addr_are_diff(int af, void *addr_1, void *addr_2) 
{
	switch (af)
	{
		case AF_INET: 
			if ( 	(*(struct in_addr *)addr_1).s_addr != \
				(*(struct in_addr *)addr_2).s_addr )
			       return false;	       
			break;
		case AF_INET6:
			// TODO: implement me!	
			/*if ( 	(*(struct in_addr *)addr_1).s_addr != \
			  	(*(struct in_addr *)addr_2).s_addr )
			         return false;	       
			 */
			break;
		default:
			//~ printf("%s. Error, bad address family.\n", "ip_addr_are_equal");
			return false;
	}

	return true;
}

/** Verify if two IP addresses are equal.
 *
 * @param[in] 	af			Address Family: AF_INET[6].
 * @param[in] 	addr_1		First IP address.
 * @param[in] 	addr_2		Second IP address.
 * @return		TRUE if they are equal, FALSE otherwise.
 */
int ip_addrs_are_equal(int af, void *addr_1, void *addr_2) 
{
    int ii = 0;
    
	switch (af)
	{
		case AF_INET: 
			if ( 	(*(struct in_addr *)addr_1).s_addr != \
				(*(struct in_addr *)addr_2).s_addr )
			       return false;	       
			break;
		case AF_INET6:
            for (ii = 0; ii < IPV6_SIZE_UINT32; ii++)
			{
				if (    (*(struct in6_addr *)addr_1).s6_addr32[ii] != \
                        (*(struct in6_addr *)addr_2).s6_addr32[ii] )
                    return false;
			}
			break;
		default:
			return false;
	}

	return true;
}

/** Check if 2 IP addresses belong to the same network.
 *  Works with !IPv6 and IPv4.
 * 
 * @param[in] 	af          Address family.
 * @param[in] 	network     Network address.
 * @param[in] 	maskbits	Network mask in CIDR format.
 * @param[in] 	addr_first  First IP address to compare.
 * @param[in] 	addr_last   Second IP address to compare.
 * @return		true if OK, otherwise false.
 */
int ip_addr_in_same_net(int af, 
			const void *network, unsigned char maskbits,
	       	const void *addr_first, const void *addr_last)
{
	struct in_addr ipv4_net;
	struct in_addr ipv4_netmask;
	struct in_addr ipv4_first;
	struct in_addr ipv4_last;

	switch (af)
	{
		case AF_INET:
			convert_bits_to_netmask(af, maskbits, &ipv4_netmask);

			get_net_addr(af, (struct in_addr *)network, &ipv4_netmask, &ipv4_net);
			if ( ip_addr_are_diff(af, (struct in_addr *)network, &ipv4_net)  )
				return false;

			get_net_addr(af, (struct in_addr *)addr_first, &ipv4_netmask, &ipv4_first);
			if ( ip_addr_are_diff(af, &ipv4_net, &ipv4_first)  )
				return false;
			
			get_net_addr(af, (struct in_addr *)addr_last, &ipv4_netmask, &ipv4_last);
			if ( ip_addr_are_diff(af, &ipv4_net, &ipv4_last)  )
				return false;

			break;
		case AF_INET6:
			// TODO: implement me!
			//convert_bits_to_netmask(af, ipv6_bits, &ipv6_netmask);
			break;
		default:
			//~ printf("%s. Error, bad address family.\n", "ip_addr_in_same_net");
			return false;
	}

	return true;
}

/** Validate the IPv4 pool address range.
 *
 * @param[in] 	network		IPv4 pool network address.
 * @param[in] 	maskbits	IPv4 pool network mask bits.
 * @param[in] 	addr_first	First IPv4 pool address available for NAT64 to use.
 * @param[in] 	addr_last	Last IPv4 pool address available for NAT64 to use.
 * @return		true if OK, otherwise false.
 */
int validate_ipv4_pool_range(	const struct in_addr *network,
								const unsigned char maskbits,
								const struct in_addr *addr_first,
								const struct in_addr *addr_last )
{
	if (addr_first->s_addr > addr_last->s_addr)
		return false;
	
	if ( ip_addr_in_same_net(AF_INET, \
			network, maskbits, \
	       	addr_first, addr_last) == false )
		return false;
	
	return true;
}	

/** Validates the IPv4 ports range.
 *
 * @param[in] 	port		First IPv4 valid port.
 * @param[in] 	port		Last IPv4 valid port.
 * @return		true if OK, otherwise false.
 */
int validate_ports_range(unsigned int first, unsigned int last)
{
	if (first < 0 || first > 65535)
		return false;
	if (last < 0 || last > 65535)
		return false;
	if (first > last)
		return false;	
	
	return true;
}

/** Validate the network mask in the format '/n'.
 *
 * @param[in] 	netmask_bits	Network mask bits.
 * @return		true if OK, otherwise false.
 */
int validate_ipv6_netmask_bits(unsigned char netmask_bits)
{
	if (netmask_bits > IPV6_DEF_MASKBITS_MAX || netmask_bits < IPV6_DEF_MASKBITS_MIN)
		return (false);
	
	// TODO: Validate values defined on RFC6052
	
	return (true);
}

int roundup(int subnetmaskx){ // We need to figure out the most significant bit, then set the subnetmaskx to that number.
	if (subnetmaskx == 0) {
		return 255;
	} else if (subnetmaskx < 2 ) {
		return 254;
	} else if (subnetmaskx < 4 ) {
		return 252;
	} else if (subnetmaskx < 8 ) {
		return 248;
	} else if (subnetmaskx < 16) {
		return 240;
	} else if (subnetmaskx < 32) {
		return 224;
	} else if (subnetmaskx < 64) {
		return 192;
	} else if (subnetmaskx < 128) {
		return 128;
	} else if (subnetmaskx < 256) {
		return 0;
	} else {
		return 0;
	}
}


/* Convert IP address's netmask into integer. We assume netmask is
   sequential one. Argument netmask should be network byte order. */
int ip_masklen (int num) {
    int i = 0;
    int bitpat=0xff00;
    if (num == 255 ){
        return(8);
    }
 
    while (i < 8){
        if (num == (bitpat & 0xff)){
            return (i);
        }
        bitpat=bitpat >> 1;
        i++;
    }
  return 0;
}

int calc_netmask (int first, int last){

	// Set up result variables.
	int subnetmask4 = 0;
	int subnetmask3 = 0;
	int subnetmask2 = 0;
	int subnetmask1 = 0;
	char netmask[15];
	struct in_addr mask;
	int res = 0;

	unsigned char bytes[4];
    bytes[0] = first & 0xFF;
    bytes[1] = (first >> 8) & 0xFF;
    bytes[2] = (first >> 16) & 0xFF;
    bytes[3] = (first >> 24) & 0xFF;	

	unsigned char bytes2[4];
    bytes2[0] = last & 0xFF;
    bytes2[1] = (last >> 8) & 0xFF;
    bytes2[2] = (last >> 16) & 0xFF;
    bytes2[3] = (last >> 24) & 0xFF;	

    //printf("%d.%d.%d.%d\n", bytes[0], bytes[1], bytes[2], bytes[3]);


	// Figure out the higest bit that changes. 
	// We do this by first doing a binary xor of the low and high numbers.
	subnetmask4 = (bytes2[0] ^ bytes[0]);
	subnetmask3 = (bytes2[1] ^ bytes[1]);
	subnetmask2 = (bytes2[2] ^ bytes[2]);
	subnetmask1 = (bytes2[3] ^ bytes[3]);

	//Then we round it up to the next most significant digit.
	subnetmask4 = roundup(subnetmask4); 
	subnetmask3 = roundup(subnetmask3);
	subnetmask2 = roundup(subnetmask2);
	subnetmask1 = roundup(subnetmask1);

	// Figure out which set of numbers changes, then set the lower numbers from it to 0.
	if (subnetmask4 < 255)
	{
	subnetmask3 = 0;
	subnetmask2 = 0;
	subnetmask1 = 0;
	}
	if (subnetmask3 < 255)
	{
	subnetmask2 = 0;
	subnetmask1 = 0;
	}
	if (subnetmask2 < 255)
	{
	subnetmask1 = 0;
	}

	sprintf (netmask, "%d.%d.%d.%d\n",subnetmask4, subnetmask3, subnetmask2,subnetmask1);

	if ( convert_ipv4_addr(netmask, &mask) == EXIT_FAILURE )	// Validate ipv4 addr
			{
				printf("Error: Malformed netmask: %s\n", netmask);
				exit(-1);
			}


	res+= ip_masklen(subnetmask4);
	res+= ip_masklen(subnetmask3);
	res+= ip_masklen(subnetmask2);
	res+= ip_masklen(subnetmask1);

	//printf("%d.%d.%d.%d mask: %d\n",subnetmask4, subnetmask3, subnetmask2,subnetmask1, res);

	return res; 


}


