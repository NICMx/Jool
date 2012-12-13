#include "xt_nat64_module_conf_validation.h"
#include "nf_nat64_config.h"
#include <linux/inet.h>

//~ #include <linux/printk.h>
#include <linux/kernel.h>

extern struct config_struct cs;

/**	Checks if an IPv6 address has a valid prefix.
 *
 * @param[in]  addr	IPv6 Address
 * @return	TRUE if it has a valid prefix, FALSE otherwise.
 * */
int addr_has_pref64( struct in6_addr *addr )
{
    struct in6_addr pref6;
    int i = 0;

    for(i = 0; i < cs.ipv6_net_prefixes_qty; i++)
    {
        if ( ! get_net_addr_from_netmask_bits(  AF_INET6, addr,
                                                cs.ipv6_net_prefixes[i]->maskbits,
                                                &pref6) )
            return false;
        if ( ip_addrs_are_equal(AF_INET6, &cs.ipv6_net_prefixes[i]->addr, &pref6))
            return true;
    }
    
    return false;
}

/**	Checks if an IPv4 address belongs to the IPv4 pool.
 *
 * @param[in]  addr	IPv4 Address
 * @return	TRUE if it is inside the pool network, FALSE otherwise.
 * */
int addr_in_pool( struct in_addr *addr )
{
    struct in_addr net;

    if ( ! get_net_addr_from_netmask_bits(AF_INET, addr, cs.ipv4_pool_net_mask_bits, &net) )
            return false;
    
    if ( ! ip_addrs_are_equal(AF_INET, &cs.ipv4_pool_net, &net) )
        return false;
    
    return true;
}

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
			if (! in4_pton(addr_str, -1, (u8 *)addr, '\x0', NULL) )
				return (false);
			break;
		case AF_INET6:
			if (! in6_pton(addr_str, -1, (u8 *)addr, '\x0', NULL) )
				return (false);
			break;
		default:
			return (false);
	}
	return (true);
}

/** Convertion (from string to in_addr) and validation of IPv4 addresses in the configuration file.
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

/** Validate the network mask in the CIDR format '/n'.
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

/** Convert the network mask in CIDR format ('/n') to address format.
 *
 * @param[in] 	af		Address Family: AF_INET[6].
 * @param[in] 	bits	Network mask bits, integer value from: /n.
 * @param[out] 	net		Network mask in address format.
 * @return		true if OK, otherwise false.
 */
int convert_bits_to_netmask(int af, unsigned char bits, void *net)
{
	unsigned char ii = 0;

	switch(af)
	{
		case AF_INET:
			in4_pton("0.0.0.0", -1, (u8 *)net, '\x0', NULL); 
			(*(struct in_addr *)net).s_addr = \
				BROADCAST_ADDR >>(IPV4_NETMASK_BITS_MAX - bits);
			break;
		case AF_INET6:
			in6_pton("::0", -1, (u8 *)net, '\x0', NULL);

			for (ii = 0; ii < IPV6_SIZE_UINT32; ii++)
			{
				if (bits < (ii+1) * IPV6_SIZE_UINT32_BITS )
				{
					if (bits == (ii) * IPV6_SIZE_UINT32_BITS )
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
			return false;
	}

	return true;	
}

/** Obtain the network address of an IP address.
 *
 * @param[in] 	af			Address Family: AF_INET[6].
 * @param[in] 	ip_addr		IP address.
 * @param[in] 	ip_netmask	Network mask in address format.
 * @param[out] 	ip_net		Network address.
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
pr_debug(">	ip_net:%pI6 = ip_addr:%pI6 & ip_netmask:%pI6", ip_net, ip_addr, ip_netmask);
			for (ii = 0; ii < IPV6_SIZE_UINT32; ii++)
			{
				(*(struct in6_addr *)ip_net).s6_addr32[ii] = \
					(*(struct in6_addr *)ip_addr).s6_addr32[ii] & \
					(*(struct in6_addr *)ip_netmask).s6_addr32[ii];
pr_debug("[%d] ip_net:%pI6 = ip_addr:%pI6 & ip_netmask:%pI6", ii, ip_net, ip_addr, ip_netmask);
			}

			break;

		default:
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
int get_net_addr_from_netmask_bits(int af, void *addr, char netmask_bits, void *net) 
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
//~ pr_debug("addr6: %pI6", addr);
//~ pr_debug("mask6: %pI6", &mask6);
            if ( ! get_net_addr(AF_INET6, addr, &mask6, net) )
                return false;
//~ pr_debug("net6: %pI6", net);
            break;
        default:
            return false;
    }
    return true;
}

/** Verify if two IP addresses are different.
 *
 * @param[in] 	af			Address Family: AF_INET[6].
 * @param[in] 	addr_1		First IP address.
 * @param[in] 	addr_2		Second IP address.
 * @return		true if they are equal, otherwise return false.
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

/** Check that first and last pool addresses belongs to the same network.
 *
 * @param[in] 	af			Address Family: AF_INET[6].
 * @param[in] 	network		Pool's network address.
 * @param[in] 	maskbits		Net mask in CIDR format ('/N').
 * @param[in] 	addr_first		First IP address.
 * @param[in] 	addr_last		Last IP address.
 * @return		true if all they belong to the same net, otherwise return false.
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
			// TODO?: implement  me
			// Is thís necesary?
			//convert_bits_to_netmask(af, ipv6_bits, &ipv6_netmask);
			break;
		default:
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
