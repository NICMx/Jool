#include "xt_nat64_module_conf_validation.h"
#include "nf_nat64_config.h"

#include <linux/kernel.h>


// TODO (ramiro) estas dos funciones (y quizá otras más) deberían estar en pool.
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
        if ( ipv6_addr_equals(&cs.ipv6_net_prefixes[i]->addr, &pref6))
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
    
    if ( ! ipv4_addr_equals(&cs.ipv4_pool_net, &net) )
        return false;
    
    return true;
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
			str_to_addr4("0.0.0.0", net);
			(*(struct in_addr *)net).s_addr = \
				BROADCAST_ADDR >>(IPV4_NETMASK_BITS_MAX - bits);
			break;
		case AF_INET6:
			str_to_addr6("::0", net);

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
			//~ log_warning("%s. Error, bad address family.", "convert_bits_to_netmask");
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
// log_debug(">	ip_net:%pI6 = ip_addr:%pI6 & ip_netmask:%pI6", ip_net, ip_addr, ip_netmask);
			for (ii = 0; ii < IPV6_SIZE_UINT32; ii++)
			{
				(*(struct in6_addr *)ip_net).s6_addr32[ii] = \
					(*(struct in6_addr *)ip_addr).s6_addr32[ii] & \
					(*(struct in6_addr *)ip_netmask).s6_addr32[ii];
// log_debug("[%d] ip_net:%pI6 = ip_addr:%pI6 & ip_netmask:%pI6", ii, ip_net, ip_addr, ip_netmask);
			}

			break;

		default:
			//~ log_warning("%s. Error, bad address family.", "get_net_addr");
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
//~ log_debug("addr6: %pI6", addr);
//~ log_debug("mask6: %pI6", &mask6);
            if ( ! get_net_addr(AF_INET6, addr, &mask6, net) )
                return false;
//~ log_debug("net6: %pI6", net);
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
			if ( !ipv4_addr_equals((struct in_addr *)network, &ipv4_net)  )
				return false;

			get_net_addr(af, (struct in_addr *)addr_first, &ipv4_netmask, &ipv4_first);
			if ( !ipv4_addr_equals(&ipv4_net, &ipv4_first)  )
				return false;
			
			get_net_addr(af, (struct in_addr *)addr_last, &ipv4_netmask, &ipv4_last);
			if ( !ipv4_addr_equals(&ipv4_net, &ipv4_last)  )
				return false;

			break;
		case AF_INET6:
			// TODO?: implement  me
			// Is thís necesary?
			//convert_bits_to_netmask(af, ipv6_bits, &ipv6_netmask);
			break;
		default:
			//~ log_warning("%s. Error, bad address family.", "ip_addr_in_same_net");
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

int round_mask_up(int subnetmaskx){ // We need to figure out the most significant bit, then set the subnetmaskx to that number.
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
	// TODO (miguel) creo que el newline y el caracter de terminación no caben en 15?
	char netmask[15];
	struct in_addr mask;
	int res = 0;

	unsigned char bytes[4], bytes2[4];

    bytes[0] = first & 0xFF;
    bytes[1] = (first >> 8) & 0xFF;
    bytes[2] = (first >> 16) & 0xFF;
    bytes[3] = (first >> 24) & 0xFF;

    bytes2[0] = last & 0xFF;
    bytes2[1] = (last >> 8) & 0xFF;
    bytes2[2] = (last >> 16) & 0xFF;
    bytes2[3] = (last >> 24) & 0xFF;

    //log_debug("%d.%d.%d.%d", bytes[0], bytes[1], bytes[2], bytes[3]);


	// Figure out the higest bit that changes.
	// We do this by first doing a binary xor of the low and high numbers.
	subnetmask4 = (bytes2[0] ^ bytes[0]);
	subnetmask3 = (bytes2[1] ^ bytes[1]);
	subnetmask2 = (bytes2[2] ^ bytes[2]);
	subnetmask1 = (bytes2[3] ^ bytes[3]);

	//Then we round it up to the next most significant digit.
	subnetmask4 = round_mask_up(subnetmask4);
	subnetmask3 = round_mask_up(subnetmask3);
	subnetmask2 = round_mask_up(subnetmask2);
	subnetmask1 = round_mask_up(subnetmask1);

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

	if ( !str_to_addr4(netmask, &mask) )	// Validate ipv4 addr
			{
				log_crit("Error: Malformed netmask: %s", netmask);
				return -1;
			}


	res+= ip_masklen(subnetmask4);
	res+= ip_masklen(subnetmask3);
	res+= ip_masklen(subnetmask2);
	res+= ip_masklen(subnetmask1);

	//log_debug("%d.%d.%d.%d mask: %d",subnetmask4, subnetmask3, subnetmask2,subnetmask1, res);

	return res;


}
