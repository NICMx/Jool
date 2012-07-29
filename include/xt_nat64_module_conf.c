/*
 * Default configuration, until it's set up by the user space application.
 * */
int init_nat_config(struct config_struct *cs)
{
	/* IPv4 */
	// IPv4 Pool Network
    if (! in4_pton(IPV4_DEF_NET, -1, (u8 *)&ipv4_pool_net.s_addr, '\x0', NULL)) {
        pr_warning("NAT64: IPv4 pool net in Headers is malformed [%s].", IPV4_DEF_NET);
        return -EINVAL;
    }
	// IPv4 Pool - Netmask
	ipv4_mask_bits = IPV4_DEF_MASKBITS;	// Num. of bits 'on' in the net mask
    if (ipv4_mask_bits > 32 || ipv4_mask_bits < 1) {
        pr_warning("NAT64: IPv4 Pool netmask bits value is invalid [%d].", 
                IPV4_DEF_MASKBITS);
        return -EINVAL;
    }
	ipv4_netmask = inet_make_mask(ipv4_mask_bits);
	ipv4_pool_net.s_addr = ipv4_pool_net.s_addr & ipv4_netmask; // For the sake of correctness

	// IPv4 Pool - First and Last addresses .
	if (! in4_pton(IPV4_DEF_POOL_FIRST, -1, (u8 *)&ipv4_pool_range_first.s_addr, '\x0', NULL)) {
        pr_warning("NAT64: IPv4 pool net in Headers is malformed [%s].", IPV4_DEF_POOL_FIRST);
        return -EINVAL;
    }
    if (! in4_pton(IPV4_DEF_POOL_LAST, -1, (u8 *)&ipv4_pool_range_last.s_addr, '\x0', NULL)) {
        pr_warning("NAT64: IPv4 pool net in Headers is malformed [%s].", IPV4_DEF_POOL_LAST);
        return -EINVAL;
    }
    
	/* IPv6 */
	ipv6_pref_addr_str = (char *)kmalloc(sizeof(char) * strlen(IPV6_DEF_PREFIX) + 1, GFP_USER);
    strcpy(ipv6_pref_addr_str, IPV6_DEF_PREFIX);	// Default IPv6	(string)
    ipv6_pref_len = IPV6_DEF_MASKBITS; // Default IPv6 Prefix	(int)

	/* Initialize config struct for function 'init_pools' */
	//~ cs = (struct config_struct *)kmalloc(sizeof(struct config_struct),GFP_USER);

	//// IPv4:
    (*cs).ipv4_addr_net = ipv4_pool_net; 
	(*cs).ipv4_addr_net_mask_bits = ipv4_mask_bits; 
	(*cs).ipv4_pool_range_first = ipv4_pool_range_first;
	(*cs).ipv4_pool_range_last = ipv4_pool_range_last;
    //
    (*cs).ipv4_tcp_port_first = IPV4_DEF_TCP_POOL_FIRST;
    (*cs).ipv4_tcp_port_last = IPV4_DEF_TCP_POOL_LAST;
    //
    (*cs).ipv4_udp_port_first = IPV4_DEF_UDP_POOL_FIRST;
    (*cs).ipv4_udp_port_last = IPV4_DEF_UDP_POOL_LAST;
    
    //// IPv6:
	if (! in6_pton(IPV6_DEF_PREFIX, -1, (u8 *)&((*cs).ipv6_net_prefix), '\0', NULL)) {
        pr_warning("NAT64: IPv6 prefix in Headers is malformed [%s].", IPV6_DEF_PREFIX);
        return -EINVAL;
    }
	(*cs).ipv6_net_mask_bits = IPV6_DEF_MASKBITS;
    //
	(*cs).ipv6_tcp_port_range_first = IPV6_DEF_TCP_POOL_FIRST;
	(*cs).ipv6_tcp_port_range_last = IPV6_DEF_TCP_POOL_LAST;
	//
	(*cs).ipv6_udp_port_range_first = IPV6_DEF_UDP_POOL_FIRST;
    (*cs).ipv6_udp_port_range_last = IPV6_DEF_UDP_POOL_LAST;   


	pr_debug("NAT64: Initial (default) configuration loaded:");
	pr_debug("NAT64:	using IPv4 pool subnet %pI4/%d (netmask %pI4),", 
			  &((*cs).ipv4_addr_net), (*cs).ipv4_addr_net_mask_bits, &ipv4_netmask);
	pr_debug("NAT64:	and IPv6 prefix %pI6c/%d.", 
			  &((*cs).ipv6_net_prefix), (*cs).ipv6_net_mask_bits);

	return 0; // Alles Klar!	
}























	//~ //// IPv4:
    //~ cs.ipv4_addr_net = (*cst).ipv4_addr_net; 			// FIXME: Rename this to ipv4_pool_net
	//~ cs.ipv4_addr_net_mask_bits = (*cst).ipv4_addr_net_mask_bits; // FIXME: Rename this to ipv4_pool_net_mask_bits
	//~ cs.ipv4_pool_range_first = (*cst).ipv4_pool_range_first;
	//~ cs.ipv4_pool_range_last = (*cst).ipv4_pool_range_last;
    //~ //
    //~ cs.ipv4_tcp_port_first = (*cst).ipv4_tcp_port_first;
    //~ cs.ipv4_tcp_port_last = (*cst).ipv4_tcp_port_last;
    //~ //
    //~ cs.ipv4_udp_port_first = (*cst).ipv4_udp_port_first;
    //~ cs.ipv4_udp_port_last = (*cst).ipv4_udp_port_last;
  //~ 
    //~ //// IPv6:
    //~ cs.ipv6_net_prefix = (*cst).ipv6_net_prefix;
	//~ cs.ipv6_net_mask_bits = (*cst).ipv6_net_mask_bits;
    //~ //
	//~ cs.ipv6_tcp_port_range_first = (*cst).ipv6_tcp_port_range_first;
	//~ cs.ipv6_tcp_port_range_last = (*cst).ipv6_tcp_port_range_last;
	//~ //
	//~ cs.ipv6_udp_port_range_first = (*cst).ipv6_udp_port_range_first;
    //~ cs.ipv6_udp_port_range_last = (*cst).ipv6_udp_port_range_last;   

	//~ pr_debug("NAT64: Updating configuration:");
	//~ pr_debug("NAT64:	using IPv4 pool subnet %pI4/%d (netmask %pI4),", 
			  //~ &(ipv4_pool_net.s_addr), (*cst).ipv4_addr_net_mask_bits, &ipv4_netmask);
	//~ pr_debug("NAT64:	and IPv6 prefix %pI6/%d.", 
			  //~ &ipv6_pref_addr_str, ipv6_pref_len);


