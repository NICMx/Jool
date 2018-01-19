#ifndef __JOOL_MOD_POOL4_CUSTOMER_H_
#define __JOOL_MOD_POOL4_CUSTOMER_H_

#include <linux/net.h>
#include "nat64/mod/common/types.h"
#include "nat64/mod/common/config.h"

struct customer_table {
	/** IPv6 addresses that use this customer table. */
	struct ipv6_prefix prefix6;
	/** Number of bits of 'prefix6' which represent the subnetwork. */
	__u8 groups6_size_len;

	/** Pool4 for this table. */
	struct ipv4_prefix prefix4;
	/** Hop size that divide the ports range for every IPv6 subnetwork
	 * in CIDR format. */
	__u8 ports_division_len;

	struct port_range ports;

	/** Port range size "ports" in CIDR format, for bitwise operations. */
	unsigned short ports_size_len;
};


bool customer_table_contains(struct customer_table *table, struct in6_addr *src6);

struct customer_table *customer_table_create(const struct customer_entry_usr *entry,
		int *error);

/**
 * Obtain the total count of ports from this customer.
 * (i.e. IPv4 prefix count * port range count )
 */
__u32 customer_table_get_total_ports_size(struct customer_table *table);

/**
 * Indicates which IPv6 group the address belongs to.
 */
__u16 customer_table_get_group_by_addr(struct customer_table *table,
		struct in6_addr *src6);

/**
 * Indicates the available port size for each IPv6 group.
 */
__u32 customer_table_get_group_ports_size(struct customer_table *table);

/**
 * Number of contiguous ports to be used as requested by the user
 * for each IPv6 group.
 */
__u16 customer_table_get_port_range_hop(struct customer_table *table);

/**
 * Initial port number for the IPv6 group 'group',
 * you can add an offset so that the initial port is different for each
 * network request.
 */
__u32 customer_get_group_first_port(struct customer_table *table,
		unsigned int offset, __u16 group, __u16 port_hop);

/**
 * Ports hope size for the following range of available ports for an IPv6 group.
 */
__u32 customer_table_get_group_ports_hop(struct customer_table *table);

/**
 * Number of IPv6 addresses for each IPv6 group.
 */
__u32 customer_table_get_group_size(struct customer_table *table);

/**
 * Same as the port_range_count(ports) but
 * for bitwise operations (1 << port_mask).
 *
 * @return port_mask
 */
unsigned short customer_table_get_ports_mask(struct customer_table *table);

void customer_table_put(struct customer_table *customer);
#endif /* __JOOL_MOD_POOL4_CUSTOMER_H_ */
