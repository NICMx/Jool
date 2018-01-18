#include "nat64/mod/stateful/pool4/customer.h"

#include "nat64/common/types.h"
#include "nat64/mod/common/wkmalloc.h"
#include "nat64/mod/common/address.h"

bool customer_table_contains(struct customer_table *table, struct in6_addr *src6)
{
	return prefix6_contains(&table->prefix6, src6);
}

__u32 customer_table_get_total_ports_size(struct customer_table *table)
{
	return (__u32)((prefix4_get_addr_count(&table->prefix4)) << table->ports_size_len);
}

__u16 customer_table_get_group_by_addr(struct customer_table *table,
		struct in6_addr *addr)
{
	__u16 group = 0U;
	__u16 bit_counter;
	for (bit_counter = 0U; bit_counter < (table->groups6_size_len - table->prefix6.len);
			bit_counter++) {
		if (!addr6_get_bit(addr, table->groups6_size_len - 1U + bit_counter))
			continue;

		group |= (((__u16) 1U) << bit_counter);
	}

	return group;
}

__u32 customer_table_get_group_ports_size(struct customer_table *table)
{
	return customer_table_get_total_ports_size(table)
			>> (table->groups6_size_len - table->prefix6.len);
}

__u16 customer_table_get_port_range_hop(struct customer_table *table)
{
	return ((__u16) 1U) << (32 - table->ports_division_len);
}

__u32 customer_get_group_first_port(struct customer_table *table,
		unsigned int offset, __u16 group, __u16 port_hop)
{
	__u32 total_ports_size;
	__u32 division_result;
	__u32 offset_group_result;
	__u32 port_hop_backward;

	total_ports_size = customer_table_get_total_ports_size(table);

	if (offset >= total_ports_size) {
		offset = offset % total_ports_size;
	}

	if (offset < port_hop) {
		return group << (32 - table->ports_division_len);
	}

	division_result = offset >> (32 - table->ports_division_len);
	offset_group_result = division_result
			& (customer_table_get_group_size(table) - 1);

	if (offset_group_result == group)
		return division_result << (32 - table->ports_division_len);

	if (group < offset_group_result)
		port_hop_backward = (offset_group_result - group) << (32 - table->ports_division_len);
	else
		port_hop_backward = (customer_table_get_group_size(table)
				- (group - offset_group_result)) << (32 - table->ports_division_len);

	return (division_result << (32 - table->ports_division_len)) - port_hop_backward;
}

__u32 customer_table_get_group_ports_hop(struct customer_table *table)
{
	return customer_table_get_group_size(table) << (32 - table->ports_division_len);
}

__u32 customer_table_get_group_size(struct customer_table *table)
{
	return ((__u32) 1U) << (table->groups6_size_len - table->prefix6.len);
}

unsigned short customer_table_get_ports_mask(struct customer_table *table)
{
	unsigned short result;
	unsigned int range_count;
	range_count = port_range_count(&table->ports);
	for (result = 1; result < 16; result ++) {
		if ((range_count >> result) == 1)
			break;
	}

	return result;

}

void customer_table_put(struct customer_table *customer)
{
	__wkfree("customer_table", customer);
}
