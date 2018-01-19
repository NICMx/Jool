#include "nat64/mod/stateful/pool4/customer.h"

#include "nat64/common/types.h"
#include "nat64/mod/common/wkmalloc.h"
#include "nat64/mod/common/address.h"

bool customer_table_contains(struct customer_table *table, struct in6_addr *src6)
{
	return prefix6_contains(&table->prefix6, src6);
}

static int validate_customer_entry_usr(const struct customer_entry_usr *entry)
{
	int error;
	__u32 port_count;
	error = prefix4_validate(&entry->prefix4);
	if (error)
		return error;

	error = prefix6_validate(&entry->prefix6);
	if (error)
		return error;

	if (entry->groups6_size_len > 128) {
		log_err("Second IPv6 prefix length %u is too high.", entry->groups6_size_len);
		return -EINVAL;
	}

	if (entry->prefix6.len > entry->groups6_size_len) {
		log_err("Second Prefix (/%u) of IPv6 Prefix can't be lower than first prefix (/%u)",
				entry->groups6_size_len, entry->prefix6.len );
		return -EINVAL;
	}

	if (entry->ports_division_len > 32) {
		log_err("Second IPv4 prefix length %u is too high.", entry->ports_division_len);
		return -EINVAL;
	}

	port_count = port_range_count(&entry->ports);
	if (port_count > (1U << 15)) {
		log_err("Port range size must be less or equals than %u ports",
				(1U << 15));
		return -EINVAL;
	}

	if (((__u64)(1 << (entry->groups6_size_len - entry->prefix6.len)))
			>= (prefix4_get_addr_count(&entry->prefix4) * port_count)) {
		log_err("There are not enough ports for each ipv6 group.");
		return -EINVAL;
	}

	return 0;
}

struct customer_table *customer_table_create(const struct customer_entry_usr *entry,
		int *error)
{
	struct customer_table *table;
	*error = validate_customer_entry_usr(entry);
	if (*error)
		return NULL; // error message already printed.

	table = __wkmalloc("customer_table", sizeof(struct customer_table)
			, GFP_ATOMIC);
	if (!table) {
		*error = -ENOMEM;
		return NULL;
	}

	table->prefix6 = entry->prefix6;
	table->groups6_size_len = entry->groups6_size_len;
	table->prefix4 = entry->prefix4;
	table->ports_division_len = entry->ports_division_len;
	if (table->ports.min > table->ports.max)
		swap(table->ports.min, table->ports.max);
	if (table->ports.min == 0)
		table->ports.min = 1U;

	table->ports = entry->ports;
	table->ports_size_len = customer_table_get_ports_mask(table);

	if (((unsigned int)(1 << table->ports_size_len))
			!= port_range_count(&table->ports)) {
		log_err("Ports range size must be a result of two to the nth.");
		customer_table_put(table);
		*error = -EINVAL;
		return NULL;
	}

	if (customer_table_get_group_size(table) >
			(customer_table_get_total_ports_size(table)
					>> (32U - table->ports_division_len))) {
		log_err("Invalid second IPv4 Prefix /%u, contiguous port range size is too big",
				table->ports_division_len);
		customer_table_put(table);
		*error = -EINVAL;
		return NULL;
	}

	return table;
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
		if (!addr6_get_bit(addr, table->groups6_size_len - 1U - bit_counter))
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
