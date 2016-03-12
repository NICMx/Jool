#include "nat64/mod/stateful/pool4/table.h"

#include <linux/rculist.h>
#include "nat64/common/types.h"
#include "nat64/mod/common/address.h"
#include "nat64/mod/common/wkmalloc.h"

struct pool4_table *pool4table_create(__u32 mark, enum l4_protocol proto)
{
	struct pool4_table *result;

	result = wkmalloc(struct pool4_table, GFP_KERNEL);
	if (!result)
		return NULL;

	result->mark = mark;
	result->proto = proto;
	INIT_LIST_HEAD(&result->rows);
	return result;
}

/**
 * pool4_destroy - frees resources allocated by the pool. Reverts pool4_init().
 */
void pool4table_destroy(struct pool4_table *table)
{
	struct pool4_addr *addr, *tmpa;
	struct pool4_ports *ports, *tmpp;

	list_for_each_entry_safe(addr, tmpa, &table->rows, list_hook) {
		list_for_each_entry_safe(ports, tmpp, &addr->ports, list_hook) {
			list_del(&ports->list_hook);
			wkfree(struct pool4_ports, ports);
		}

		list_del(&addr->list_hook);
		wkfree(struct pool4_addr, addr);
	}

	wkfree(struct pool4_table, table);
}

static unsigned int count_ports(struct pool4_table *table)
{
	struct pool4_addr *addr;
	struct pool4_ports *ports;
	unsigned int result = 0;

	list_for_each_entry_rcu(addr, &table->rows, list_hook) {
		list_for_each_entry_rcu(ports, &addr->ports, list_hook) {
			result += port_range_count(&ports->range);
		}
	}

	return result;
}

static void fuse(struct port_range *first, struct port_range *second,
		struct port_range *result)
{
	result->min = min(first->min, second->min);
	result->max = max(first->max, second->max);
}

static bool try_fusion(struct pool4_addr *addr, struct port_range *range)
{
	struct pool4_ports *ports, *tmp;
	struct pool4_ports *fusion = NULL;

	list_for_each_entry_safe(ports, tmp, &addr->ports, list_hook) {
		if (!port_range_touches(&ports->range, range))
			continue;

		list_del_rcu(&ports->list_hook);
		synchronize_rcu_bh();

		if (fusion) {
			fuse(&ports->range, &fusion->range, &fusion->range);
			wkfree(struct pool4_ports, ports);
		} else {
			fuse(&ports->range, range, &ports->range);
			fusion = ports;
		}
	}

	if (fusion) {
		list_add_tail_rcu(&fusion->list_hook, &addr->ports);
		return true;
	}

	return false;
}

static int add_ports(struct pool4_addr *addr, struct port_range *range)
{
	struct pool4_ports *ports;

	if (try_fusion(addr, range))
		return 0;

	ports = wkmalloc(struct pool4_ports, GFP_KERNEL);
	if (!ports)
		return -ENOMEM;
	ports->range = *range;
	list_add_tail_rcu(&ports->list_hook, &addr->ports);
	return 0;
}

static int add_sample(struct pool4_table *table, struct pool4_sample *sample)
{
	struct pool4_addr *addr;
	int error;

	/* log_debug("Adding sample %pI4 %u-%u", &sample->addr,
			sample->range.min, sample->range.max); */

	if (addr4_is_scope_subnet(sample->addr.s_addr)) {
		log_err("The scope of address %pI4 is too low (look up "
				"'Reserved IP addresses'. Quitting.",
				&sample->addr);
		return -EINVAL;
	}

	list_for_each_entry(addr, &table->rows, list_hook) {
		if (addr4_equals(&addr->addr, &sample->addr))
			return add_ports(addr, &sample->range);
	}

	addr = wkmalloc(struct pool4_addr, GFP_KERNEL);
	if (!addr)
		return -ENOMEM;
	addr->addr = sample->addr;
	INIT_LIST_HEAD(&addr->ports);

	error = add_ports(addr, &sample->range);
	if (error) {
		wkfree(struct pool4_addr, addr);
		return error;
	}

	list_add_tail_rcu(&addr->list_hook, &table->rows);
	return 0;
}

static int validate_overflow(struct pool4_table *table,
		struct ipv4_prefix *prefix, struct port_range *ports)
{
	__u64 num_ports;

	num_ports = prefix4_get_addr_count(prefix) * port_range_count(ports);
	if (num_ports > UINT_MAX)
		goto fail;

	num_ports += count_ports(table);

	if (num_ports > UINT_MAX)
		goto fail;

	return 0;

fail:
	log_err("Overflow. A pool4 table can contain %u ports at most.",
			UINT_MAX);
	return -E2BIG;
}

/**
 * pool4table_add - stock add @sample to @table.
 */
int pool4table_add(struct pool4_table *table, struct ipv4_prefix *prefix,
		struct port_range *ports)
{
	struct pool4_sample sample;
	u64 tmp;
	int error;

	sample.range = *ports;
	if (sample.range.min > sample.range.max)
		swap(sample.range.min, sample.range.max);

	if (table->proto == L4PROTO_TCP || table->proto == L4PROTO_UDP) {
		if (sample.range.min == 0)
			sample.range.min = 1;
	}

	error = validate_overflow(table, prefix, ports);
	if (error)
		return error;

	/*
	 * The reason why we store each address separately, instead of the
	 * single prefix is iteration order.
	 *
	 * In order to achieve address preservation (ie. always *try* to mask an
	 * IPv6 node with the same IPv4 address or addresses),
	 * pool4table_foreach_taddr4() (which is the key function used during
	 * port allocations) needs to group transport addresses by address. This
	 * is so port allocations will *try* to use up all of an address's ports
	 * before falling back to testing ports on the next one.
	 * ("address preservation" is an expression I probably made up.)
	 *
	 * If we store prefixes instead of addresses, we run into the following
	 * problem:
	 *
	 * Consider these two (would be) pool4 entries:
	 * 	mark:0	prefix:192.0.2.0/31	ports:100-200
	 * 	mark:0	prefix:192.0.2.0/32	ports:400-500
	 *
	 * Assuming iteration starts from the beginning, the natural iteration
	 * order of port allocation would be
	 *
	 * 1. 192.0.2.0 100-200
	 * 2. 192.0.2.1 100-200
	 * 3. 192.0.2.0 400-500
	 *
	 * To attempt address preservation, it should be
	 *
	 * 1. 192.0.2.0 100-200
	 * 2. 192.0.2.0 400-500
	 * 3. 192.0.2.1 100-200
	 *
	 * I though about this a little, and felt that overcoming this while
	 * storing prefixes instead of addresses seems to be a lot more trouble
	 * than it's worth, especially considering it's unlikely for pool4 to
	 * consist of many addresses.
	 */
	foreach_addr4(sample.addr, tmp, prefix) {
		error = add_sample(table, &sample);
		if (error)
			break;
	}

	return error;
}

static int rm_range(struct pool4_addr *addr, const struct port_range *rm)
{
	struct pool4_ports *ports, *tmpp;
	struct pool4_ports *new1;
	struct pool4_ports *new2;
	struct pool4_addr *tmp;

	list_for_each_entry_safe(ports, tmpp, &addr->ports, list_hook) {
		if (rm->min <= ports->range.min && ports->range.max <= rm->max) {
			tmp = NULL;

			list_del_rcu(&ports->list_hook);
			if (list_empty(&addr->ports)) {
				tmp = addr;
				list_del_rcu(&addr->list_hook);
			}

			synchronize_rcu_bh();
			wkfree(struct pool4_ports, ports);
			wkfree(struct pool4_addr, tmp);
			continue;
		}

		if (ports->range.min < rm->min && rm->max < ports->range.max) {
			/* Punch a hole in old. */
			new1 = pool4_ports_create(ports->range.min, rm->min - 1);
			if (!new1)
				return -ENOMEM;
			new2 = pool4_ports_create(rm->max + 1, ports->range.max);
			if (!new2) {
				wkfree(struct pool4_ports, new1);
				return -ENOMEM;
			}

			list_del_rcu(&ports->list_hook);
			list_add_tail_rcu(&new1->list_hook, &addr->ports);
			list_add_tail_rcu(&new2->list_hook, &addr->ports);
			wkfree(struct pool4_ports, ports);
			continue;
		}

		if (rm->max < ports->range.min || rm->min > ports->range.max)
			continue;

		if (ports->range.min < rm->min) {
			list_del_rcu(&ports->list_hook);
			ports->range.max = rm->min - 1;
			list_add_tail_rcu(&ports->list_hook, &addr->ports);
			continue;
		}

		if (rm->max < ports->range.max) {
			list_del_rcu(&ports->list_hook);
			ports->range.min = rm->max + 1;
			list_add_tail_rcu(&ports->list_hook, &addr->ports);
			continue;
		}
	}

	return 0;
}

static int rm_sample(struct pool4_table *table, struct pool4_sample *sample)
{
	struct pool4_addr *addr;

	list_for_each_entry(addr, &table->rows, list_hook) {
		if (addr4_equals(&addr->addr, &sample->addr))
			return rm_range(addr, &sample->range);
	}

	return 0;
}

/**
 * pool4table_rm - stock remove @sample from @table.
 *
 * Will delete from @table ports @sample->range.min through @sample->range.max.
 * If no ports remain, will purge @sample->addr as well.
 */
int pool4table_rm(struct pool4_table *table, struct ipv4_prefix *prefix,
		struct port_range *ports)
{
	struct pool4_sample sample;
	u64 tmp;
	int error = 0;

	sample.range = *ports;
	foreach_addr4(sample.addr, tmp, prefix) {
		error = rm_sample(table, &sample);
		if (error)
			break;
	}

	return error;
}

/**
 * pool4table_foreach_sample - executes @func for every sample in @table.
 * @table: sample collection that will be iterated.
 * @func: callback to be run for every sample in @table.
 * @arg: additional argument to send to @func on every iteration.
 * @offset: sample you want to start iteration from; unset to start from the
 * first sample.
 *
 * If @offset is set, iteration will actually start from the sample _after_
 * @offset. This is because this assumes you already "iterated" over @offset.
 * Iteration does not wrap at the end of the table.
 */
int pool4table_foreach_sample(struct pool4_table *table,
		int (*func)(struct pool4_sample *, void *), void *arg,
		struct pool4_sample *offset)
{
	struct pool4_addr *addr;
	struct pool4_ports *ports;
	struct pool4_sample sample;
	int error = offset ? -ESRCH : 0;

	sample.mark = table->mark;
	sample.proto = table->proto;

	list_for_each_entry_rcu(addr, &table->rows, list_hook) {
		if (offset && !addr4_equals(&addr->addr, &offset->addr))
			continue;

		sample.addr = addr->addr;
		list_for_each_entry_rcu(ports, &addr->ports, list_hook) {
			if (!offset) {
				sample.range = ports->range;
				error = func(&sample, arg);
				if (error)
					return error;
			} else if (port_range_equals(&offset->range,
					&ports->range)) {
				offset = NULL;
				error = 0;
			}
		}
	}

	return error;
}

/**
 * pool4table_foreach_port - run @func on every transport address on @table.
 * @table: sample collection that will be iterated.
 * @func: callback to be run for every transport address in @table.
 * @arg: additional argument to send to @func on every iteration.
 * @offset: iteration will start from the @offset'th element (inclusive).
 *
 * Iterations wraps around and doesn't stop naturally until the @offset'th
 * element is reached. You want @func to break iteration early!
 */
int pool4table_foreach_taddr4(struct pool4_table *table,
		int (*func)(struct ipv4_transport_addr *, void *), void *arg,
		unsigned int offset_main)
{
	struct pool4_addr *addr;
	struct pool4_ports *ports;
	struct ipv4_transport_addr tmp;
	unsigned int num_ports;
	unsigned int offset;
	unsigned int i;
	int error = 0;

	num_ports = count_ports(table);
	if (num_ports == 0)
		return 0;
	offset_main %= num_ports;

	offset = offset_main;
	list_for_each_entry_rcu(addr, &table->rows, list_hook) {
		tmp.l3 = addr->addr;
		list_for_each_entry_rcu(ports, &addr->ports, list_hook) {
			num_ports = port_range_count(&ports->range);

			if (offset > num_ports) {
				offset -= num_ports;
				continue;
			}

			for (i = offset; i < num_ports; i++) {
				tmp.l4 = ports->range.min + i;
				error = func(&tmp, arg);
				if (error)
					return error;
			}
			offset = 0;
		}
	}

	offset = offset_main;
	list_for_each_entry_rcu(addr, &table->rows, list_hook) {
		tmp.l3 = addr->addr;
		list_for_each_entry_rcu(ports, &addr->ports, list_hook) {
			num_ports = port_range_count(&ports->range);

			for (i = 0; i < num_ports; i++) {
				if (i >= offset)
					return 0;

				tmp.l4 = ports->range.min + i;
				error = func(&tmp, arg);
				if (error)
					return error;
			}

			offset -= num_ports;
		}
	}

	return 0;
}

/**
 * pool4table_contains - is @taddr listed within @table?
 */
bool pool4table_contains(struct pool4_table *table,
		const struct ipv4_transport_addr *taddr)
{
	struct pool4_addr *addr;
	struct pool4_ports *ports;
	struct port_range *range;

	list_for_each_entry_rcu(addr, &table->rows, list_hook) {
		if (!addr4_equals(&addr->addr, &taddr->l3))
			continue;

		list_for_each_entry_rcu(ports, &addr->ports, list_hook) {
			range = &ports->range;
			if (port_range_contains(range, taddr->l4))
				return true;
		}
	}

	return false;
}

bool pool4table_is_empty(struct pool4_table *table)
{
	return list_empty(&table->rows);
}

void pool4table_count(struct pool4_table *table, __u64 *samples, __u64 *taddrs)
{
	struct pool4_addr *addr;
	struct pool4_ports *ports;

	list_for_each_entry_rcu(addr, &table->rows, list_hook) {
		(*samples)++;
		list_for_each_entry_rcu(ports, &addr->ports, list_hook) {
			(*taddrs) += port_range_count(&ports->range);
		}
	}
}
