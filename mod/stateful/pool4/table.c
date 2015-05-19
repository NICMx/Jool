#include "nat64/mod/stateful/pool4/table.h"
#include "nat64/mod/common/address.h"
#include "nat64/mod/common/types.h"

#include <linux/slab.h>
#include <linux/rculist.h>

struct pool4_table *pool4table_create(__u32 mark)
{
	struct pool4_table *result;

	result = kmalloc(sizeof(*result), GFP_ATOMIC);
	if (!result)
		return NULL;

	result->mark = mark;
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
			kfree(ports);
		}

		list_del(&addr->list_hook);
		kfree(addr);
	}

	kfree(table);
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

static int add_ports(struct pool4_addr *addr, struct port_range *range)
{
	struct pool4_ports *ports;

	list_for_each_entry(ports, &addr->ports, list_hook) {
		if (!port_range_touches(&ports->range, range))
			continue;

		list_del_rcu(&ports->list_hook);
		ports->range.min = min(ports->range.min, range->min);
		ports->range.max = max(ports->range.max, range->max);
		list_add_tail_rcu(&ports->list_hook, &addr->ports);
		return 0;
	}

	ports = kmalloc(sizeof(*ports), GFP_KERNEL);
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

	list_for_each_entry(addr, &table->rows, list_hook) {
		if (addr4_equals(&addr->addr, &sample->addr))
			return add_ports(addr, &sample->range);
	}

	addr = kmalloc(sizeof(*addr), GFP_KERNEL);
	if (!addr)
		return -ENOMEM;
	addr->addr = sample->addr;
	INIT_LIST_HEAD(&addr->ports);

	error = add_ports(addr, &sample->range);
	if (error) {
		kfree(addr);
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

	error = validate_overflow(table, prefix, ports);
	if (error)
		return error;

	foreach_addr4(sample.addr, tmp, prefix) {
		error = add_sample(table, &sample);
		if (error)
			break;
	}

	return error;
}

static int rm_range(struct pool4_addr *addr, const struct port_range *rm)
{
	struct pool4_ports *ports;
	struct pool4_ports *new1;
	struct pool4_ports *new2;
	struct pool4_addr *tmp;

	list_for_each_entry(ports, &addr->ports, list_hook) {
		if (rm->min <= ports->range.min && ports->range.max <= rm->max) {
			tmp = NULL;

			list_del_rcu(&ports->list_hook);
			if (list_empty(&addr->ports)) {
				tmp = addr;
				list_del_rcu(&addr->list_hook);
			}

			synchronize_rcu();
			kfree(ports);
			kfree(tmp);
		}

		if (ports->range.min < rm->min && rm->max < ports->range.max) {
			/* Punch a hole in old. */
			new1 = pool4_ports_create(ports->range.min, rm->min);
			if (!new1)
				return -ENOMEM;
			new2 = pool4_ports_create(rm->max, ports->range.max);
			if (!new2) {
				kfree(new1);
				return -ENOMEM;
			}

			list_del_rcu(&ports->list_hook);
			list_add_tail_rcu(&new1->list_hook, &addr->ports);
			list_add_tail_rcu(&new2->list_hook, &addr->ports);
			kfree(ports);
			return 0;
		}

		if (ports->range.min < rm->min) {
			list_del_rcu(&ports->list_hook);
			ports->range.max = rm->min;
			list_add_tail_rcu(&ports->list_hook, &addr->ports);
			return 0;
		}

		if (rm->max < ports->range.max) {
			list_del_rcu(&ports->list_hook);
			ports->range.min = rm->max;
			list_add_tail_rcu(&ports->list_hook, &addr->ports);
			return 0;
		}
	}

	log_err("%pI4 does not contain range %u-%u...", &addr->addr, rm->min,
			rm->max);
	return -ESRCH;
}

static int rm_sample(struct pool4_table *table, struct pool4_sample *sample)
{
	struct pool4_addr *addr;

	list_for_each_entry(addr, &table->rows, list_hook) {
		if (addr4_equals(&addr->addr, &sample->addr))
			return rm_range(addr, &sample->range);
	}

	log_err("%pI4 does not belong to pool4.", &sample->addr);
	return -ESRCH;
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
	int error;

	sample.range = *ports;
	foreach_addr4(sample.addr, tmp, prefix) {
		error = rm_sample(table, &sample);
		if (error)
			break;
	}

	return error;
}

/* TODO (issue36) separate TCP, UDP and ICMP ranges? */
/* TODO (issue36) I'm not accounting for parity and range. */

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
int pool4table_foreach_tadd4(struct pool4_table *table,
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
