#include "nat64/mod/stateful/pool4/table.h"
#include "nat64/mod/common/address.h"
#include "nat64/mod/common/types.h"

#include <linux/slab.h>
#include <linux/rculist.h>

///**
// * pool4_init - readies the rest of this module for future use.
// * @prefix_strs: array of strings denoting the prefixes the pool should start
// *	with.
// * @prefix_count: length of the "prefix_strs" array.
// */
//int pool4table_init(char *prefix_strs[], int prefix_count)
//{
//	struct pool4_sample sample;
//	unsigned int i;
//	int error;
//
//	node_pool = NULL;
//
//	if (!prefix_strs || prefix_count == 0)
//		return 0;
//
//	/* TODO (issue36) add the ability to inject non-default ports. */
//	for (i = 0; i < prefix_count; i++) {
//		error = prefix4_parse(prefix_strs[i], &sample.prefix);
//		if (error)
//			goto fail;
//		/* TODO (issue36) align the defaults with masquerade. */
//		sample.range.min = 60000U;
//		sample.range.max = 65535U;
//		error = pool4table_add(&sample);
//		if (error)
//			goto fail;
//	}
//
//	return 0;
//
//fail:
//	pool4table_destroy();
//	return error;
//}
//
///**
// * pool4_destroy - frees resources allocated by the pool. Reverts pool4_init().
// */
//void pool4table_destroy(void)
//{
//	struct pool4_node *tmp = node_pool;
//	rcu_assign_pointer(node_pool, NULL);
//	synchronize_rcu();
//	kfree(tmp);
//}

static bool range_intersect(struct port_range *r1, struct port_range *r2)
{
	return !(r1->max < r2->min || r2->max < r1->min);
}

static int add_ports(struct pool4_addr *addr, struct port_range *range)
{
	struct pool4_ports *ports;

	list_for_each_entry(ports, &addr->ports, list_hook) {
		if (!range_intersect(&ports->range, range))
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

/**
 * pool4table_add - stock add @sample to @table.
 */
int pool4table_add(struct pool4_table *table, struct pool4_sample *sample)
{
	struct pool4_addr *addr;
	int error;

	if (sample->range.min > sample->range.max)
		swap(sample->range.min, sample->range.max);

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

	list_add_rcu(&addr->list_hook, &table->rows);
	return 0;
}

static int remove_range(struct pool4_addr *addr, struct port_range *rm)
{
	struct pool4_ports *ports;
	struct pool4_ports *new1;
	struct pool4_ports *new2;
	struct pool4_addr *tmp;

	list_for_each_entry(ports, &addr->ports, list_hook) {
		if (rm->min <= ports->range.min && ports->range.max <= rm->max) {
			tmp = NULL;

			/* TODO Readers can see a portless pool4_node. */
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

/**
 * pool4table_rm - stock remove @sample from @table.
 *
 * Will delete from @table ports @sample->range.min through @sample->range.max.
 * If no ports remain, will purge @sample->addr as well.
 */
int pool4table_rm(struct pool4_table *table, struct pool4_sample *sample)
{
	struct pool4_addr *addr;

	list_for_each_entry(addr, &table->rows, list_hook) {
		if (addr4_equals(&addr->addr, &sample->addr))
			return remove_range(addr, &sample->range);
	}

	log_err("%pI4 does not belong to pool4.", &sample->addr);
	return -ESRCH;
}

/**
 * pool4table_flush - clears/empties @table.
 */
int pool4table_flush(struct pool4_table *table)
{
	struct pool4_addr *addr, *tmpa;
	struct pool4_ports *ports, *tmpp;
	LIST_HEAD(tmp_list);

	/*
	 * TODO if this is called with the table already unindexed,
	 * this loop can be avoided.
	 */
	list_for_each_entry_safe(addr, tmpa, &table->rows, list_hook) {
		list_del_rcu(&addr->list_hook);
		list_add(&addr->list_hook, &tmp_list);
	}

	synchronize_rcu();

	list_for_each_entry_safe(addr, tmpa, &tmp_list, list_hook) {
		list_for_each_entry_safe(ports, tmpp, &addr->ports, list_hook) {
			list_del(&ports->list_hook);
			kfree(ports);
		}

		list_del(&addr->list_hook);
		kfree(addr);
	}

	return 0;
}

///**
// * pool4table_contains - is addr listed within the pool?
// * @addr: IPv4 address *and* port that will be looked into the pool.
// */
//bool pool4table_contains(struct pool4_table *table,
//		const struct ipv4_transport_addr *addr)
//{
//	struct pool4_node *node;
//	struct pool4_ports *ports;
//
//	if (WARN(!addr, "NULL is not a valid address."))
//		return false;
//
//	rcu_read_lock_bh();
//	node = rcu_dereference(node_pool);
//
//	if (!node || !addr4_equals(&node->prefix.address, &addr->l3))
//		goto not_found;
//
//	list_for_each_entry_rcu(ports, &node->ports, list_hook) {
//		if (ports->range.min <= addr->l4 && addr->l4 <= ports->range.max) {
//			rcu_read_unlock_bh();
//			return true;
//		}
//	}
//	/* Fall through. */
//
//not_found:
//	rcu_read_unlock_bh();
//	return false;
//}

/* TODO (issue36) separate TCP, UDP and ICMP ranges? */
/* TODO (issue36) I'm not accounting for parity and range. */

static bool range_equal(struct port_range *r1, struct port_range *r2)
{
	return (r1->min == r2->min) && (r1->max == r2->max);
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
 */
int pool4table_foreach_sample(struct pool4_table *table,
		int (*func)(struct pool4_sample *, void *), void *arg,
		struct pool4_sample *offset)
{
	struct pool4_addr *addr;
	struct pool4_ports *ports;
	struct pool4_sample sample;
	int error = offset ? -ESRCH : 0;

	rcu_read_lock_bh();

	list_for_each_entry_rcu(addr, &table->rows, list_hook) {
		if (offset && !addr4_equals(&addr->addr, &offset->addr))
			continue;

		sample.addr = addr->addr;
		list_for_each_entry_rcu(ports, &addr->ports, list_hook) {
			if (!offset) {
				sample.range = ports->range;
				error = func(&sample, arg);
				if (error)
					goto end;
			} else if (range_equal(&offset->range, &ports->range)) {
				offset = NULL;
				error = 0;
			}
		}
	}

end:
	rcu_read_unlock_bh();
	return error;
}

/**
 * pool4table_foreach_port - run @func on every transport address on @table.
 * @table: sample collection that will be iterated.
 * @func: callback to be run for every transport address in @table.
 * @arg: additional argument to send to @func on every iteration.
 * @offset: iteration will start from the @offset'th element (inclusive).
 *
 * Iterations wraps around until the first iterated element is reached.
 * You want to break iteration early!
 */
int pool4table_foreach_port(struct pool4_table *table,
		int (*func)(struct ipv4_transport_addr *, void *), void *arg,
		unsigned int offset)
{
	struct pool4_addr *addr;
	struct pool4_ports *ports;
	struct ipv4_transport_addr tmp;
	unsigned int num_ports;
	unsigned int offset_current;
	unsigned int i;
	int error = 0;

	rcu_read_lock_bh();

	num_ports = 0;
	list_for_each_entry_rcu(addr, &table->rows, list_hook) {
		list_for_each_entry_rcu(ports, &addr->ports, list_hook) {
			/* TODO overflow validations elsewhere? */
			num_ports += ports->range.max - ports->range.min + 1U;
		}
	}
	offset %= num_ports;

	offset_current = offset;
	list_for_each_entry_rcu(addr, &table->rows, list_hook) {
		tmp.l3 = addr->addr;
		list_for_each_entry_rcu(ports, &addr->ports, list_hook) {
			num_ports = ports->range.max - ports->range.min + 1U;

			for (i = offset_current; i < num_ports; i++) {
				tmp.l4 = i % num_ports;
				error = func(&tmp, arg);
				if (error)
					goto end;
			}

			if (offset_current > 0)
				offset_current -= num_ports;
		}
	}

	offset_current = offset;
	list_for_each_entry_rcu(addr, &table->rows, list_hook) {
		tmp.l3 = addr->addr;
		list_for_each_entry_rcu(ports, &addr->ports, list_hook) {
			num_ports = ports->range.max - ports->range.min + 1U;

			for (i = 0; i < num_ports; i++) {
				if (i >= offset_current)
					goto end;

				tmp.l4 = i % num_ports;
				error = func(&tmp, arg);
				if (error)
					goto end;
			}

			offset_current -= num_ports;
		}
	}

end:
	rcu_read_unlock_bh();
	return error;
}

/**
 * pool4table_count - return in @result the number of transport addresses in
 * @table.
 * @result: the number of addresses will be placed here.
 */
int pool4table_count(struct pool4_table *table, __u64 *result)
{
	struct pool4_addr *addr;
	struct pool4_ports *ports;
	*result = 0;

	list_for_each_entry_rcu(addr, &table->rows, list_hook) {
		list_for_each_entry_rcu(ports, &addr->ports, list_hook) {
			*result += ports->range.max - ports->range.min + 1U;
		}
	}

	return 0;
}
