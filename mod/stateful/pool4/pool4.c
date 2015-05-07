#include "nat64/mod/stateful/pool4.h"
#include "nat64/mod/common/address.h"
#include "nat64/mod/common/types.h"

#include <linux/slab.h>
#include <linux/rculist.h>

struct pool4_ports {
	struct port_range range;
	/* Links this pool4_ports to its address's "ports" list. */
	struct list_head list_hook;
};

/**
 * A prefix within the pool, along with its addresses' ports.
 */
struct pool4_node {
	/** The addresses this node represents. */
	struct ipv4_prefix prefix;
	/**
	 * The port ranges from the addresses the user reserved for Jool to use.
	 * It links elements of type pool4_ports.
	 * TODO (performance) maybe we could break some iterations early if
	 * this was sorted.
	 */
	struct list_head ports;
};

static struct pool4_node *node_pool;

/**
 * pool4_init - readies the rest of this module for future use.
 * @prefix_strs: array of strings denoting the prefixes the pool should start
 *	with.
 * @prefix_count: length of the "prefix_strs" array.
 */
int pool4_init(char *prefix_strs[], int prefix_count)
{
	struct pool4_sample sample;
	unsigned int i;
	int error;

	node_pool = NULL;

	if (!prefix_strs || prefix_count == 0)
		return 0;

	/* TODO (issue36) add the ability to inject non-default ports. */
	for (i = 0; i < prefix_count; i++) {
		error = prefix4_parse(prefix_strs[i], &sample.prefix);
		if (error)
			goto fail;
		/* TODO (issue36) align the defaults with masquerade. */
		sample.range.min = 60000U;
		sample.range.max = 65535U;
		error = pool4_add(&sample);
		if (error)
			goto fail;
	}

	return 0;

fail:
	pool4_destroy();
	return error;
}

/**
 * pool4_destroy - frees resources allocated by the pool. Reverts pool4_init().
 */
void pool4_destroy(void)
{
	struct pool4_node *tmp = node_pool;
	rcu_assign_pointer(node_pool, NULL);
	synchronize_rcu();
	kfree(tmp);
}

static struct pool4_ports *create_ports(__u16 min, __u16 max)
{
	struct pool4_ports *ports;

	ports = kmalloc(sizeof(*ports), GFP_KERNEL);
	if (!ports)
		return NULL;

	ports->range.min = min;
	ports->range.max = max;
	return ports;
}

static int add_new_node(struct pool4_sample *sample)
{
	struct pool4_node *node;
	struct pool4_ports *ports;

	node = kmalloc(sizeof(*node), GFP_KERNEL);
	if (!node)
		return -ENOMEM;
	ports = create_ports(sample->range.min, sample->range.max);
	if (!ports) {
		kfree(node);
		return -ENOMEM;
	}

	node->prefix = sample->prefix;
	INIT_LIST_HEAD(&node->ports);
	list_add(&ports->list_hook, &node->ports);
	rcu_assign_pointer(node_pool, node);

	return 0;
}


static int add_range_to_node(struct port_range *new)
{
	struct pool4_ports *ports;

	list_for_each_entry_rcu(ports, &node_pool->ports, list_hook) {
		if (new->max < ports->range.min || ports->range.max < new->min)
			continue;

		list_del_rcu(&ports->list_hook);
		ports->range.min = min(ports->range.min, new->min);
		ports->range.max = max(ports->range.max, new->max);
		list_add_tail_rcu(&ports->list_hook, &node_pool->ports);
		return 0;
	}

	ports = create_ports(new->min, new->max);
	if (!ports)
		return -ENOMEM;

	list_add_tail_rcu(&ports->list_hook, &node_pool->ports);
	return 0;
}

/**
 * pool4_add - stock add an element (prefix, along with its ports) to the pool.
 * @prefix: range of addresses to be added.
 * @min: lowest port, from the range of translatable ports of the addresses.
 * @max: highest port, from the range of translatable ports of the addresses.
 */
int pool4_add(struct pool4_sample *sample)
{
	if (WARN(!sample, "NULL cannot be inserted to pool4."))
		return -EINVAL;
	if (sample->range.min > sample->range.max)
		swap(sample->range.min, sample->range.max);

	if (!node_pool)
		return add_new_node(sample);

	if (!prefix4_equals(&node_pool->prefix, &sample->prefix)) {
		/* TODO (issue36) */
		log_err("This tmp implementation only supports 1 pool4 prefix");
		return -E2BIG;
	}

	return add_range_to_node(&sample->range);
}

static int remove_range(struct port_range *rm)
{
	struct pool4_ports *ports;
	struct pool4_ports *new1;
	struct pool4_ports *new2;
	struct pool4_node *tmp;

	if (!node_pool) {
		log_err("pool4 is empty.");
		return -ESRCH;
	}

	list_for_each_entry(ports, &node_pool->ports, list_hook) {
		if (rm->min <= ports->range.min && ports->range.max <= rm->max) {
			tmp = NULL;

			/* TODO Readers can see a portless pool4_node. */
			list_del_rcu(&ports->list_hook);
			if (list_empty(&node_pool->ports)) {
				tmp = node_pool;
				rcu_assign_pointer(node_pool, NULL);
			}

			synchronize_rcu();
			kfree(ports);
			kfree(tmp);
		}

		if (ports->range.min < rm->min && rm->max < ports->range.max) {
			/* Punch a hole in old. */
			new1 = create_ports(ports->range.min, rm->min);
			if (!new1)
				return -ENOMEM;
			new2 = create_ports(rm->max, ports->range.max);
			if (!new2) {
				kfree(new1);
				return -ENOMEM;
			}

			list_del_rcu(&ports->list_hook);
			list_add_tail_rcu(&new1->list_hook, &node_pool->ports);
			list_add_tail_rcu(&new2->list_hook, &node_pool->ports);
			kfree(ports);
			return 0;
		}

		if (ports->range.min < rm->min) {
			list_del_rcu(&ports->list_hook);
			ports->range.max = rm->min;
			list_add_tail_rcu(&ports->list_hook, &node_pool->ports);
			return 0;
		}

		if (rm->max < ports->range.max) {
			list_del_rcu(&ports->list_hook);
			ports->range.min = rm->max;
			list_add_tail_rcu(&ports->list_hook, &node_pool->ports);
			return 0;
		}
	}

	log_err("%pI4/%u does not contain range %u-%u...",
			&node_pool->prefix.address, node_pool->prefix.len,
			rm->min, rm->max);
	return -ESRCH;
}

/**
 * pool4_remove - stock remove something from the pool.
 * @prefix: range of addresses to remove or remove from.
 * @min: lowest port, from the range of ports to remove.
 * @max: highest port, from the range of ports to remove.
 *
 * Will delete from prefix ports min through max. If no ports remain, will
 * purge prefix as well.
 */
int pool4_remove(struct pool4_sample *sample)
{
	if (!node_pool) {
		log_err("pool4 is empty.");
		return -ESRCH;
	}

	if (!prefix4_equals(&node_pool->prefix, &sample->prefix)) {
		log_err("%pI4/%u does not belong to pool4.",
				&sample->prefix.address,
				sample->prefix.len);
		return -ESRCH;
	}

	return remove_range(&sample->range);
}

/**
 * pool4_flush - clears/empties the pool.
 */
int pool4_flush(void)
{
	pool4_destroy();
	return 0;
}

/**
 * pool4_contains_addr - is addr listed within the pool?
 * @addr: IPv4 address that will be looked into the pool.
 */
bool pool4_contains_addr(__be32 addr)
{
	struct pool4_node *node;
	struct in_addr inaddr = { .s_addr = addr };
	bool result;

	/* TODO test again rcu_dereference() doesn't die on null. */
	rcu_read_lock_bh();
	node = rcu_dereference(node_pool);
	result = node ? addr4_equals(&node->prefix.address, &inaddr) : false;
	rcu_read_unlock_bh();

	return result;
}

/**
 * pool4_contains_addr - is addr listed within the pool?
 * @addr: IPv4 address *and* port that will be looked into the pool.
 */
bool pool4_contains_transport_addr(const struct ipv4_transport_addr *addr)
{
	struct pool4_node *node;
	struct pool4_ports *ports;

	if (WARN(!addr, "NULL is not a valid address."))
		return false;

	rcu_read_lock_bh();
	node = rcu_dereference(node_pool);

	if (!node || !addr4_equals(&node->prefix.address, &addr->l3))
		goto not_found;

	list_for_each_entry_rcu(ports, &node->ports, list_hook) {
		if (ports->range.min <= addr->l4 && addr->l4 <= ports->range.max) {
			rcu_read_unlock_bh();
			return true;
		}
	}
	/* Fall through. */

not_found:
	rcu_read_unlock_bh();
	return false;
}

/* TODO (issue36) separate TCP, UDP and ICMP ranges? */
/* TODO (issue36) I'm not accounting for parity and range. */

/**
 * pool4_get_nth_port - return in "result" the nth port from the addr address.
 * @addr: address to look the port from.
 * @n: offset of the port to look.
 * @result: the resulting port number will be placed here.
 *
 * eg. if the address has ports 5 through 20, and n is 7, then result will
 * contain port 12.
 */
int pool4_get_nth_port(struct in_addr *addr, __u16 n, __u16 *result)
{
	struct pool4_node *node;
	struct pool4_ports *ports;
	__u16 range_total;

	if (WARN(!addr, "NULL is not a valid address."))
		return -EINVAL;

	rcu_read_lock_bh();
	node = rcu_dereference(node_pool);

	if (!node || !addr4_equals(&node->prefix.address, addr)) {
		rcu_read_unlock_bh();
		log_debug("%pI4 does not belong to pool4.", addr);
		return -EINVAL;
	}

	do {
		list_for_each_entry_rcu(ports, &node->ports, list_hook) {
			/* TODO (issue36) Isn't range inclusive? */
			range_total = ports->range.max - ports->range.min;

			if (n <= range_total) {
				*result = ports->range.min + n;
				rcu_read_unlock_bh();
				return 0;
			}

			n -= range_total;
		}
	} while (true);
}

static bool range_equals(struct port_range *r1, struct port_range *r2)
{
	return (r1->min == r2->min) && (r1->max == r2->max);
}

/**
 * pool4_for_each - executes func for every address in the pool.
 * @func: function to execute.
 * @arg: general purpose additional argument that will be handed to func.
 * @offset: prefix and range you want to start iteration from; unset to start
 * from the first prefix.
 */
int pool4_for_each(int (*func)(struct pool4_sample *, void *), void * arg,
		struct pool4_sample *offset)
{
	struct pool4_node *node;
	struct pool4_ports *ports;
	struct pool4_sample sample;
	int error = 0;

	rcu_read_lock_bh();
	node = rcu_dereference(node_pool);

	if (offset) {
		if (!node || !prefix4_equals(&offset->prefix, &node->prefix)) {
			log_debug("%pI4/%u is not part of pool4.",
					&offset->prefix.address,
					offset->prefix.len);
			rcu_read_unlock_bh();
			return -EINVAL;
		}

	} else {
		if (!node) {
			rcu_read_unlock_bh();
			return 0;
		}
	}

	list_for_each_entry_rcu(ports, &node->ports, list_hook) {
		if (!offset) {
			sample.prefix = node->prefix;
			sample.range = ports->range;
			error = func(&sample, arg);
			if (error)
				break;
		} else if (range_equals(&offset->range, &ports->range)) {
			offset = NULL;
		}
	}

	rcu_read_unlock_bh();
	return error;
}

static __be32 build_addr(struct ipv4_prefix *prefix, unsigned int offset)
{
	return cpu_to_be32(be32_to_cpu(prefix->address.s_addr) + offset);
}

/**
 * pool4_foreach_port - run @func on every pool4 transport address.
 * @mark: identifier of the pool4 to be iterated.
 * @func: callback to be run for every transport address in the pool.
 * @args: additional argument to send to @func on every iteration.
 * @offset: iteration will start from the @offset'th element.
 *
 * You want to break iteration early!
 */
int pool4_foreach_port(__u32 mark,
		int (*func)(struct ipv4_transport_addr *, void *), void *args,
		unsigned int offset)
{
	struct pool4_node *node;
	struct pool4_ports *ports;
	struct ipv4_transport_addr tmp;
	unsigned int num_ports;
	__u64 count;
	unsigned int offset_current;
	unsigned int i;
	int error = 0;

	rcu_read_lock_bh();
	node = rcu_dereference(node_pool);

	count = 0;
	list_for_each_entry_rcu(ports, &node->ports, list_hook) {
		num_ports = ports->range.max - ports->range.min + 1U;
		count += prefix4_get_addr_count(&node->prefix) * num_ports;
	}
	/* TODO overflow validations elsewhere? */
	offset %= (unsigned int)count;

	log_debug("offset: %u", offset);

	offset_current = offset;
	list_for_each_entry_rcu(ports, &node->ports, list_hook) {
		num_ports = ports->range.max - ports->range.min + 1U;
		count = prefix4_get_addr_count(&node->prefix) * num_ports;

		for (i = offset_current; i < count; i++) {
			tmp.l3.s_addr = build_addr(&node->prefix, i / num_ports);
			tmp.l4 = i % num_ports;
			error = func(&tmp, args);
			if (error)
				goto end;
		}

		if (offset_current > 0)
			offset_current -= count;
	}

	offset_current = offset;
	list_for_each_entry_rcu(ports, &node->ports, list_hook) {
		num_ports = ports->range.max - ports->range.min + 1U;
		count = prefix4_get_addr_count(&node->prefix) * num_ports;

		for (i = 0; i < count; i++) {
			if (i >= offset_current)
				goto end;

			tmp.l3.s_addr = build_addr(&node->prefix, i / num_ports);
			tmp.l4 = i % num_ports;
			error = func(&tmp, args);
			if (error)
				goto end;
		}

		offset_current -= count;
	}

end:
	rcu_read_unlock_bh();
	return error;
}

/**
 * pool4_count - return in @result the number of addresses in the pool.
 * @result: the number of addresses will be placed here.
 *
 * port counts do not affect the result.
 */
int pool4_count(__u64 *result)
{
	*result = !pool4_is_empty();
	return 0;
}

/**
 * pool4_is_empty - does the pool contain at least one address?
 */
bool pool4_is_empty(void)
{
	struct pool4_node *node;
	bool result;

	rcu_read_lock_bh();
	node = rcu_dereference(node_pool);
	result = !node;
	rcu_read_unlock_bh();

	return result;
}
