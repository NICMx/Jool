#include "nat64/mod/poolnum.h"

#include <linux/slab.h>

#include "nat64/comm/types.h"
#include "nat64/mod/random.h"


static int random_by_range(u16 min, u16 max)
{
	u32 random_num = get_random_u32();
	return min + random_num % (max - min + 1);
}

int poolnum_init(struct poolnum *pool, u16 min, u16 max, u16 step)
{
	u32 i, j;

	if (min > max) {
		u16 temp = min;
		min = max;
		max = temp;
	}

	/* TODO (fine) this looks like it could be optimized using some formula. */
	pool->count = 0;
	for (i = min; i <= max; i += step)
		pool->count++;

	pool->array = kmalloc(pool->count * sizeof(u16), GFP_ATOMIC);
	if (!pool->array)
		return -ENOMEM;
	/* Initialize and shuffle the numbers (http://en.wikipedia.org/wiki/Fisher-Yates_shuffle). */
	pool->array[0] = min;
	for (i = 1; i < pool->count; i++) {
		j = random_by_range(0, i);
		pool->array[i] = pool->array[j];
		pool->array[j] = min + step * i;
	}

	pool->next = 0;
	pool->returned = 0;
	pool->next_is_ahead = false;

	return 0;
}

void poolnum_destroy(struct poolnum *pool)
{
	if (pool)
		kfree(pool->array);
}

static u32 get_next_index(u32 index, u32 max)
{
	index++;
	if (index >= max)
		index = 0;
	return index;
}

int poolnum_get_any(struct poolnum *pool, u16 *result)
{
	if (pool->next_is_ahead && pool->next == pool->returned)
		return -ESRCH; /* We ran out of values. */

	*result = pool->array[pool->next];
	pool->next = get_next_index(pool->next, pool->count);
	pool->next_is_ahead = true;
	return 0;
}

bool poolnum_get(struct poolnum *pool, u16 value)
{
	u32 current_index;

	if (pool->next_is_ahead && pool->next == pool->returned)
		return false;

	current_index = pool->next;
	do {
		if (pool->array[current_index] == value) {
			pool->array[current_index] = pool->array[pool->next];
			pool->next = get_next_index(pool->next, pool->count);
			pool->next_is_ahead = true;
			return true;
		}
		current_index = get_next_index(current_index, pool->count);
	} while (current_index != pool->returned);

	return false;
}

int poolnum_return(struct poolnum *pool, u16 value)
{
	if (!pool->next_is_ahead && pool->returned == pool->next) {
		log_crit(ERR_UNKNOWN_ERROR, "Something's trying to return values that were originally "
				"not part of the pool.");
		return -EINVAL;
	}

	pool->array[pool->returned] = value;
	pool->returned = get_next_index(pool->returned, pool->count);
	if (pool->next == pool->returned)
		pool->next_is_ahead = false;

	return 0;
}
