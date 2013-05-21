#include <linux/module.h>
#include <linux/printk.h>

#include "nat64/unit/unit_test.h"
#include "poolnum.c"

static bool find(u16 *arr, u16 arr_len, u16 value)
{
	u16 i;

	for (i = 0; i < arr_len; i++)
		if (arr[i] == value)
			return true;

	return false;
}

static bool test_poolnum_init_function(void)
{
	bool success = true;
	struct poolnum pool;

	success &= assert_equals_int(0, poolnum_init(&pool, 7, 13, 2), "Return value");
	if (!success)
		return success;

	success &= assert_equals_u16(4, pool.count, "Pool's array count");
	success &= assert_equals_u16(0, pool.next, "Next gettable value's index");
	success &= assert_equals_u16(0, pool.returned, "Index of value just returned");

	success &= assert_false(find(pool.array, 4, 5), "5 should not belong to the pool");
	success &= assert_false(find(pool.array, 4, 6), "6 should not belong to the pool");
	success &= assert_true(find(pool.array, 4, 7), "7 should belong to the pool");
	success &= assert_false(find(pool.array, 4, 8), "8 should not belong to the pool");
	success &= assert_true(find(pool.array, 4, 9), "9 should belong to the pool");
	success &= assert_false(find(pool.array, 4, 10), "10 should not belong to the pool");
	success &= assert_true(find(pool.array, 4, 11), "11 should belong to the pool");
	success &= assert_false(find(pool.array, 4, 12), "12 should not belong to the pool");
	success &= assert_true(find(pool.array, 4, 13), "13 should belong to the pool");
	success &= assert_false(find(pool.array, 4, 14), "14 should not belong to the pool");
	success &= assert_false(find(pool.array, 4, 15), "15 should not belong to the pool");

	poolnum_destroy(&pool);
	return success;
}

static bool test_poolnum_get_any_function(void)
{
	bool success = true;
	struct poolnum pool;
	u16 first_get = 456, second_get = 123, third_get = 789, fourth_get;

	success &= assert_equals_int(0, poolnum_init(&pool, 1, 3, 1), "");
	if (!success)
		return success;

	success &= assert_equals_int(0, poolnum_get_any(&pool, &first_get), "");
	success &= assert_equals_u16(pool.count, 3, "Count remains unchanged 1");
	success &= assert_equals_u16(pool.next, 1, "Next should point to the second value");
	success &= assert_equals_u16(pool.returned, 0, "Returned remains unchanged 1");

	success &= assert_equals_int(0, poolnum_get_any(&pool, &second_get), "");
	success &= assert_true(first_get != second_get, "The number is not already taken 1");
	success &= assert_equals_u16(pool.count, 3, "Count remains unchanged 2");
	success &= assert_equals_u16(pool.next, 2, "Next should point to the third value");
	success &= assert_equals_u16(pool.returned, 0, "Returned remains unchanged 2");

	success &= assert_equals_int(0, poolnum_get_any(&pool, &third_get), "");
	success &= assert_true(first_get != third_get && second_get != third_get,
			"The number is not already taken 2");
	success &= assert_equals_u16(pool.count, 3, "Count remains unchanged 3");
	success &= assert_equals_u16(pool.next, 0, "Next should point to the first value");
	success &= assert_equals_u16(pool.returned, 0, "Returned remains unchanged 3");

	success &= assert_equals_int(-ESRCH, poolnum_get_any(&pool, &fourth_get),
			"Pool is exhausted; get should fail 1");
	success &= assert_equals_int(-ESRCH, poolnum_get_any(&pool, &fourth_get),
			"Pool is exhausted; get should fail 2");

	poolnum_destroy(&pool);
	return success;
}

/*
static bool assert_pool(struct poolnum *pool,
		u16 expected_arr_1, u16 expected_arr_2, u16 expected_arr_3,
		u32 expected_next, u32 expected_returned)
{
	bool success = true;

	success &= assert_equals_u16(expected_arr_1, pool->array[0], "");
	success &= assert_equals_u16(expected_arr_2, pool->array[1], "");
	success &= assert_equals_u16(expected_arr_3, pool->array[2], "");
	success &= assert_equals_u32(3, pool->count, "");
	success &= assert_equals_u32(expected_next, pool->next, "");
	success &= assert_equals_u32(expected_returned, pool->returned, "");

	return success;
}
*/

static bool test_poolnum_return_function(void)
{
	bool success = true;
	struct poolnum pool;
	u16 next_get = 0;

	/* TODO (test) change numbers to comments? */
	success &= assert_equals_int(0, poolnum_init(&pool, 1, 3, 1), "1");
	if (!success)
		return success;
	pool.array[0] = 1;
	pool.array[1] = 2;
	pool.array[2] = 3;

	success &= assert_equals_int(-EINVAL, poolnum_return(&pool, 4), "2");
	/* success &= assert_pool(&pool, 1, 2, 3, 0, 0); */

	success &= assert_equals_int(0, poolnum_get_any(&pool, &next_get), "3");
	success &= assert_equals_u16(1, next_get, "");
	/* success &= assert_pool(&pool, 1, 2, 3, 1, 0); */

	success &= assert_equals_int(0, poolnum_return(&pool, 10), "4");
	/* success &= assert_pool(&pool, 10, 2, 3, 1, 1); */

	success &= assert_equals_int(-EINVAL, poolnum_return(&pool, 4), "5");
	/* success &= assert_pool(&pool, 10, 2, 3, 1, 1); */

	success &= assert_equals_int(0, poolnum_get_any(&pool, &next_get), "6");
	success &= assert_equals_u16(2, next_get, "7");
	success &= assert_equals_int(0, poolnum_get_any(&pool, &next_get), "8");
	success &= assert_equals_u16(3, next_get, "9");
	success &= assert_equals_int(0, poolnum_get_any(&pool, &next_get), "10");
	success &= assert_equals_u16(10, next_get, "11");
	success &= assert_equals_int(-ESRCH, poolnum_get_any(&pool, &next_get), "12");
	/* success &= assert_pool(&pool, 10, 2, 3, 1, 0); */

	success &= assert_equals_int(0, poolnum_return(&pool, 2), "13");
	success &= assert_equals_int(0, poolnum_return(&pool, 3), "14");
	success &= assert_equals_int(0, poolnum_return(&pool, 1), "15");
	success &= assert_equals_int(-EINVAL, poolnum_return(&pool, 4), "16");

	success &= assert_equals_int(0, poolnum_get_any(&pool, &next_get), "17");
	success &= assert_equals_u16(2, next_get, "18");

	poolnum_destroy(&pool);
	return success;
}

static bool assert_pool(struct poolnum *pool, u16 val1, u16 val2, u16 val3, u16 val4, u32 next,
		u32 returned, bool next_is_ahead)
{
	bool success = true;

	success &= assert_equals_u16(val1, pool->array[0], "1st value");
	success &= assert_equals_u16(val2, pool->array[1], "2nd value");
	success &= assert_equals_u16(val3, pool->array[2], "3rd value");
	success &= assert_equals_u16(val4, pool->array[3], "4th value");
	success &= assert_equals_u32(4, pool->count, "count");
	success &= assert_equals_u32(next, pool->next, "next");
	success &= assert_equals_u32(returned, pool->returned, "returned");
	success &= assert_equals_u32(next_is_ahead, pool->next_is_ahead, "next_is_ahead");

	return success;
}

static bool test_poolnum_get_function(void) {
	bool success = true;
	struct poolnum pool;
	u16 get_any_result = 0;

	success &= assert_equals_int(0, poolnum_init(&pool, 0, 3, 1), "");
	if (!success)
		return success;
	pool.array[0] = 0;
	pool.array[1] = 1;
	pool.array[2] = 2;
	pool.array[3] = 3;

	/* Request values that do not belong to the pool. */
	success &= assert_false(poolnum_get(&pool, -1), "");
	success &= assert_pool(&pool, 0, 1, 2, 3,	0, 0, false);
	success &= assert_false(poolnum_get(&pool, -4), "");
	success &= assert_pool(&pool, 0, 1, 2, 3,	0, 0, false);

	if (!success)
		return success;

	/* Test featuring get_anys. */
	success &= assert_true(poolnum_get(&pool, 2), "");
	success &= assert_pool(&pool, 0, 1, 0, 3,	1, 0, true);
	success &= assert_true(poolnum_get(&pool, 1), "");
	success &= assert_pool(&pool, 0, 1, 0, 3,	2, 0, true);
	success &= assert_equals_int(0, poolnum_get_any(&pool, &get_any_result), "");
	success &= assert_equals_u16(0, get_any_result, "");
	success &= assert_false(poolnum_get(&pool, 0), "");
	success &= assert_false(poolnum_get(&pool, 1), "");
	success &= assert_false(poolnum_get(&pool, 2), "");
	success &= assert_true(poolnum_get(&pool, 3), "");
	success &= assert_pool(&pool, 0, 1, 0, 3,	0, 0, true);
	success &= assert_false(poolnum_get(&pool, 3), "");
	success &= assert_equals_int(-ESRCH, poolnum_get_any(&pool, &get_any_result), "");

	if (!success)
		return success;

	/* Reset. */
	pool.array[0] = 0;
	pool.array[1] = 1;
	pool.array[2] = 2;
	pool.array[3] = 3;
	pool.next = 0;
	pool.returned = 0;
	pool.next_is_ahead = false;

	/* Test featuring returns. */
	success &= assert_true(poolnum_get(&pool, 0), "1");
	success &= assert_pool(&pool, 0, 1, 2, 3,	1, 0, true);
	success &= assert_true(poolnum_get(&pool, 3), "2");
	success &= assert_pool(&pool, 0, 1, 2, 1,	2, 0, true);
	success &= assert_equals_int(0, poolnum_return(&pool, 3), "3");
	success &= assert_pool(&pool, 3, 1, 2, 1,	2, 1, true);
	success &= assert_equals_int(0, poolnum_return(&pool, 0), "4");
	success &= assert_pool(&pool, 3, 0, 2, 1,	2, 2, false);

	success &= assert_true(poolnum_get(&pool, 3), "5");
	success &= assert_pool(&pool, 2, 0, 2, 1,	3, 2, true);
	success &= assert_true(poolnum_get(&pool, 1), "6");
	success &= assert_pool(&pool, 2, 0, 2, 1,	0, 2, true);
	success &= assert_true(poolnum_get(&pool, 0), "7");
	success &= assert_pool(&pool, 2, 2, 2, 1,	1, 2, true);
	success &= assert_true(poolnum_get(&pool, 2), "8");
	success &= assert_pool(&pool, 2, 2, 2, 1,	2, 2, true);

	success &= assert_false(poolnum_get(&pool, 0), "");
	success &= assert_false(poolnum_get(&pool, 1), "");
	success &= assert_false(poolnum_get(&pool, 2), "");
	success &= assert_false(poolnum_get(&pool, 3), "");
	success &= assert_equals_int(-ESRCH, poolnum_get_any(&pool, &get_any_result), "");

	poolnum_destroy(&pool);
	return success;
}

static bool test_boundaries(void)
{
	const u32 PORT_COUNT = 65536;
	const u32 PORT_MIN = 0;
	const u32 PORT_MAX = PORT_COUNT - 1;

	bool *results;
	struct poolnum pool;
	u32 i;
	bool success = true;
	u16 port = 0;

	/* Init result array. */
	results = kmalloc(PORT_COUNT * sizeof(*results), GFP_ATOMIC);
	success = assert_true(results, "Test array allocation");
	if (!success)
		return false;
	for (i = 0; i < PORT_COUNT; i++)
		results[i] = false;

	/* Init the pool. */
	success &= assert_equals_int(0, poolnum_init(&pool, PORT_MIN, PORT_MAX, 1), "Pool init");
	if (!success) {
		kfree(results);
		return false;
	}

	/* Fakely advance both pointers, in order to test the wrapping as well. */
	pool.next = 10;
	pool.returned = 10;

	/* Test. */
	for (i = 0; i < PORT_COUNT; i++) {
		success &= assert_equals_int(0, poolnum_get_any(&pool, &port), "Function result");
		success &= assert_false(results[port], "Result is unique");
		results[port] = true;
	}
	success &= assert_equals_int(-ESRCH, poolnum_get_any(&pool, &port), "Pool should be empty");

	for (i = 0; i < PORT_COUNT; i++)
		success &= assert_equals_int(0, poolnum_return(&pool, i), "");
	success &= assert_equals_int(-EINVAL, poolnum_return(&pool, 0), "");

	for (i = 0; i < PORT_COUNT; i++)
		success &= assert_true(poolnum_get(&pool, i), "");
	success &= assert_false(poolnum_get(&pool, 5), "");

	/* Clean up & quit. */
	kfree(results);
	poolnum_destroy(&pool);
	return success;
}

int init_module(void)
{
	START_TESTS("Number pool");

	/* BTW, neither of these functions test the randomness of the number order. */
	CALL_TEST(test_poolnum_init_function(), "num_pool_init function.");
	CALL_TEST(test_poolnum_get_any_function(), "num_pool_get_any function.");
	CALL_TEST(test_poolnum_return_function(), "num_pool_return function.");
	CALL_TEST(test_poolnum_get_function(), "num_pool_get function.");
	CALL_TEST(test_boundaries(), "boundaries test.");

	END_TESTS;
}

void cleanup_module(void)
{
	/* No code. */
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Alberto Leiva Popper <aleiva@nic.mx>");
MODULE_DESCRIPTION("Number pool test.");
