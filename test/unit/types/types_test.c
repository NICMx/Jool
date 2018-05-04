#include <linux/module.h>

#include "nat64/unit/unit_test.h"

MODULE_LICENSE(JOOL_LICENSE);
MODULE_AUTHOR("Alberto Leiva Popper");
MODULE_DESCRIPTION("Types test.");

#define assert_prt(expected, r1min, r1max, r2min, r2max, name) \
	r1.min = r1min; \
	r1.max = r1max; \
	r2.min = r2min; \
	r2.max = r2max; \
	success &= ASSERT_BOOL(expected, port_range_touches(&r1, &r2), name);

static bool test_port_range_touches(void)
{
	struct port_range r1;
	struct port_range r2;
	bool success = true;

	assert_prt(true, 1, 3, 2, 6, "1326");
	assert_prt(true, 1, 3, 3, 6, "1336");
	assert_prt(true, 1, 3, 4, 6, "1346");
	assert_prt(false, 1, 3, 5, 6, "1356");

	/* The point of these is to test overflow on those +1/-1 on r2. */
	assert_prt(false, 2, 3, 0, 0, "2300");
	assert_prt(true, 1, 3, 0, 0, "1300");
	assert_prt(false, 65531, 65532, 65534, 65535, "2300");
	assert_prt(true, 65531, 65533, 65534, 65535, "2300");

	return success;
}

int init_module(void)
{
	struct test_group test = {
		.name = "Types",
	};

	if (test_group_begin(&test))
		return -EINVAL;

	test_group_test(&test, test_port_range_touches, "port range touches function");

	return test_group_end(&test);
}

void cleanup_module(void)
{
	/* No code. */
}
