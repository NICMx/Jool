#include "nat64/unit/unit_test.h"

#include <linux/kernel.h>
#include <net/ipv6.h>
#include "nat64/common/str_utils.h"

bool __ASSERT_ADDR4(const struct in_addr *expected,
		const struct in_addr *actual,
		const char *test_name)
{
	if (expected == actual)
		return true;

	if (!expected || !actual || expected->s_addr != actual->s_addr) {
		log_err("Test '%s' failed.", test_name);
		pr_err("  Expected: %pI4\n", expected);
		pr_err("  Actual  : %pI4\n", actual);
		return false;
	}

	return true;
}

bool ASSERT_ADDR4(const char *expected_str, const struct in_addr *actual,
		const char *test_name)
{
	struct in_addr expected;

	if (!expected_str)
		return __ASSERT_ADDR4(NULL, actual, test_name);

	return str_to_addr4(expected_str, &expected)
			? false
			: __ASSERT_ADDR4(&expected, actual, test_name);
}

bool ASSERT_TADDR4(const struct ipv4_transport_addr *expected,
		const struct ipv4_transport_addr *actual,
		const char *test_name)
{
	if (taddr4_equals(expected, actual))
		return true;

	log_err("Test '%s' failed.", test_name);
	pr_err("  Expected: %pI4#%u\n", &expected->l3, expected->l4);
	pr_err("  Actual  : %pI4#%u\n", &actual->l3, actual->l4);
	return false;
}

bool __ASSERT_ADDR6(const struct in6_addr *expected,
		const struct in6_addr *actual,
		const char *test_name)
{
	if (expected == actual)
		return true;

	if (!expected || !actual || ipv6_addr_cmp(expected, actual)) {
		log_err("Test '%s' failed. Expected:%pI6c Actual:%pI6c",
				test_name, expected, actual);
		return false;
	}

	return true;
}

bool ASSERT_ADDR6(const char *expected_str, const struct in6_addr *actual,
		const char *test_name)
{
	struct in6_addr expected;

	if (!expected_str)
		return __ASSERT_ADDR6(NULL, actual, test_name);

	return str_to_addr6(expected_str, &expected)
			? false
			: __ASSERT_ADDR6(&expected, actual, test_name);
}

bool ASSERT_TADDR6(const struct ipv6_transport_addr *expected,
		const struct ipv6_transport_addr *actual,
		const char *test_name)
{
	if (taddr6_equals(expected, actual))
		return true;

	log_err("Test '%s' failed. Expected:%pI6c#%u Actual:%pI6c#%u",
			test_name,
			&expected->l3, expected->l4,
			&actual->l3, actual->l4);
	return false;
}

#define TUPLE_KEY "%pI4#%u -> %pI4#%u [%u]"
#define TUPLE_PRINT(tuple) &tuple->src.addr4.l3, tuple->src.addr4.l4, \
	&tuple->dst.addr4.l3, tuple->dst.addr4.l4, tuple->l4_proto

static bool ASSERT_TUPLE4(struct tuple *expected, struct tuple *actual,
		char *test_name)
{
	if (expected->l4_proto != actual->l4_proto)
		goto fail;
	if (ipv4_addr_cmp(&expected->src.addr4.l3, &actual->src.addr4.l3))
		goto fail;
	if (expected->src.addr4.l4 != actual->src.addr4.l4)
		goto fail;
	if (ipv4_addr_cmp(&expected->dst.addr4.l3, &actual->dst.addr4.l3))
		goto fail;
	if (expected->dst.addr4.l4 != actual->dst.addr4.l4)
		goto fail;

	return true;

fail:
	log_err("Test '%s' failed.", test_name);
	if (expected)
		pr_err("  Expected:" TUPLE_KEY "\n", TUPLE_PRINT(expected));
	else
		pr_err("  Expected:NULL\n");
	if (actual)
		pr_err("  Actual:  " TUPLE_KEY "\n", TUPLE_PRINT(actual));
	else
		pr_err("  Actual:  NULL\n");
	return false;
}

#undef TUPLE_KEY
#undef TUPLE_PRINT

#define TUPLE_KEY "%pI6c#%u -> %pI6c#%u [%u]"
#define TUPLE_PRINT(tuple) &tuple->src.addr6.l3, tuple->src.addr6.l4, \
	&tuple->dst.addr6.l3, tuple->dst.addr6.l4, tuple->l4_proto

static bool ASSERT_TUPLE6(struct tuple *expected, struct tuple *actual,
		char *test_name)
{
	if (expected->l4_proto != actual->l4_proto)
		goto fail;
	if (ipv6_addr_cmp(&expected->src.addr6.l3, &actual->src.addr6.l3))
		goto fail;
	if (expected->src.addr6.l4 != actual->src.addr6.l4)
		goto fail;
	if (ipv6_addr_cmp(&expected->dst.addr6.l3, &actual->dst.addr6.l3))
		goto fail;
	if (expected->dst.addr6.l4 != actual->dst.addr6.l4)
		goto fail;

	return true;

fail:
	log_err("Test '%s' failed.", test_name);
	if (expected)
		pr_err("  Expected:" TUPLE_KEY "\n", TUPLE_PRINT(expected));
	else
		pr_err("  Expected:NULL\n");
	if (actual)
		pr_err("  Actual:  " TUPLE_KEY "\n", TUPLE_PRINT(actual));
	else
		pr_err("  Actual:  NULL\n");
	return false;
}

#undef TUPLE_KEY
#undef TUPLE_PRINT

bool ASSERT_TUPLE(struct tuple *expected, struct tuple *actual, char *test_name)
{
	if (expected->l3_proto != actual->l3_proto) {
		log_err("Test '%s' failed; Expected:%u Actual:%u", test_name,
				expected->l3_proto, actual->l3_proto);
		return false;
	}

	switch (expected->l3_proto) {
	case L3PROTO_IPV4:
		return ASSERT_TUPLE4(expected, actual, test_name);
	case L3PROTO_IPV6:
		return ASSERT_TUPLE6(expected, actual, test_name);
	}

	log_err("?");
	return false;
}

#define BIB_KEY "[BIB %pI4#%u %pI6c#%u]"
#define BIB_PRINT(bib) &bib->ipv4.l3, bib->ipv4.l4, &bib->ipv6.l3, bib->ipv6.l4

bool ASSERT_BIB(struct bib_entry* expected, struct bib_entry* actual,
		char *test_name)
{
	if (expected == actual)
		return true;

	if (!expected) {
		log_err("Test '%s' failed:", test_name);
		pr_err("  Expected: NULL\n");
		pr_err("  Actual  : " BIB_KEY "\n", BIB_PRINT(actual));
		return false;
	}
	if (!actual) {
		log_err("Test '%s' failed:", test_name);
		pr_err("  Expected: " BIB_KEY "\n", BIB_PRINT(expected));
		pr_err("  Actual  : NULL\n");
		return false;
	}

	if (!taddr4_equals(&expected->ipv4, &actual->ipv4)
			|| !taddr6_equals(&expected->ipv6, &actual->ipv6)) {
		log_err("Test '%s' failed:", test_name);
		pr_err("  Expected: " BIB_KEY "\n", BIB_PRINT(expected));
		pr_err("  Actual  : " BIB_KEY "\n", BIB_PRINT(actual));
		return false;
	}

	return true;
}

#undef BIB_PRINT
#undef BIB_KEY

#define SESSION_KEY "[Session %pI6c#%u %pI6c#%u %pI4#%u %pI4#%u]"
#define SESSION_PRINT(session) \
	&session->src6.l3, session->src6.l4, \
	&session->dst6.l3, session->dst6.l4, \
	&session->src4.l3, session->src4.l4, \
	&session->dst4.l3, session->dst4.l4 \

bool ASSERT_SESSION(struct session_entry *expected,
		struct session_entry *actual,
		char *test_name)
{
	if (expected == actual)
		return true;
	if (!expected || !actual)
		goto fail;

	if (expected->proto != actual->proto)
		goto fail;
	if (!taddr6_equals(&expected->src6, &actual->src6))
		goto fail;
	if (!taddr6_equals(&expected->dst6, &actual->dst6))
		goto fail;
	if (!taddr4_equals(&expected->src4, &actual->src4))
		goto fail;
	if (!taddr4_equals(&expected->dst4, &actual->dst4))
		goto fail;

	return true;

fail:
	log_err("Test '%s' failed.", test_name);
	if (expected)
		pr_err("  Expected:" SESSION_KEY "\n", SESSION_PRINT(expected));
	else
		pr_err("  Expected:NULL\n");
	if (actual)
		pr_err("  Actual:  " SESSION_KEY "\n", SESSION_PRINT(actual));
	else
		pr_err("  Actual:  NULL\n");
	return false;
}

void print_session(struct session_entry *session)
{
	pr_cont(SESSION_KEY, SESSION_PRINT(session));
}

#undef SESSION_PRINT
#undef SESSION_KEY

int test_group_begin(struct test_group *group)
{
	log_info("Module '%s': Starting tests...", group->name);
	return group->setup_fn ? group->setup_fn() : 0;
}

void test_group_test(struct test_group *group, bool (*test)(void),
		char *name)
{
	bool success;

	log_info("Test '%s': Starting...", name);
	group->test_counter++;

	if (group->init_fn && group->init_fn()) {
		group->failure_counter++;
		return;
	}

	success = test();
	if (!success)
		group->failure_counter++;

	if (group->clean_fn)
		group->clean_fn();

	log_info("Test '%s': %s.\n", name, success ? "Success" : "Failure");
}

int test_group_end(struct test_group *group)
{
	if (group->teardown_fn)
		group->teardown_fn();

	log_info("Finished. Runs: %d; Errors: %d",
			group->test_counter,
			group->failure_counter);

	return (group->failure_counter > 0) ? -EINVAL : 0;
}

int broken_unit_call(const char *function)
{
	WARN(true, "%s() was called! The unit test is broken.", function);
	return -EINVAL;
}
