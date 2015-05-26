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
		log_err("Test '%s' failed. Expected:%pI4 Actual:%pI4",
				test_name, expected, actual);
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
		log_err("  Expected:" TUPLE_KEY, TUPLE_PRINT(expected));
	else
		log_err("  Expected:NULL");
	if (actual)
		log_err("  Actual:  " TUPLE_KEY, TUPLE_PRINT(actual));
	else
		log_err("  Actual:  NULL");
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
		log_err("  Expected:" TUPLE_KEY, TUPLE_PRINT(expected));
	else
		log_err("  Expected:NULL");
	if (actual)
		log_err("  Actual:  " TUPLE_KEY, TUPLE_PRINT(actual));
	else
		log_err("  Actual:  NULL");
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

#define BIB_KEY "BIB [%pI4#%u, %pI6c#%u]"
#define BIB_PRINT(bib) &bib->ipv4.l3, bib->ipv4.l4, &bib->ipv6.l3, bib->ipv6.l4

bool ASSERT_BIB(struct bib_entry* expected, struct bib_entry* actual,
		char *test_name)
{
	if (expected == actual)
		return true;

	if (!expected) {
		log_err("Test '%s' failed: Expected:NULL Actual:" BIB_KEY,
				test_name, BIB_PRINT(actual));
		return false;
	}
	if (!actual) {
		log_err("Test '%s' failed: Expected:" BIB_KEY " Actual:NULL",
				test_name, BIB_PRINT(expected));
		return false;
	}

	if (!ipv4_transport_addr_equals(&expected->ipv4, &actual->ipv4)
			|| !ipv6_transport_addr_equals(&expected->ipv6, &actual->ipv6)) {
		log_err("Test '%s' failed: Expected:" BIB_KEY
				" Actual:" BIB_KEY, test_name,
				BIB_PRINT(expected), BIB_PRINT(actual));
		return false;
	}

	return true;
}

#undef BIB_PRINT
#undef BIB_KEY

#define SESSION_KEY "session [%pI4#%u, %pI4#%u, %pI6c#%u, %pI6c#%u]"
#define SESSION_PRINT(session) \
	&session->remote4.l3, session->remote4.l4, \
	&session->local4.l3, session->local4.l4, \
	&session->local6.l3, session->local6.l4, \
	&session->remote6.l3, session->remote6.l4

bool ASSERT_SESSION(struct session_entry *expected,
		struct session_entry *actual,
		char *test_name)
{
	if (expected == actual)
		return true;
	if (!expected || !actual)
		goto fail;

	if (expected->l4_proto != actual->l4_proto)
		goto fail;
	if (!ipv6_transport_addr_equals(&expected->remote6, &actual->remote6))
		goto fail;
	if (!ipv6_transport_addr_equals(&expected->local6, &actual->local6))
		goto fail;
	if (!ipv4_transport_addr_equals(&expected->local4, &actual->local4))
		goto fail;
	if (!ipv4_transport_addr_equals(&expected->remote4, &actual->remote4))
		goto fail;

	return true;

fail:
	log_err("Test '%s' failed.", test_name);
	if (expected)
		log_err("  Expected:" SESSION_KEY, SESSION_PRINT(expected));
	else
		log_err("  Expected:NULL");
	if (actual)
		log_err("  Actual:  " SESSION_KEY, SESSION_PRINT(actual));
	else
		log_err("  Actual:  NULL");
	return false;
}

#undef SESSION_PRINT
#undef SESSION_KEY
