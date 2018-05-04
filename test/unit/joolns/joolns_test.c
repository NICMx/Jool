#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include "nat64/common/str_utils.h"
#include "nat64/mod/common/linux_version.h"
#include "nat64/mod/common/xlator.h"
#include "nat64/unit/unit_test.h"
#include "nat64/mod/common/atomic_config.h"
#include "common/pool6.c"

/*
 * Er... this doesn't even try to test everything.
 * Most of the implementation is brain-dead anyway. I'm only concerned about
 * usable APIs and reference counts at the moment.
 */

MODULE_LICENSE(JOOL_LICENSE);
MODULE_AUTHOR("Alberto Leiva");
MODULE_DESCRIPTION("Xlator test.");

/** The network namespace where the test is being run. */
static struct net *ns;
/** Number of references that @ns had at the beginning of the test. */
static int old_refs;

static int ns_refcount(struct net *ns)
{
#if LINUX_VERSION_AT_LEAST(4, 16, 0, 9999, 0)
	return refcount_read(&ns->count);
#else
	return atomic_read(&ns->count);
#endif
}

static bool validate(char *expected_addr, __u8 expected_len)
{
	struct xlator jool;
	struct ipv6_prefix prefix;
	int error;
	bool success = true;

	error = xlator_find_current(&jool);
	if (error) {
		log_info("xlator_find_current() threw %d", error);
		return false;
	}

	error = pool6_peek(jool.pool6, &prefix);
	xlator_put(&jool);
	if (error) {
		log_info("pool6_peek() threw %d", error);
		return false;
	}

	success &= ASSERT_ADDR6(expected_addr, &prefix.address, "addr");
	success &= ASSERT_UINT(expected_len, prefix.len, "len");

	return success;
}

/**
 * Superfluous test over xlator. It's mostly just API manhandling so krefs can
 * be tested next.
 */
static bool simple_test(void)
{
	return validate("2001:db8::", 96);
}

/**
 * Superfluous test over the jparser. It's mostly just API manhandling so krefs
 * can be tested next.
 */
static bool atomic_test(void)
{
	struct xlator new;
	unsigned char request[sizeof(__u16) + sizeof(struct ipv6_prefix)];
	__u16 type;
	struct ipv6_prefix prefix;
	int error;
	bool success = false;

	error = xlator_find_current(&new);
	if (error) {
		log_info("jparser_init() threw %d", error);
		return false;
	}

	error = str_to_addr6("2001:db8:bbbb::", &prefix.address);
	if (error)
		goto end;
	prefix.len = 56;

	type = SEC_POOL6;
	memcpy(&request[0], &type, sizeof(type));
	memcpy(&request[2], &prefix, sizeof(prefix));

	error = atomconfig_add(&new, request, sizeof(type) + sizeof(prefix));
	if (error) {
		log_info("jparser_handle() 1 threw %d", error);
		goto end;
	}

	type = SEC_COMMIT;
	memcpy(&request[0], &type, sizeof(type));

	error = atomconfig_add(&new, request, sizeof(type));
	if (error) {
		log_info("jparser_handle() 2 threw %d", error);
		goto end;
	}

	success = validate("2001:db8:bbbb::", 56);

end:
	xlator_put(&new);
	return success;
}

/**
 * Test the previous test handled krefs correctly.Siege on Bowser's Castle
 */
static bool krefs_test(void)
{
	struct xlator jool;
	int error;
	bool success = true;

	error = xlator_find_current(&jool);
	if (error) {
		log_info("xlator_find_current() threw %d", error);
		return false;
	}

	/* @old + database's ref + the one we just took. */
	success &= ASSERT_INT(old_refs + 2, ns_refcount(jool.ns), "ns kref");
	/* xlator DB's kref + the one we just took. */
	success &= ASSERT_INT(2,
#if LINUX_VERSION_AT_LEAST(4, 11, 0, 9999, 0)
			kref_read(&jool.pool6->refcount),
#else
			atomic_read(&jool.pool6->refcount.refcount),
#endif
			"pool6 kref");

	xlator_put(&jool);
	return success;
}

/**
 * Test the previous test handled krefs correctly. Assumes the xlator has been
 * deinitialized.
 */
static bool ns_only_krefs_test(void)
{
	return ASSERT_INT(old_refs, ns_refcount(ns), "ns kref");
}

static int setup(void)
{
	/*
	 * This whole test assumes nothing else will grab or return references
	 * towards @ns, but some kernels seem to spawn threads during module
	 * insertion that do. So we sleep two seconds to wait them out.
	 *
	 * Of course, this is not bulletproof. @ns can always change without
	 * warning, but at least this does improve the rate from almost
	 * guaranteed failure to almost guaranteed success.
	 */
	ssleep(2);

	ns = get_net_ns_by_pid(task_pid_vnr(current));
	if (IS_ERR(ns)) {
		log_err("Could not retrieve the current namespace.");
		return PTR_ERR(ns);
	}
	old_refs = ns_refcount(ns);

	return 0;
}

static void teardown(void)
{
	put_net(ns);
}

static int init(void)
{
	struct xlator jool;
	struct ipv6_prefix prefix;
	int error;

	error = xlator_setup();
	if (error) {
		log_info("xlator_setup() threw %d", error);
		return error;
	}
	error = xlator_add(&jool);
	if (error) {
		log_info("xlator_add() threw %d", error);
		goto fail1;
	}

	error = str_to_addr6("2001:db8::", &prefix.address);
	if (error)
		goto fail2;
	prefix.len = 96;

	error = pool6_add(jool.pool6, &prefix);
	if (error) {
		log_info("pool6_add() threw %d", error);
		goto fail2;
	}

	xlator_put(&jool);
	return 0;

fail2:
	xlator_rm();
fail1:
	xlator_put(&jool);
	xlator_teardown();
	return error;
}

/**
 * This is not a test, but since it can fail, might as well declare it as one.
 */
static bool clean(void)
{
	bool success;
	success = ASSERT_INT(0, xlator_rm(), "xlator_rm");
	xlator_teardown();
	return success;
}

int init_module(void)
{
	struct test_group test = {
		.name = "Xlator",
		.setup_fn = setup,
		.teardown_fn = teardown,
	};
	int error;

	test_group_begin(&test);

	error = init();
	if (error) {
		teardown();
		return error;
	}

	test_group_test(&test, simple_test, "xlator API");
	test_group_test(&test, krefs_test, "kfref checks 1");
	test_group_test(&test, atomic_test, "atomic config API");
	test_group_test(&test, krefs_test, "kfref checks 2");
	test_group_test(&test, clean, "clean");
	test_group_test(&test, ns_only_krefs_test, "kfref checks 3");

	return test_group_end(&test);
}

void cleanup_module(void)
{
	/* No code. */
}
